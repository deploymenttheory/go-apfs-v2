# Serialized quarantine metadata

`ParseQuarantine` and `Quarantine.MarshalBinary` convert the `q/` envelope stored
in an AppleDouble `com.apple.quarantine` record. They run in pure Go on Linux,
macOS and Windows. They do not load libquarantine, read a host database, change a
file's quarantine state or interpret the plain filesystem xattr as an envelope.

The default API targets macOS 27. Use `ParseQuarantineWithProfile` and
`MarshalBinaryWithProfile` with `QuarantineMacOS26` or `QuarantineMacOS27` to
select a target explicitly. Selection is independent of the machine running Go.
Unknown profiles return `ErrQuarantine`; flags unsupported by the selected
profile are rejected, not removed. Compatibility with other macOS releases has
not yet been qualified.

Use these APIs when inspecting or constructing the serialized record. Ordinary
`Decode`, `Encode` and `Xattrs` preserve its raw bytes, including malformed policy
payloads. Parsing is an explicit operation and returns `ErrQuarantine` when the
payload cannot be interpreted.

## Native reference and evidence

Apple's pinned [copyfile.c](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c)
calls `qtn_file_to_data` while packing and `qtn_file_init_with_data` followed by
native application while unpacking. The captured source SHA-256 is
`19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`.

The serializer's implementation is not part of that public source. The test-only
[`quarantine.c`](../testdata/appledouble/native/quarantine.c) helper loads the
host's libquarantine exports independently of Go. The SDK export manifest and
Clang JSON ASTs of this helper for arm64 and x86_64 are retained. Those ASTs verify
the helper's C interfaces, **not the proprietary library implementation**. Native
execution is performed only on the runner's architecture.

[`quarantine.json`](../testdata/appledouble/native/quarantine.json) records 434 macOS 27
independently observed inputs (365 accepted, 69 rejected), canonical bytes, diagnostics,
host identity and input/helper hashes. Cases cover envelope prefixes, numeric
widths and signs, whitespace, missing separators, all non-NUL byte values,
escapes, embedded NULs and decoded field boundaries. Portable unit tests replay
all cases. The corresponding [macOS 26 corpus](../testdata/appledouble/native/quarantine-macos26.json)
records the same 434 inputs (363 accepted, 71 rejected), captured independently
on the CI Mac. Both corpora run on every supported Go OS: 868 native fixture
cases in total. The Mac harness selects its host's qualified corpus and repeats it against the host library and compares
native, recorded and Go serialization byte for byte. Helper setup failures are
fatal and cannot count as native parse rejections. Ten additional flag-boundary
probes exercise both sides of the format limits on the native host.

Six native producer cases additionally set real filesystem xattrs, pack them
with `copyfile`, parse and serialize the resulting quarantine record in Go, and
require byte equality for both the record and the re-encoded whole sidecar.
These include escaped/UTF-8 bytes and maximum decoded agent/identifier lengths.
The high-flag producer uses `0x2000` for macOS 27 and `0x1000` for macOS 26;
unsupported flags remain covered by native rejection probes.

## Envelope behavior

Canonical bytes have this form, including a terminating NUL:

```text
q/0081;12345678;Probe;01234567-89AB-CDEF-0123-456789ABCDEF\0
```

- Flags and timestamp are hexadecimal unsigned fields, scanned with widths four
  and eight respectively. Initial ASCII whitespace does not consume the width;
  signs and an optional hexadecimal prefix do. Negative values use unsigned
  32-bit arithmetic. macOS 27 accepts flags through `0x3fff`; macOS 26 through
  `0x1fff`. Larger values are rejected; zero becomes one.
- The flag separator and a successful timestamp conversion are required. Native
  parsing has a compatibility quirk: if the separator after the timestamp is
  missing, its text-field offset stays at the start of the envelope. For example,
  `q/81;1` serializes as `q/0081;00000001;q\x2f81;1\0`. Overlong or partly
  hexadecimal timestamp fields can take the same path. Go retains this behavior.
- Agent and identifier split at the first text-field semicolon. Additional
  semicolons belong to the identifier. Input terminates at the first literal NUL;
  a final NUL is optional on input.
- `\xHH` decodes a byte; the `x` must be lowercase, but hexadecimal digits can use
  either case. An invalid backslash becomes `?` without consuming following bytes.
- Limits are 255 decoded bytes for agent and 64 for identifier. Bytes after an
  escaped NUL still count towards those limits before the decoded string is
  truncated at NUL. These fields are byte strings and need not be valid UTF-8.
- Serialization emits lowercase `\xhh` escapes for non-printable/non-ASCII bytes,
  spaces and `"`, `$`, `,`, `/`, `:`, `;`, `[`, `]`, `\`, `{`, `}`. Other printable
  ASCII bytes are literal. Flags have four digits and timestamp has eight.
- Direct model construction rejects embedded NUL, oversized strings and invalid
  flags. The largest canonical envelope is 1,294 bytes. Nil receivers return an
  error. Parsed values do not alias input storage.

These rules describe the observed serialized format, not destination security
policy. A syntactically valid envelope does not establish that restoring it
should leave identical flags or create an xattr at all.

## Application observations and remaining work

[`quarantine-application.json`](../testdata/appledouble/native/quarantine-application.json)
and its [macOS 26 counterpart](../testdata/appledouble/native/quarantine-application-macos26.json)
each contain 34 observations: 17 flag values each on a fresh file and directory.
They are explicitly `PolicyOnly`. The harness submits Go-canonicalized accepted
envelopes (and raw rejected envelopes to observe native ignore behavior)
to native `copyfile`, records actual filesystem readback and checks observations,
but does **not** compare a Go implementation of destination policy.

On macOS 27, in the observed unquarantined command-line process context:

- `0`/`1` flags become `0x81`; `2` becomes `0x82`.
- Flag-only `0x8`, `0x10` and `0x200` produce no quarantine xattr.
- `0x3fff` becomes `0x3de7`; the other individually probed flags are preserved.
- Files receive the current Unix timestamp (checked within the operation's time
  interval); directories receive a zero timestamp. Agent is empty; the supplied
  identifier is retained.

On the macOS 26 CI runner, timestamps and agents are preserved for both files and
directories. Flags `0`/`1` become `0x81` and `2` becomes `0x82`; other accepted
probed values are preserved, including `0x8`, `0x10` and `0x200`. The two flag
values outside that format (`0x2000` and `0x3fff`) leave no quarantine xattr.
Those readbacks are compared exactly, including timestamp. The reports retain
the different native environments; the eventual application API must establish
which differences depend on OS version and which depend on runtime context.

These observations are deliberately narrower than a portable runtime policy.
Remaining work must establish source-side quarantine override, process context,
existing destination state, duplicate/invalid records and write failures. It must
then expose explicit context to pure-Go policy and integrate application through
shared host metadata transport without an OS-dependent feature gap. Neither
these observations nor serialization support completes that release gate.

## Reproduce

Run portable coverage on any supported OS:

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble.go
```

Run the independent oracle on macOS with Command Line Tools and network access
for the hash-pinned reference source:

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble-quarantine.go
```

CI publishes `appledouble-quarantine` with the report, every input and native/Go
output, native producer sidecars, application readbacks, command diagnostics,
source, SDK exports and two helper ASTs. Coverage evidence hashes the fixtures,
helper and harness alongside package sources. The fuzz workflow also exercises
`FuzzQuarantine` for canonicalization stability and bounded serialized output.
