# Serialized quarantine metadata

`ParseQuarantine` and `Quarantine.MarshalBinary` convert the `q/` envelope stored
in an AppleDouble `com.apple.quarantine` record. They run in pure Go on Linux,
macOS and Windows. They do not load libquarantine, read a host database, change a
file's quarantine state. `ParseQuarantineXattr` explicitly imports the different
plain filesystem representation.

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
cases in total. The Mac harness selects its host's qualified corpus, repeats it
against the host library and compares
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

On the observed macOS 27 host, whose captured process state is `q/0200;;`:

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
Ordered record selection and source override are covered below. Remaining work
must establish process context, source-state capture, destination preparation,
existing-state normalization and write failures. It must
then expose explicit context to pure-Go policy and integrate application through
shared host metadata transport without an OS-dependent feature gap. Neither
these observations nor serialization support completes that release gate.

## Importing a filesystem quarantine value

`ParseQuarantineXattr` converts a captured `com.apple.quarantine` filesystem value
into the same `Quarantine` model used by serialized envelopes. The default targets
macOS 27; `ParseQuarantineXattrWithProfile` explicitly selects macOS 26 or 27.
The caller reads the xattr and must distinguish absence from a read failure.
A successful import can supply the `source` argument to `File.QuarantineUpdates`.

Native filesystem import accepts **at most 382 stored bytes**. The limit is
checked before NUL termination or escape decoding, so even unused bytes following
a NUL can cause rejection. It is a distinct boundary from the larger serialized
AppleDouble envelope. For example, 100 escaped agent bytes can fit the logical
agent limit while making the raw xattr too large for native import.

After the size check, native import interprets the value as a `q/` envelope.
Go reuses the established envelope parser for flags, timestamp, separators,
escapes and decoded field limits. The raw input is not retained. Malformed or
oversized values and unknown profiles return `ErrQuarantine`.

This API does not generate destination xattrs. `MarshalBinary` still exports an
AppleDouble envelope; its output is not a destination-normalized filesystem
value. Destination preparation, process policy, privilege checks and write errors
remain separate work.

### Native import and context evidence

[`quarantine-xattr.json`](../testdata/appledouble/native/quarantine-xattr.json)
records 522 independently captured macOS 27 inputs: 440 accepted and 82 rejected.
The corpus includes all byte/escape/numeric cases from the envelope investigation,
stored-size probes through the 382/383-byte boundary, and oversized NUL tails.

The native helper sets a real file xattr, verifies its exact bytes, imports with
`qtn_file_init_with_fd`, and exports through `qtn_file_to_data`. Setup/readback
failures cannot count as parser refusals. CI compares recorded, native and Go
values, preserves another raw readback, and retains helper ASTs for both Mac
architectures. macOS 26 additionally rejects the two inputs carrying flags outside
its independently qualified range. Portable unit tests retain the original
capture and exercise explicit profile selection and source-override integration.

Every helper invocation also reads its process state using
`qtn_proc_init_with_self`/`qtn_proc_to_data`. The native reports retain these
snapshots and exact initialization/serialization return codes instead of assuming
a command-line process has no quarantine state. Failed context capture is retained
as unavailable, never interpreted as absence or used to normalize metadata.
A fresh file without a quarantine xattr does not imply an unquarantined process.
The previous application observations must therefore remain scoped to their
captured host/runtime context until controlled experiments separate OS-version,
process-state and privilege effects. No destination normalizer is inferred from
those observations in this increment.

## Ordered quarantine update decisions

`File.QuarantineUpdates(profile, source)` returns one `QuarantineUpdate` for each
`com.apple.quarantine` record. The caller selects the target profile and may
supply an already-resolved source `Quarantine` model. A nil source means record
payloads supply the values.

Each decision carries its `RecordIndex`, a `Quarantine` value to apply, and
`Invalid`/`SourceOverride` indicators. Apply valid decisions at their original
record positions relative to other metadata. Unlike deferred ACL replacement,
quarantine processes every matching record in order. Duplicate records must not
be collapsed into a map or reduced to the last record before application.

- Without source state, malformed, plain-xattr, empty and NUL-only envelopes
  produce an ignored decision. A later malformed record does not cancel an
  earlier valid application.
- With source state, each matching record uses that state instead of its payload,
  including empty and malformed records. The source model is validated against
  the target profile; invalid models return `ErrQuarantine` rather than silently
  falling back to record data. Zero source flags normalize to one.
- No matching records means no application decisions, even with source state.
  Nil files and ordinary-only containers follow the same rule.
- Results own their models and do not alias source state, input bytes or one
  another. Their indices describe the `File.Attrs` order when called. `Encode`
  sorts attributes stably, so obtain decisions after the final record order has
  been established.

These are application **decisions**, not destination xattr values. In particular,
`copyfile_unpack` attempts to remove existing destination xattrs before processing
records. Removal can be refused by the native host. An ignored record therefore
does not promise preservation of the destination's pre-unpack quarantine value.
Host transport must separately reproduce preparation, normalization and write
failure handling, and capture source state from the appropriate context.

### Independent native qualification

[`quarantine-update.json`](../testdata/appledouble/native/quarantine-update.json)
contains 288 native observations: 18 record sequences, four source contexts,
fresh/existing quarantine state and file/directory destinations. Source contexts
are absent, explicitly supplied copyfile state, a quarantine-bearing AppleDouble
carrier file, and a carrier whose quarantine value is malformed. The sequences
include duplicate ordering, malformed/empty/NUL records, plain xattr text and
valid records whose native application can be a no-op.

The fixture was captured before implementing the decision API. Its candidate
values come from independent native serialization. Portable unit tests replay
all decisions under both target profiles. The Mac harness additionally compares:

1. Native `copyfile` unpacking the complete recorded container with its source
   context.
2. A separate destination prepared using a native no-quarantine control container,
   followed by libquarantine application of the **Go-selected** candidate values.

The two destinations must agree on quarantine presence, flags, agent and
identifier. Bytes match exactly on macOS 26. Where macOS 27 refreshes timestamps,
both timestamps must independently fall within the recorded operation interval;
other fields still match exactly. Initial and prepared states, carrier readbacks,
candidate bytes, resulting xattrs, diagnostics and commands are retained. Missing
attributes count as absence only after the expected native error and an existing
destination have been verified.

This comparison qualifies dispatch and source override. It deliberately uses
native application on both sides to avoid claiming an unimplemented portable
normalizer. The fresh-destination policy-only observations above remain separate.

The harness also extracts the unchanged `copyfile_unpack_quarantine` function and
complete `attr_entry_t` declaration from the hash-pinned Apple source, preserving
the license header. Clang ASTs for arm64 and x86_64 retain those bodies and the
native helper. Minimal state/dependency declarations allow syntax analysis;
they are explicitly **not** a claim about the private state structure's ABI.

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
