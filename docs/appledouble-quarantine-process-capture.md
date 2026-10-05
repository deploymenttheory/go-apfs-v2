# Quarantine process capture and confirmed absence

The application planner needs the actual effective process flags and raw agent,
or an explicit confirmation that no process quarantine label exists. A failed
serialized snapshot is not enough to select either state. The portable AppleDouble
planner contains no macOS calls. Host acquisition is provided separately by
`hostdata.CaptureQuarantineProcess`.

## Production capture

`hostdata.CaptureQuarantineProcess(ctx)` reads the current process on qualified
macOS 26/27 hosts. It uses the fixed libSystem wrapper ABI measured below and
returns owned raw agent, metadata and tracking byte slices. It never changes a
label, queries another PID or infers effective state from a request. Two raw
observations must agree; absence additionally requires libquarantine's independent
self-capture to report `ENOATTR`. Permission errors, allocation failure, unknown
ABIs and changing snapshots remain errors. Callers must exclude concurrent label
changes because observed equality cannot detect a change followed by a reversal.

Call the snapshot's `Process()` method to obtain exact planner input. A capture
does not authorize a native write or turn an unqualified policy context into a
supported one. Linux and Windows consume the same portable snapshot without
native dependencies. Byte slices survive JSON as base64; opaque tracking bytes
must be retained only when required and must not be written into diagnostic logs.

`go run scripts/verify-quarantine-capture-native.go` compiles an independent C
observer, retains Clang ASTs for both architectures and compares C and production
Go capture inside the same process. The evidence records only payload lengths,
toolchain/OS/source hashes and completion, not raw process tracking bytes.

## Using an absent context

`QuarantineProcess{Absent: true}` represents confirmed label absence for the
macOS 26 and 27 target profiles. Its `Flags` and `Agent` must be empty. A nil `Process`
still means unavailable state; a successful zero-flags snapshot is also distinct.
Unknown or contradictory contexts return `ErrQuarantineContext`. The absent
context behaves identically in Go on Linux, macOS and Windows.

Without a process label, application retains the source's encoded agent, full
identifier and original timestamp, including for directories. It still normalizes
zero source flags and adds bit `0x80` when either low quarantine bit is set
without bit `0x40`. Existing destination flags do not replace source fields. The same
381-byte canonical application limit applies before a write is planned. The
macOS 27 profile also removes file flag bits `0x218`; if no bits remain, it
preserves the prepared destination, including attribute absence.

```go
plan, err := source.PlanApplication(appledouble.QuarantineApplicationContext{
    Profile: appledouble.QuarantineMacOS26,
    Process: &appledouble.QuarantineProcess{Absent: true},
    Directory: true,
})
```

The caller must establish absence before constructing this value. Do not map an
arbitrary capture failure, permission denial, unknown process or empty buffer to
`Absent`. The independently captured macOS 27 absent-context corpus includes
3,328 process/context cases, 6,672 existing-value cases and 2,499 destination
cases. Native field filtering and process-label substitution are separate
decisions; receiving-host OS detection never supplies either input.

## Lossless native evidence

The serialized libquarantine snapshot decodes an already raw kernel agent again.
For example, a raw `A\B;C` agent becomes `A?B;C` in that snapshot. The planner must
receive the original bytes to reproduce the eventual filesystem value.

The test-only capture extension uses libSystem's `__mac_syscall` wrapper, the
same wrapper used by native libquarantine. It queries only its own process. The
wrapper ABI is declared in Apple's pinned
[XNU header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/security/mac.h#L165).
The private process-info layout and operations were identified by inspecting the
host library's `qtn_proc_init_with_pid` and
`__qtn_syscall_quarantine_getprocinfo` routines, then measured independently.
The portable policy uses no native library or process. The Darwin host adapter
calls libSystem wrappers with CGo disabled; it does not issue numbered system
calls. Native C helpers are used only for qualification.

The extension records:

- Raw self-query return code and errno, effective flags, exact agent and metadata
  bytes, and tracking length. Tracking payloads are not published.
- The library snapshot alongside the raw query. An absent context requires both
  the raw valid-self query and the library capture to report `-1` with `ENOATTR`
  (93), rather than treating all snapshot failures alike.
- Explicit current-PID and invalid-PID probes. These routes can require privileges
  and return `EPERM` even when self capture succeeds. Their errors are retained;
  they neither substitute for self capture nor confirm absence.
- Actual destination state before/after direct native file application. Go plans
  are compared against raw native writes, preservation and errors.

When raw capture is available, the Go comparison obtains flags and agent solely
from that capture; it does not recover them from the requested process change.
Byte probes, escaped/backslash agents, binary values and maximum-length agents
exercise this distinction. Inherited contexts exercise source fields, flags,
existing state, file/directory behavior and buffer boundaries.

## Reproducing qualification

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble.go
CGO_ENABLED=0 go run scripts/verify-appledouble-quarantine-runtime.go -contexts
```

The native mode requires a qualified Mac and Command Line Tools. It inserts the
small capture extension into the existing helper at checked locations, retaining
the exact generated C source. The original helper and its earlier fixtures remain
unchanged. Artifacts record base/extension/generated-source hashes, both SDK export
manifests, Clang ASTs for arm64 and x86_64, native commands, inputs, captures and Go
plans. Static assertions verify structure size and field offsets. Native execution
qualifies the host architecture; an AST is not native execution of the other one.

Portable tests replay both captured profiles with CGO disabled. Earlier fixtures
without raw evidence remain unavailable where capture failed; they are not
retrospectively relabeled as confirmed absence. The native macOS 26 mode also
requires actual absent and present observations, so missing absence coverage
cannot silently qualify the new behavior.

## Held-file quarantine I/O

`hostdata.CaptureQuarantineFile` reads through the held descriptor and parses the
returned envelope in Go. `ApplyQuarantineFile` checks that the captured process
context still matches, serializes the source model in Go, and submits it through
the libSystem MAC wrapper. The kernel performs destination authorization and
normalization. Sending already normalized planner output through that operation
would apply the native transformation twice.

Captured logical objects use the portable application planner instead. This
keeps Linux and Windows operations independent of a Darwin host, while the host
adapter measures actual kernel results. A nil source requests native clearing;
permission failures remain errors rather than becoming an absent value.

Run `CGO_ENABLED=0 go run scripts/verify-quarantine-capture-native.go` on a qualified
Mac to compare the production adapter against an independent C helper in the
same process. It covers twelve flag/protected-file combinations and clearing,
retains both architecture ASTs, and checks readback as well as return codes.
These cases do not qualify every destination or privilege context.

## Remaining work

Production capture is implemented with observed-change detection and preserved
errors. Host lifecycle integration and additional privilege contexts still need
qualification. An absent process on
macOS 27 is not qualified. Destination automatic creation, link transport,
cleanup/callback behavior and the remaining size/allocation gaps
also remain part of the [migration gate](appledouble-migration.md). Package PR #72
stays draft and codesign remains paused until that gate is complete.
