# Quarantine process capture and confirmed absence

The application planner needs the actual effective process flags and raw agent,
or an explicit confirmation that no process quarantine label exists. A failed
serialized snapshot is not enough to select either state. Capture remains a
transport responsibility; the production API contains no macOS calls.

## Using an absent context

`QuarantineProcess{Absent: true}` represents confirmed label absence for the
macOS 26 target profile. Its `Flags` and `Agent` must be empty. A nil `Process`
still means unavailable state; a successful zero-flags snapshot is also distinct.
Unknown or contradictory contexts return `ErrQuarantineContext`. The absent
context behaves identically in Go on Linux, macOS and Windows.

Without a process label, application retains the source's encoded agent, full
identifier and original timestamp, including for directories. It still normalizes
zero source flags and adds the native approval bit when the low quarantine bits
require it. Existing destination flags do not replace source fields. The same
381-byte canonical application limit applies before a write is planned.

```go
plan, err := source.PlanApplication(appledouble.QuarantineApplicationContext{
    Profile: appledouble.QuarantineMacOS26,
    Process: &appledouble.QuarantineProcess{Absent: true},
    Directory: true,
})
```

The caller must establish absence before constructing this value. Do not map an
arbitrary capture failure, permission denial, unknown process or empty buffer to
`Absent`. The macOS 27 profile still rejects this context until native evidence
qualifies it; this profile restriction applies on every Go operating system.

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
No numbered system calls, native library or native process are used in production.

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

## Remaining work

Production capture and host transport still need integration, including capture
races, additional privilege/tracking contexts and errors. An absent process on
macOS 27 is not qualified. Destination automatic creation, malformed existing
values, links, cleanup/callback behavior and the remaining size/allocation gaps
also remain part of the [migration gate](appledouble-migration.md). Package PR #72
stays draft and codesign remains paused until that gate is complete.
