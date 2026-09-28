# Quarantine runtime policy investigation

Quarantine restoration depends on the process applying metadata and the state of
its destination. The serialized envelope alone does not determine the bytes
written to disk. This investigation supplies independent native evidence for the
[portable application planner](appledouble-quarantine-application.md). The planner
now covers qualified captured-process contexts; unresolved contexts and transport
remain explicit work.

Use `ParseQuarantineXattr` to import captured filesystem values and
`File.QuarantineUpdates` to select ordered records. Neither API changes process
state or implements the policy described here. Production remains pure Go on
Linux, macOS and Windows.

## Controlled matrix

The test-only [native helper](../testdata/appledouble/native/quarantine-runtime.c)
uses the SDK's libquarantine exports. Every invocation runs in a separate child
process and changes only its own quarantine state. It never targets another
process, requests elevated privileges, or changes system security settings.

Each host matrix has 768 cases:

| Dimension | Values |
| --- | --- |
| Requested process context | Inherited; flags `0000`, `0001`, `0002`, `0004`, `0040`, `0200`, `0201` |
| File-envelope flags | `0000`, `0001`, `0002`, `0003`, `0004`, `0008`, `0010`, `0040`, `0041`, `0080`, `0200`, `1fff` |
| Destination | File or directory |
| Creation and baseline setup | Before or after the process-state change |
| Baseline request | Absent or a fixed existing quarantine xattr |

Process inputs carry `ContextAgent` and `ContextID`; file envelopes carry a
fixed timestamp, `FileAgent` and `FileID`. Existing-value requests carry a
separate fixed timestamp, `ExistingAgent` and `ExistingID`. These distinguish
which source supplies each field without relying on byte coincidences.

The helper records:

- Process capture before and after the request, including initialization status,
  errno and exact serialized bytes. A failed capture is unavailable state, not a
  successfully captured empty process context.
- Canonical requested process data and the process-application return code. A
  refused change never counts as an applied request; subsequent observations are
  associated with the actual captured context.
- The baseline setter's return code and the prepared destination's actual xattr.
  A denied baseline write is retained rather than silently claiming an existing
  value was installed.
- File-application status, final xattr presence and bytes, and independently
  imported native envelopes for both prepared and final values.
- Operation timestamps, real/effective user IDs, host/SDK/compiler identity,
  commands, SDK exports, and helper ASTs for arm64 and x86_64. Native execution
  covers the runner architecture; the ASTs describe the helper interfaces, not
  the proprietary kernel or library implementation.

Only the native `ENOATTR` result on an existing descriptor counts as xattr
absence. Allocation, symbol loading, input parsing, I/O and native readback-import
failures fail the harness. Expected denials remain ordinary recorded results and
must match the qualified fixture. Errno after a successful operation is retained
for diagnosis but is not used as a success predicate.

The process importer takes a counted text buffer excluding NUL; the helper uses
canonical NUL-free requests. Its ABI differs from the file envelope importer.
Exploratory malformed process inputs are not part of the qualified codec corpus,
and no general-purpose process serializer/parser API is introduced here.

## Findings and their limits

The macOS 27 host starts with captured process data `q/0200;;`. Requests with
`0000`, `0001` and `0040` produce effective flags `0201`; `0002` produces `0202`
and `0004` produces `0204`. The requested agent survives these successful changes,
but the test tracking string does not. Requests containing `0200` are denied
with code 13 and leave the original process context intact.

Across that matrix, 192 process-change requests are denied, 24 baseline writes
are refused, and six file applications return an error. The six errors occur
under effective `0202` for destinations created before the context change,
without a baseline, when file flags are `0008`, `0010` or `0200`. The actual
return is `-1` with errno 93 and the xattr remains absent. Neither a successful
file-envelope parse nor a nominal no-op flag proves that application succeeds.

The macOS 26 CI runner cannot capture its inherited context (`-1`, errno 93).
Successful requests establish effective flags `0001`, `0002` or `0004` without
the macOS 27 host's `0200` bit. It also refuses 192 process changes and 24
baseline writes, but all 768 file applications succeed in this matrix.

Crucially, macOS 26 preserves `FileAgent` and the input timestamp in the inherited
context, but successful process-state changes make it use `ContextAgent` and the
operation time for the same file input. Thus agent/timestamp replacement is
provably process-dependent on one OS. That does not prove every observed flag
difference is caused by process state: the hosts retain different effective flags,
and requests to set `0200` are refused on both. Those differences remain scoped
to the captured runtime profiles until further native evidence separates them.

These are observations of captured process and filesystem contexts, not universal
macOS-version rules. The macOS 26 fixture is captured and qualified separately on CI. Captured
unavailable state must not be replaced with an invented zero-flags context.
Successful context changes do not establish whether all privilege, entitlement,
filesystem or kernel-policy combinations behave identically.

## Qualification

Run the native matrix on a qualified Mac with Command Line Tools:

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble-quarantine-runtime.go
```

CI retains `appledouble-quarantine-runtime`, containing every raw input, native
JSON result, command, AST and SDK export manifest. The helper hash and exact
matrix inputs must match the fixture. Process snapshots, statuses, xattr
presence, flags, agent and identifier must match exactly. A timestamp is allowed
to vary only when the original capture placed it inside that operation's time
interval; a new value must independently fall inside its new operation interval.
Fixed and zero timestamps remain exact comparisons.

`-capture` writes independent observations for review but explicitly reports
`qualified: false`. Normal CI does not use this option. A missing or mismatched
fixture fails qualification after retaining the complete observation matrix.

Portable unit tests replay actual prepared/final filesystem imports against the
independent native envelopes on every supported Go OS. This verifies the existing
codec on process-dependent output. The harness also compares Go application plans directly with native write bytes,
preservation and error outcomes for qualified contexts. Unavailable context is
explicitly rejected and is not counted as policy parity.

## Remaining implementation

1. Extend the explicit application context to absent and additional process
   states, raw-agent resolution and privilege/destination combinations.
2. Build on qualified Go write/preserve/error planning, including buffer limits
   and native field truncation, to cover the remaining normalization cases.
3. Extend the matrix for additional agents/tracking data, flag combinations,
   destination protection and permissions, and `copyfile` error callbacks. Preserve
   the distinction between direct library application and full unpack preparation.
4. Integrate the decisions through shared host metadata transport and qualify
   APFS/HFS+ behavior on Linux, macOS and Windows.

These steps remain part of the [migration gate](appledouble-migration.md), followed
by size/allocation closure, release qualification and downstream package adoption.
