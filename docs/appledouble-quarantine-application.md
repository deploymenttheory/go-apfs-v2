# Portable quarantine application planning

`Quarantine.PlanApplication` calculates the exact filesystem quarantine value for
qualified process and destination contexts. It runs in pure Go on Linux, macOS
and Windows. It can request a write, preserve the current attribute, or report a
specific native-policy error. It does not mutate a filesystem or consult the
machine running Go.

Use it after `File.QuarantineUpdates` selects a valid record, at that record's
position in the metadata stream. The caller supplies the actual prepared
state, rather than assuming destination cleanup or an attempted write succeeded.
A later record must use the destination state resulting from earlier operations.
This is direct application planning; `copyfile` cleanup, callbacks and host
transport remain separate responsibilities.

```go
source, err := appledouble.ParseQuarantine(
    []byte("q/0081;12345678;FileAgent;FileID"),
)
if err != nil {
    return err
}
plan, err := source.PlanApplication(appledouble.QuarantineApplicationContext{
    Profile: appledouble.QuarantineMacOS27,
    Process: &appledouble.QuarantineProcess{
        Flags: 0x201, // Known effective flags, not a requested change.
        Agent: "Browser", // Known raw kernel agent bytes.
    },
    Timestamp: 1700000000, // Injected operation time; no hidden clock read.
    // Existing and ExistingXattr both nil confirm absence after preparation.
})
if err != nil {
    return err
}
if plan.Write {
    // Transport writes plan.Value exactly as supplied.
    // Here: 0081;6553f100;Browser;FileID
}
```

## Context and supported behavior

Supply `ExistingXattr` when you have exact destination bytes. A non-nil empty
slice means an existing zero-byte attribute; nil means absent unless `Existing`
supplies a valid imported model. Supplying both representations is an error.
The raw form handles values that full library import rejects, without discarding
the original bytes. See [existing destination state](appledouble-quarantine-existing.md)
for numeric-header interpretation and the `ErrQuarantineExisting` outcome.

The caller selects the target profile independently of its operating system.
Qualified effective process flags are `0001` through `001f` for macOS 26 and
both `0001..001f` and `0200..021f` for macOS 27. These include every combination of the five
low process bits; other combinations return
`ErrQuarantineContext`. A nil process is unavailable state and returns that error;
it never becomes an unquarantined context. For both profiles,
`QuarantineProcess{Absent: true}` explicitly selects independently confirmed
process-label absence; its flags and agent must be empty. This state retains
the source fields and timestamp, including for directories, while applying the
native flag adjustment and application size limit. macOS 27 also removes file
flag bits `0x218` independently of the process label; a zero result preserves
the prepared destination. See
[process capture and absence](appledouble-quarantine-process-capture.md). These
profile restrictions apply identically on all three Go operating systems.

The planner accepts **effective** flags only. In the native matrix, requesting
zero becomes one, some high requested bits are discarded, and requests carrying
`0x200` can be denied. A denied request leaves the inherited context in effect.
These observations do not authorize converting an arbitrary requested mask into
a context; capture success and the actual resulting state must be checked.

The process agent must be known raw byte data. Native process snapshots can be
lossy: a raw kernel backslash can be decoded again during `init_with_self`, so
blindly importing a snapshot can change `a\b` into `a?b`. In controlled tests,
only a successful process request supplies the independently known agent; actual
flags still come from the effective capture. A refused request supplies neither.
The raw-process native matrix instead reads the kernel agent through libSystem,
without deriving it from a request or reconstructing lost snapshot bytes.
Production capture and integration still remain transport work.

`Existing` supplies a valid imported destination model. Use `ExistingXattr` for
exact raw bytes; both nil confirm absence.
`Kind` selects a regular file, directory or symlink itself. Regular files and
symlinks use the injected `Timestamp`; directories use zero when policy refreshes
the timestamp. The original `Directory` option remains supported. Unknown kinds
or a contradictory symlink/directory selection return `ErrQuarantineDestination`.
See [destination kinds and link targets](appledouble-quarantine-destinations.md).
Input models and process state are not mutated, and every write result owns its
bytes.

The qualified rules include:

- Canonicalize zero source flags to one. Validate the profile and logical model
  using the shared envelope codec.
- Reject a canonical plain source value larger than **381 bytes** before process
  substitution. This native application limit differs from the **382-byte**
  filesystem-import limit. A large agent can therefore cause failure even when
  application would replace that agent with a shorter process name.
- Sandbox process policy removes source bits `0x60` and retains existing
  destination bits `0x6`. Its zero-flags fallback writes `0081` with the original
  encoded fields and input timestamp.
- The qualified contexts carrying process bit `0x200` remove file bits `0x218`.
  A zero result can preserve the original attribute or produce the native
  missing-attribute error. Preservation leaves the original raw bytes untouched.
- Add `0x80` when either low quarantine bit is set without `0x40` approval.
  Ordinary writes use the current process agent and injected timestamp; directory
  timestamps become zero. The sandbox fallback retains source fields instead.
- Ordinary writes insert the **raw** process agent and truncate the **escaped**
  source identifier to 63 bytes, even in the middle of an escape sequence. The
  fallback preserves the entire encoded identifier.

`Value` is deliberately a byte slice rather than another `Quarantine` model.
A raw agent containing a semicolon or backslash, or a partially truncated escape,
can be interpreted differently on subsequent import. Re-encoding a logical
model would silently change the bytes native application writes.

## Errors and transport

| Result | Caller action |
| --- | --- |
| `Write: true` | Write `Value` exactly, then handle actual transport errors. |
| `Write: false` | Preserve the existing raw value or its absence; `Value` is nil. |
| `ErrQuarantine` | Reject an invalid source/existing model or profile. |
| `ErrQuarantineContext` | Resolve a known, qualified process context before planning. |
| `ErrQuarantineApplicationSize` | Preserve the destination; native application rejects the source buffer (code 34). |
| `ErrQuarantineMissing` | Preserve absence; the qualified native application returns `-1` with errno 93. |

An error returns no plan. A write plan is not a promise that a real host permits
that write. Ownership, filesystem protection, actual I/O errors and `copyfile`
error callbacks must be handled by shared metadata transport.

## Native qualification

The [runtime matrix](appledouble-quarantine-runtime.md) and an extended matrix
exercise process states, existing flags, every low-byte flag combination with
and without `0x200`, high flags, individual non-NUL agent/identifier byte values,
escaping, field limits, truncation and the application buffer boundary. A process
matrix adds every low-five-bit process combination with sixteen source flag
values, both object kinds, both creation orders, and absent/existing destinations.
It also exercises discarded/refused high-bit requests and empty, escaped, binary
and maximum-length process agents. The same write rules apply across all of
these qualified effective flags; the planner does not emulate process mutation.
The native helper is reused unchanged; no Go result supplies native input or an
expected fixture value. Compressed extended fixtures retain all independent raw
observations without inflating the repository with repetitive JSON.

Portable tests replay both profiles. The Mac harness additionally compares Go
write bytes directly with native filesystem readback, verifies preservation and
specific error outcomes, and asserts rejection of unavailable contexts. It does
not count unavailable-context rejection as native policy parity. Current-time
bytes may vary only within the independently recorded operation interval; all
other bytes are exact comparisons.

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble.go
CGO_ENABLED=0 go run scripts/verify-appledouble-quarantine-runtime.go
CGO_ENABLED=0 go run scripts/verify-appledouble-quarantine-runtime.go -normalization
CGO_ENABLED=0 go run scripts/verify-appledouble-quarantine-runtime.go -processes
CGO_ENABLED=0 go run scripts/verify-appledouble-quarantine-runtime.go -contexts
CGO_ENABLED=0 go run scripts/verify-appledouble-quarantine-runtime.go -existing
CGO_ENABLED=0 go run scripts/verify-appledouble-quarantine-runtime.go -destinations
```

Native runs require macOS and Command Line Tools; portable production and tests
have no native dependency. CI retains raw inputs/readbacks, Go plans and explicit
contexts, statuses, source/SDK provenance and helper Clang ASTs for both Mac
architectures. `-capture` remains an unqualified native-only recording mode.

## Remaining work

1. Qualify additional effective process contexts and privilege/entitlement combinations,
   other object kinds and destination protection.
2. Integrate ordered plans with real source capture, destination preparation,
   actual write/readback and `copyfile` callback/error handling in shared transport.
3. Close the remaining size/allocation gaps, qualify APFS/HFS+ preservation across
   all operating systems, release APFS and validate downstream package adoption.

The [migration gate](appledouble-migration.md) remains open. These APIs do not
complete host metadata transport or authorize resuming codesign.
