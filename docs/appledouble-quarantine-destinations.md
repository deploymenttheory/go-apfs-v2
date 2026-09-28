# Quarantine destination kinds

`QuarantineApplicationContext.Kind` identifies the object receiving quarantine
metadata: a regular file, directory or symlink itself. The planner runs in pure Go
on Linux, macOS and Windows. It calculates bytes and policy errors; it does not
create links, resolve paths or write a filesystem.

Use this when restoring metadata onto a link or applying an ordered quarantine
record to an already identified destination. A symlink to a directory remains a
symlink for quarantine policy. Using the target's kind would incorrectly select
the directory timestamp rule and could lead transport to change the wrong object.

```go
plan, err := source.PlanApplication(appledouble.QuarantineApplicationContext{
    Profile: appledouble.QuarantineMacOS27,
    Process: &appledouble.QuarantineProcess{Flags: 0x201, Agent: "Browser"},
    Kind: appledouble.QuarantineSymlink,
    ExistingXattr: capturedLinkValue, // The link's bytes, not the target's.
    Timestamp: 1700000000,
})
```

## Choosing a kind

| Kind | Object receiving metadata | Timestamp on ordinary replacement |
| --- | --- | --- |
| `QuarantineRegularFile` (zero/default) | Regular file | Injected `Timestamp` |
| `QuarantineDirectory` | Directory | Zero |
| `QuarantineSymlink` | Link itself, including dangling links | Injected `Timestamp` |

The existing `Directory: true` option still selects a directory with a zero Kind;
it may also accompany `QuarantineDirectory`. Combining it with
`QuarantineSymlink` is contradictory and returns `ErrQuarantineDestination`.
Unknown kind values return the same error on every Go host. Kind validation
follows source/existing-model and process validation and precedes application-size
handling. Errors do not request a write.

The kind does not change other qualified flag or byte rules. The sandbox fallback
and confirmed absent-process path preserve source timestamps, including for
symlinks. Raw existing values, malformed-header errors, native source-size limits,
agent insertion and identifier truncation continue to use the shared planner.

## Native qualification and target isolation

The native destination matrix has 2,499 observations per profile: 192 regular
files, 192 directories and 705 each of links to files, directories and missing
targets. It covers inherited and all 31 qualified low process-bit combinations,
source flags, absent/empty/malformed destination values, every non-NUL source
field byte, identifier boundaries and the 381-byte application boundary.

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble-quarantine-runtime.go -destinations
```

The test-only helper opens links with `O_SYMLINK`, following the descriptor
pattern in Apple's [pinned copyfile source](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c).
It verifies that `lstat` and the open descriptor identify the same vnode, then
retains the destination type and link text before/after application. Existing
targets carry a known quarantine value and sentinel content; directory targets
also have a checked entry list. Target identity, content and quarantine bytes
must remain equal within each operation. Dangling targets must remain absent.
Only target device/inode numbers are excluded when comparing separate runs;
within-run identity checks remain strict.

Raw effective process state, prepared/applied link xattrs, native import statuses,
Go contexts/plans and operation-bounded timestamps are retained. The base helper
is unchanged; checked generation combines the process, existing-state and
new destination observers, each with its own hash. Clang ASTs for both Mac
architectures and SDK manifests accompany the evidence. The committed native
corpora replay in portable unit tests on all three operating systems, without
requiring symlink creation privileges or a native library.

## Remaining work

Safe filesystem transport must identify the link itself, capture its metadata,
handle path races and report write failures. The planner does not provide those
operations or authorize following the target. Source capture, cleanup/callback
integration, destination protection and other object kinds still require work.
The shared APFS/HFS+ transport, size/allocation and release/adoption gates remain
open. Package PR #72 stays draft and codesign remains paused.
