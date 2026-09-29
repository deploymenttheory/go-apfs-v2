# Ordinary security copying in image trees

Use `root.CopySecurity(target, source, options)` on an APFS or HFS+ writer tree
when copying captured security onto an existing destination. It stages the
ordinary `copyfile_security` operation in pure Go on Linux, macOS and Windows.
The source can come from an image reader's `Security` snapshot. A subsequent
`RestoreACL` applies an AppleDouble replacement after this ordinary copy stage.

```go
source, err := sourceVolume.Security("path/to/source")
if err != nil {
    return err
}
result, err := root.CopySecurity(destinationEntry, source.Source,
    hostmeta.SecurityCopyOptions{ACL: true, Stat: true})
if err != nil {
    return err
}
// Check Completed and Failures before serializing with CreateContainer or
// CreateImage. Volume policy must be captured and supplied by the caller.
_ = result
```

The target is an entry pointer within the supplied root. The adapter never
opens a host path or follows a symlink. Nil children, cycles, repeated entry
pointers, unsupported types and conflicting hard-link security are rejected
before publishing changes. Regular hard-link aliases update together, including
aliases in other directories. Directory and symlink LinkGroups do not select
regular-file aliases. The caller excludes concurrent tree mutation.

## Selected metadata

| Selection | Staged behavior |
| --- | --- |
| Neither ACL nor stat | Completed no-op, even without a tree |
| Stat only | Captured stat mode, with set-ID policy; ownership and security storage retained |
| ACL only | Explicit source entries followed by inherited destination entries; numeric UID/GID/mode omitted |
| ACL and stat | Merged ACL and independently present numeric source properties; omitted properties retained |

The shared `hostmeta.CopySecurity` executor still owns source-cache changes,
selection, filtering and diagnostics. Writer adapters share graph validation
with deferred restoration. They do not duplicate the selection algorithm.

- An explicit zero mode is retained. File type cannot be changed by a mode
  request. Set-ID and sticky bits use the same portable conversions as readers
  and image writers.
- `AlwaysCopySetID` overrides forbid-copy and captured source/destination
  `MNT_NOSUID`; otherwise the requested stat mode is filtered as native copyfile
  does. A failed volume lookup must not be treated as a positive capability.
- Independently of copyfile's filtering, selecting numeric ownership with mode
  omitted clears existing set-ID bits, including when the IDs do not change.
  XNU applies this even to root. A simultaneously selected mode is authoritative.
- Extended chmod selects the ACL, not the UUID slots from its argument.
  Existing stored owner/group UUIDs therefore remain, including UUIDs hidden by
  the public zero-entry statx view. Numeric IDs are separate from these UUIDs.
- Null security leaves storage untouched. A present empty ACL produces a
  canonical empty record. A NOACL request removes storage only when both stored
  UUIDs are zero; otherwise it retains the UUID-bearing NOACL record. UUID-only
  source properties can produce this request.
- A **raw NOACL source property is different from an absent source ACL**.
  Libc refuses to materialize it as `acl_t`; ordinary ACL copying stops before
  destination capture with EINVAL. The portable executor reports
  `appledouble.ErrFileSecurity` and makes no writes. Stat-only copying can still
  use its separate stat metadata. Native statx snapshots already omit such raw
  source properties, so this mainly matters for independently prepared sources.

Every changed alias gets its own security value and xattr map. Original maps,
source properties, payloads, resource forks, lazy payload readers, timestamps,
BSD flags and unrelated attributes remain intact. An invalid source or failed
selection publishes no tree edits. Allocation completes before publication.

## Completion and scope

`Completed` means that the image-tree operation finished. It does not mean an
image was written; serialization remains a separate fallible operation.
The offline backend has no native permission check or capability failure, so it
does not invent EPERM/ENOTSUP results or execute a simulated fallback sequence.
The executor's native fallback behavior is qualified separately in
[ordinary security execution](appledouble-security-copy.md).

This is staging of selected filesystem metadata, not evaluation of the caller's
credentials. Immutable flags are preserved as metadata; native authorization to
modify a mounted immutable inode is a separate host-backend concern. Arbitrary
numeric IDs can be staged without claiming that an unprivileged host process
could perform the same ownership change. Native ctime updates are not fabricated
in the offline tree.

## Native qualification

`go run scripts/verify-image-security-copy.go` compares real writes using the
complete unchanged Apple `copyfile_security` routine against separately written
Go images on APFS, APFS-sensitive, HFSX and HFS+. The corpus contains:

- 2,692 comparisons: 2,436 completed stages and 256 required source-property
  refusals, plus 1,344 native/written hard-link observations.
- Files, directories, symlinks, hard links and explicit zero-mode volume roots;
  absent, malformed, empty, NOACL, ordinary, surplus, oversized and inherited
  destination records; source property presence, UUID-only removal, empty,
  explicit, mixed inherited and 127-entry ACLs.
- ACL-only, stat-only and combined stages; forbid-copy and always-copy policy;
  zero permissions and all special bits. The mount is verified to have owners
  enabled and `MNT_NOSUID`. The shared native oracle receives that measured
  destination bit for its held descriptor; source properties are supplied, not
  acquired from a live source inode. This does not qualify volume-query failures.
- 1,012 explicit owner-controlled descriptor setups for unreadable modes.
  Before calling Apple, the harness restores and verifies exact mode and inode
  identity. Observation-only reads use no-follow metadata calls without opening
  restricted payloads.
- Full public statx metadata, attribute-list bytes (including otherwise hidden
  UUIDs/ACL flags), source cache, actual errors, alias identity and final image
  hashes. Initial, native-mutated and Go-written images are retained separately;
  filesystem checkers validate both resulting images. Read-only observations
  must leave Go image hashes unchanged.

Six source files are hash-pinned. Complete function extractions and arm64/x86_64
Clang ASTs are retained. The extra XNU `vfs_subr.c` evidence documents numeric
ownership's set-ID clearing; `vfs_syscalls.c` and `kpi_vfs.c` document selected
attributes and stored security updates. C/Clang is test-only.

All three operating systems replay the committed binary-safe corpus and
reproduce the initial/final image hashes. Focused code coverage must exceed
95% separately for each new/shared file, with no skipped focused tests. Existing
layout controls and deferred-restoration evidence remain required.

## Next integration

Connect live source and volume-policy acquisition to ordered restoration:
creation inheritance, ordinary security copying, stat/flags/times/xattrs, then
deferred AppleDouble replacement and cleanup. Native host authorization,
privileged/sandbox contexts and foreign metadata carriers remain separate open
work. The [five roadmap gates](../pkg/appledouble/README.md#roadmap) remain open.
Package PR72 stays draft; codesign waits for final APFS qualification and release.
