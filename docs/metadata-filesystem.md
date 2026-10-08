# Filesystem-selected metadata

The codesign consumer needs ordinary path operations to see the metadata that
macOS exposes, without asking users to supply AppleDouble flags or a sidecar map.
This behavior belongs in the shared filesystem layer. AppleDouble byte decoding,
copyfile pack/unpack semantics and filesystem-visible attributes are separate
contracts; success in one does not establish another.

## Native evidence and CI

`scripts/capture-metadata-filesystem.go` creates disposable APFS, HFS+, FAT32 and
exFAT volumes with Apple's tools. A Clang-built C oracle queries both held and
no-follow path attributes, records complete name lists, and performs native
attribute operations. Inputs include ordinary files and directories with absent,
valid, truncated, bad-magic, empty, directory-valued and readonly sidecars, plus
native-seeded and conflicting storage controls. Twelve actions cover reading,
plain/fork create/replace/set, empty assignment, removal and zero FinderInfo.
There are 960 required cases, with full input/output carrier bytes and native
results. Permission and link profiles beyond these cases remain outstanding.

The seed comes from native attribute installation and `copyfile` with
`COPYFILE_PACK | COPYFILE_ALL`; its three intended values are validated before
capture. Filesystem seeding itself can have different native outcomes (for
example fork installation on FAT/exFAT); command journals preserve those results,
and every case records the actual values visible before the requested action.
Fixture creation removes host-created provenance sidecars before preparing an
explicit absent or replacement-sidecar state. This does not normalize attributes
out of the operation's observations.

FAT32 and exFAT use shared-volume ownership (`-owners off`), matching the
normal ownership mode documented by `mount_exfat(8)`. APFS and HFS+ retain
`-owners on`. Forcing Unix ownership on FAT made setup depend on the mount
service's identity and prevented the macOS 15/26 CI user from creating fixtures.
This change does not disable file-mode checks: readonly sidecars remain in every
producer's matrix. Before cases begin, the C oracle records actual mount flags,
mount owner, process credentials, and root ownership/mode in `mount-N.json` and
the CI log. Dedicated ownership/authorization profiles remain separate work.

The existing Metadata transport workflow now captures macOS 15, 26 and 27
separately. Each producer must report the requested actual version; a moved runner
alias fails rather than silently substituting a different producer. All three
host operating systems validate every producer's complete corpus. Negative tests
reject missing/duplicate cases, malformed observations and damaged input seeds.
The shared CI reporter retains command boundaries, heartbeat/deadline information,
raw channels and failures. A failed capture saves an explicitly incomplete report.

Both Clang targets also compile four complete pinned XNU attribute dispatch
bodies. Kernel helpers are declaration-only shims; private constants and vnode
layout are symbolic. This is static source evidence, not kernel execution or a
claim that a published source revision matches the installed macOS binary.

## Reading filesystem-selected metadata

`hostdata.OpenFilesystemMetadata(ctx, root, name)` opens a contained entry and
retains its parent association. `List` returns visible attribute names, `Read`
returns an owned value with a caller-supplied allocation bound, and `OpenValue`
returns a sized `ReaderAt` that owns its backing handle. Close both the view and
each returned value; a value remains readable after the view closes. The context
supplied to `OpenValue` also cancels subsequent reads.

Selection is automatic. On macOS the kernel selects the storage. On Linux,
`fstatfs` selects AppleDouble for FAT/exFAT. On Windows, the held volume's FAT,
FAT32 or exFAT type selects it. Other local filesystems retain native attributes;
a neighboring `._` file does not enable an alternative metadata mode. The codec
is reused for borrowed value ranges, without copying the resource fork.

Pass a named entry beneath its parent root, including when inspecting a
directory. Dot, dot-dot and an empty final path component are rejected. A root
capability does not authorize reading its parent's sidecar, and a planted `._.`
inside an arbitrary directory must not become that directory's attributes.
Volume-root metadata and consumer path normalization remain integration work.

The retained observations establish visible name order, empty versus missing
attributes, zero FinderInfo suppression, the native blank-fork marker, and the
difference between absent storage and an existing invalid header. In particular,
invalid-header enumeration returns `ErrXattrNotFound`; it is not a successful
empty list. Permission, identity, I/O and unqualified format errors remain errors.
Exclude concurrent namespace and content changes: held identity checks do not
provide a snapshot transaction or detect arbitrary same-size in-place edits.

Resource-fork reads use the existing 64-bit named stream on APFS/HFS. Darwin FAT
forks use held positional attribute reads because their fork vnode can have a
different inode from the data vnode. The AppleDouble length field bounds that
route to `uint32`; it does not limit native APFS/HFS forks. Ordinary native
attributes still use the existing bounded snapshot API (8 MiB maximum).

## Qualification and remaining deliverables

Each retained macOS 15/26/27 fixture comes from its actual producer. Portable
readback checks both before and after snapshots of the 480 FAT cases per producer:
2,880 snapshots in total. The independent CI read job requires every compiled new
production file to exceed 95% coverage and rejects skipped tests. It retains the
raw profile, test transcript, source hashes and exact revision. The final evidence
auditor imports that host's report from the same workflow run instead of executing
the focused suite again.

Fresh captures also compare the public Go reader with the live C oracle on all
960 cases, including APFS and HFS+. Linux, Windows and macOS replay the resulting
FAT snapshots after independently validating all three producer corpora. A sparse
format-boundary test checks reads around 2 GiB and at the maximum 32-bit fork
length without allocating or writing a dense multi-gigabyte fixture. That test is
a storage/format boundary check, not a native large-fork capture.

This implements discovery and reads, not the complete filesystem operation layer.
The following deliverables remain required:

- Version-qualified create, replace, set and remove operations, including the
  macOS 15 versus 26/27 FAT resource-fork write differences.
- Native byte layout and partial effects for sidecar updates; copyfile packing's
  layout is not interchangeable with the VFS writer's layout.
- Authorization, readonly storage, ownership, links, root paths, rename/unlink
  association, concurrent substitution, cancellation and cleanup qualification.
- Foreign-produced output readback on native macOS, genuine large-fork acceptance,
  and remaining ordinary-attribute streaming limits.
- Codesign consumption, removal/replacement of obsolete CLI routing scenarios,
  and complete Phase 2 lifecycle and resource-budget acceptance.

These gaps keep the prerequisite open even when the read coverage job passes.

## Cleanup and CI refinement

The completion work includes an audit of native behavior, useful library/transport
contracts, fault injection, obsolete CLI scenarios and duplicate execution.
Codesign's invented AppleDouble routing flags are to be replaced by ordinary
command/filesystem cases. Record old case IDs, the reason for replacement and the
new native requirement/case IDs; do not retain obsolete product semantics merely
to preserve an old test count.

The APFS metadata carrier also serves real extraction/repacking consumers. Its
explicit API tests are valid library tests, not proof that a native codesign CLI
requires configuration. Keep necessary library and corruption/failure tests.

CI timing baseline at release commit f9b546a: the macOS and Windows core jobs
execute for approximately 37 minutes. Windows runs carrier qualification for
about six minutes and then the complete unit suite for about ten minutes;
separate carrier/owned-compression workflows also execute those packages.
Consolidation must retain unique cases and raw per-host coverage, including
stricter per-file gates, while removing duplicate execution. Distinct race modes,
macOS producers and foreign-image readbacks are not interchangeable. Separate
queue time from execution time when evaluating improvements.
