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

### Packed empty values versus filesystem-visible metadata

`COPYFILE_PACK` can encode an empty ATTR value with offset zero. It is a valid
snapshot for unpacking, but the filesystem can reject the entire carrier as an
attribute namespace: even its FinderInfo and resource fork become unavailable.
`DecodeStream` retains that snapshot. `DecodeFilesystemStream`, used by the
filesystem view and in-place removal, applies the observed filesystem rule.
No application mode or CLI flag selects this distinction.

The `packed-empty` profile installs an actual empty native attribute, packs it
with `copyfile`, then exercises the same twelve actions on files and directories
across APFS, HFS+, FAT32 and exFAT: 96 native cases. Both pathname and held queries,
raw carrier bytes and mutation failures are retained. The checked-in capture is
from macOS 27; CI independently captures 15, 26 and 27 and requires all three
corpora on Linux, Windows and macOS. The original 960-case profile stays required.
Native VFS-created empty values have ordinary data offsets and remain supported;
the original `empty-plain` cases retain that positive control.

The distinction matters to generic signature removal. A missing individual value
is harmless to that removal operation, while failure to list an existing invalid
namespace remains an error. Consumers retain the operation's already-committed
changes and render its diagnostic; the filesystem API preserves the distinction.

```sh
go run scripts/capture-metadata-filesystem.go -profile packed-empty -out artifacts/metadata-packed/native.json
go run scripts/capture-metadata-filesystem.go -profile packed-empty -verify artifacts/metadata-packed/native.json
```

## Reading filesystem-selected metadata

### Attribute files as query targets

On FAT/exFAT, querying attributes on a regular `._name` file fails with `EPERM`.
This is distinct from an access-denied (`EACCES`) result. The filesystem view
preserves that distinction on every host: codesign treats a presence-query
`EPERM` as absence but still rejects removal failures and access-denied queries.
A directory named `._name` remains a directory with its own metadata; the rule
does not apply to every name beginning with dot-underscore or to native APFS/HFS
storage.

The `attribute-target` profile captures 192 C-oracle observations across all four
filesystems: file/directory targets, absent/present associated storage and all
twelve operations. Retained evidence is from macOS 27. CI captures macOS 15, 26
and 27 independently, then requires every producer's read and removal outcomes
on Linux, Windows and macOS, including exact unchanged bytes after failed
removals. Both XNU dispatch AST targets remain required.

### Opening a metadata view

`hostdata.OpenFilesystemMetadata(ctx, root, name)` opens a contained entry and
retains its parent association. `List` returns visible attribute names, `Size` queries without allocating the value, `Read`
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

## Held objects and attribute removal

`FilesystemMetadataForFile(ctx, file)` borrows an already-held object. Closing
its view leaves the caller's file open. Native storage never reopens its name.
Foreign FAT storage resolves the descriptor's current path through the OS and
verifies that the entry still identifies the held object. Descriptor labels are
not used as paths; the existing typed Windows final-path and Darwin held-path
wrappers are reused, and Linux resolves its process-owned `/proc/self/fd` link. A missing or substituted name is an error;
callers must keep the descriptor open and exclude concurrent namespace changes.
`UsesAppleDouble` and `CaseInsensitiveNames` report the selected storage's
properties; they do not change the selection.

`Remove(ctx, name)` preserves the data fork and deletes the selected attribute.
Missing attributes return `false, nil`. Native storage uses the existing held
attribute-removal API. Foreign FAT storage checks the carrier's identity before
opening a writer and before unlinking an empty carrier. Successful earlier writes
remain visible after a later failure; this is not a transaction or rollback API.

`appledouble.RemoveFilesystemAttribute` implements the bounded byte operation
separately from filesystem association. It retains record order, allocation slack
and unrelated bytes, shifts large values in 64 KiB chunks, and truncates a trailing
fork when appropriate. An empty result asks the filesystem owner to unlink the
carrier. Snapshot decoding accepts layouts that are unsafe to mutate in place;
overlapping descriptors, inconsistent summary ranges and non-VFS zero-offset
empty values are rejected before mutation. They remain readable by the snapshot
codec. This qualification does not establish native results for every malformed
layout.

The retained producers supply 360 FAT removal cases across files, directories,
missing/malformed storage and each of the three removed attribute kinds. Portable
API tests compare whole entry sets and file bytes; 180 decodable-carrier cases
also compare the codec output byte for byte. The macOS 15/26/27 captures permit
directory fork removal in these cases, so the older published XNU rejection
branch is not used as the current runtime contract. Structural large-value tests,
cancellation and IO fault injection are distinct from these native observations.

## Qualification and remaining deliverables

Each retained macOS 15/26/27 fixture comes from its actual producer. Portable
readback checks both before and after snapshots of the 480 FAT cases per producer:
2,880 snapshots in total. The independent CI metadata job requires every compiled new
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

Discovery, reads and the captured removal cases are implemented. The complete
filesystem operation layer still requires the following qualification.
The following deliverables remain required:

- Version-qualified create, replace and set operations, including the
  macOS 15 versus 26/27 FAT resource-fork write differences.
- Native byte layout and partial effects for creation/assignment, broader empty-value
  and large-removal captures, and foreign-produced removal readback; copyfile
  packing is not interchangeable with the VFS writer.
- Authorization, readonly storage, ownership, links, root paths, rename/unlink
  association, concurrent substitution, cancellation and cleanup qualification.
- Foreign-produced output readback on native macOS, genuine large-fork acceptance,
  and remaining ordinary-attribute streaming limits.
- Resolve the [local native allocation counterexample](../testdata/appledouble/native/allocation-observations/README.md) without discarding stored-byte or lifecycle checks.
- Codesign consumption, removal/replacement of obsolete CLI routing scenarios,
  and complete Phase 2 lifecycle and resource-budget acceptance.

These gaps keep the prerequisite open even when the metadata coverage job passes.

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

### Replacement on volumes without ACLs

Darwin replacement queries `ATTR_VOL_CAPABILITIES` through the held file before
clearing staging ACLs or restoring source ACLs. The value and validity bit for
`VOL_CAP_INT_EXTENDED_SECURITY` must both be understood. FAT32 and exFAT report
that extended security is unsupported; no ACL operation is needed there. APFS
and HFS+ keep the existing ACL capture, temporary write access and restoration
checks. Query failures and unknown capabilities are errors, never permission to
discard metadata. See Apple's [volume capability contract](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getattrlist.2.html).

`TestReplacementVolumeDarwinNative` exercises both path and rooted preparation on
fresh APFS, HFS+, FAT32 and exFAT images. The independent Clang-built
`replacement-volume.c` observer checks capability results and creation-time setter
precision; exFAT setters can round a source creation timestamp. The test compares
against the actual native result and verifies ownership, mode, flags, unrelated
attributes, unchanged source data and removal of private staging objects.
`scripts/verify-replacement-volume.go` retains both architecture ASTs, source
hashes, native observations and coverage. The replacement workflow runs it on
macOS 15, 26 and 27. This Darwin qualification does not establish foreign-host
replacement of associated AppleDouble files; that remains a separate prerequisite
for complete transparent signing on Linux and Windows.

### Querying attribute-file storage

`hostdata.FilesystemUsesXattrFiles(ctx, file)` queries the held object's volume.
On Darwin it reads `VOL_CAP_INT_EXTENDED_ATTR` and its validity mask; missing
native support (including an unknown capability) selects companion-file storage,
matching Apple's `pathFileSystemUsesXattrFiles`. Query and malformed-reply errors
remain errors for callers to handle. On Linux and Windows the qualified FAT and
exFAT filesystems select that storage; native attribute filesystems do not.

This differs from `FilesystemMetadata.UsesAppleDouble`, which identifies whether
Go itself resolves carriers. Darwin's kernel resolves them even on FAT, so that
method remains false there. Neither query makes every `._` file a valid carrier.
Callers must apply their own enumeration policy and inspect the companion object.
For example, codesign root validation and resource traversal have different rules.

The native volume qualification checks this query against a Clang-built oracle
on APFS, HFS+, FAT32 and exFAT across macOS 15, 26 and 27. Portable lifecycle tests
exercise cancellation, missing/closed handles and caller ownership on all hosts.
