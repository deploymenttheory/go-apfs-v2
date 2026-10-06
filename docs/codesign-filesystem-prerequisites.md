# Remaining codesign Phase 2 filesystem prerequisites

This work supplies the shared filesystem operations needed by codesign's portable
signing pipeline. Codesign retains representation policy, signature construction,
sideband ordering, replacement versus in-place selection, recompression scheduling
and diagnostic mapping. APFS owns held metadata operations, explicit foreign
filesystem authority, carrier publication and preservation of native host data.

Implementation starts from main commit `3aa2026`, which includes the qualified
recompression package separation in [PR #207](https://github.com/deploymenttheory/go-apfs-v2/pull/207).
Preserve the existing APIs and every qualification gate. Keep the upstream release
batched; this work does not authorize a release. This document records outstanding
requirements, not a claim that the APIs or proposed Windows mechanisms below are
already implemented or qualified.

## Completion gates

- [ ] Owned native compression input and context-aware held fork acquisition.
- [ ] One held observation of filesystem kind and mount policy.
- [ ] Cancellable replacement preparation/restoration and complete cleanup errors.
- [ ] Windows source identity, contained staging and full metadata preservation.
- [ ] Explicit, source-qualified pathname authorization and path recompression.
- [ ] Replacement/in-place publication and hard-link composition acceptance.
- [ ] Above 95% changed production-file coverage and unchanged strict CI gates.
- [ ] Native macOS 15/26/27 qualification and Linux/Windows-produced native readback.
- [ ] Public API documentation, consumer contract and limitation reconciliation.

Check an item only after its implementation and required acceptance pass at the
same PR head. Local probes and successful compilation do not close a platform gate.

## Required changes

### Held native compression input

Add an owned-file constructor for the existing native CompressionInput backend.
The caller acquires a fresh O_RDWR file using its required namespace boundary,
including os.Root.OpenFile for a contained bundle path. The constructor validates
context and a nonnil file, then transfers ownership on success without open,
stat, duplication, truncation, offset changes or other native operations.

The native write-open may already decompress the input. Recompress must retain
its existing admission-stat, eligibility, restoration-stat, zero-byte-write,
duplicate, fork-open, volume, staging, install and cleanup order. Constructor
failure leaves ownership with the caller. A successfully returned input belongs
to the recompression lifecycle; all close errors remain observable. Existing
pathname acquisition remains available through the same backend.

Test ordinary/active/inactive compressed files, root and leaf rename, internal
symlinks, rejected root escapes, cancellation before/after acquisition, closed
and readonly handles, nil file, descriptor position, identity and close counts.
Do not pass nil contexts in production or tests. Distinguish C openat semantics
from Go's stronger os.Root containment rather than claiming they are identical.

### Complete held volume observation and fork context

Capture filesystem kind and raw Darwin mount flags in one descriptor-bound
observation. Reuse Fstatfs; keep unknown or failed observations explicit. Foreign
operations must receive their captured context: an APFS label, AppleDouble
attributes or the receiving operating system does not establish mount policy.
Retain CompressionVolumeFlags compatibility while using the common observation.

Thread operation context through native fork opening and OS-version detection.
Keep the existing no-context API as a compatible wrapper. Preserve macOS 15's
current-path/inode-validation route and 26/27 descriptor-relative route. A15
unlinked-fork limitation must remain explicit; do not promise a namespace snapshot.
Cancellation must close acquired handles without pretending that an earlier
successful native open or partial write was undone.

Qualify actual mounted APFS and HFS+ names/flags on 15/26/27, failure and closed-file
paths, cancellation, and unchanged storage-selection outcomes including CPROTECT.

### Cancellable replacement lifecycle and complete cleanup errors

Add PrepareReplacementContext, PrepareReplacementAtContext, and
RestoreMetadataContext on both replacement types. Existing entry points retain
their noncancellable behavior through common implementations. Carry context into
Darwin fallback attribute/resource-fork copies, Windows stream/native-copy loops,
Linux attribute loops and restore checkpoints. Check between bounded transfers
and native calls; a single kernel call is not guaranteed interruptible.

Cleanup always runs independently of cancellation. Preserve the source and remove
private staging; join the original error with close, permission-restoration and
removal failures. Ignore only explicitly harmless missing private cleanup names.
Use per-call injected operations for fault tests rather than production globals.
Do not chmod a committed replacement or close caller-owned source/root handles.

Exercise cancellation and independent short-read/write, storage, restore, sync,
close and cleanup failures at every owned checkpoint on every host. Keep clone
fallback admission precise: a permission/storage failure is not permission to
silently choose another algorithm.

### Windows held identity and full metadata capability

The current nonrooted CopyFileW path uses source.Name and can copy a replacement
directory entry instead of the held source. The rooted stream route avoids that
lookup but currently rejects compression/encryption and imposes 8 MiB stream limits.
A shared correction must preserve existing capability, including EFS, compression,
sparse and ordinary alternate streams, extended attributes, security, creation
time and relevant file attributes.

Use native CopyFileEx where its full metadata behavior is needed. A pathname
obtained from a held handle is only a lookup hint. Validate the actual callback
source identity and resulting destination identity; require that validation even
for empty inputs. Preserve EFS keys, never allow a decrypted destination, and
report cancellation through the native copy mechanism without losing errors.
Verify the actual EFS recipient and recovery-key metadata: CopyFileEx can fall
back to default keys even without permitting a decrypted destination. Merely
retaining the encrypted attribute does not establish full preservation.

Rooted creation must be contained before the callback. Qualify a private stage
with restricted Windows security and a no-delete-share anchor/necessary namespace
pins. Resolve its actual held path, never reconstruct from root.Name. Prevent
preexisting destination symlink traversal with the documented copy flags. Exercise
ordinary/POSIX ancestor rename, junction and dangling-leaf substitution at
deterministic checkpoints. Callback validation alone cannot prove containment.

Retain a fully held non-EFS route for sources whose names are unavailable. Remove
size-only ADS/EA/sparse-extent ceilings from bounded streaming while preserving
checked offsets, format validation and bounded buffers. Preserve NTFS compression
through held controls. EFS must not enter BackupRead or a plaintext fallback.
Any remaining platform boundary requires evidence and an explicit contract, not
a blanket compressed/encrypted-file exclusion.

Run both replacement variants against independent native-copy observations.
Include source rename/rebind, empty files, ADS above8 MiB, high sparse offsets,
protected DACLs, readonly/hidden/system attributes, compression, EFS recipient-key
metadata, cancellation and cleanup. Provision EFS in Windows CI; do not skip it.

Primary Windows contracts:
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfileexw
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nc-winbase-lpprogress_routine
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupread
- https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_compression

### Qualified foreign pathname authorization

Add a path-aware operation using explicit captured ancestry/security bound to
the selected logical root, manifest generation, macOS profile, authority and
volume. Reuse the existing file authority and recompression engine. A documented
already-resolved endpoint API is a separate acquisition boundary; path callers
must never fall back to it when context is missing.

Every required ancestor needs known ownership/mode and explicitly observed ACL
presence or absence. NativeCaptured describes receiving-host attributes and is
not evidence that a source ACL was observed. Missing source state is a distinct
uncaptured-context error; real denial follows the independently observed native
result. Do not invent 0755 roots, infer source ownership from the receiver, or
translate unknown membership into known nonmembership.

Persist successful complete source-attribute enumeration separately from receiving-
host capture, so later consumers can distinguish observed ACL absence from metadata
that was never read. Older carriers remain uncaptured until explicit observations
are provided. New readers must retain older manifests; document that older strict
readers cannot consume manifests containing newly introduced observation fields.

Bind observed filesystem name-comparison policy as well as mount flags. Reuse the
existing APFS/HFS+ collation implementations for case and normalization behavior;
never infer case sensitivity from an APFS or HFS label. Qualify case variants,
Unicode equivalents, empty paths, NUL input, repeated separators, trailing slashes,
component and total path limits, symlink-expanded lengths and the symlink traversal
boundary. Native source/SDK constants alone do not establish the filesystem
name-length unit or the error ordering relative to directory authorization.

Qualify the shared comparison and on-disk hash implementations together. Full
case folds, canonical decomposition/reordering, ignorable characters and Unicode
revision differences need actual native directory-key observations, not equality
unit tests alone. Do not substitute current Go Unicode tables or a historical
Unicode revision for measured macOS behavior. Preserve the distinction between
APFS/APFSX name hashing and HFS+/HFSX catalog comparison. Replay independently
retained native names and raw hashes, produce images on Linux and Windows, and
read them back natively on every supported macOS version. A foreign operation's
explicit target profile must not be inferred from the receiving host.

Search, create, delete and rename require distinct authorization operations.
Capture per-directory SEARCH before lookup; ADD_FILE/ADD_SUBDIRECTORY for creation;
leaf DELETE versus parent DELETE_CHILD, POSIX/sticky fallback and immutable/append
conditions for removal; source deletion, destination addition and overwritten-leaf
deletion for rename. Account for ordered ACL grants/denials, identity/group lookup,
root boundaries and mount/process context. Capture process/thread ignore-permissions
policy explicitly and qualify source-backed owner overrides; an omitted policy
must not silently become an ordinary-process observation. Consumer policy selects when to invoke
these operations; APFS supplies the qualified reusable filesystem rules.

Qualify read-only mount rejection independently of the file's access bits and
compression storage policy. Require observed ACL presence or absence for selected
leaves as well as ancestors; omitted security metadata is not proof of no ACL.
Distinguish the filesystem context at the logical operation target from an
original distribution image's mount context.

Use separate native copies per operation. Establish successful setup and positive
controls before applying denials through held descriptors; retain setup and
cleanup failures. Compare pathname, root-relative, held-parent and already-open
acquisition before/after permission changes. Record bytes, identity, links, modes,
ACLs, flags, timestamps and namespace state. Missing-context tests are portable
contract tests, not fabricated native EACCES captures.

Compile complete relevant pinned XNU authorization/lookup bodies for both Clang
targets. Existing sources include vfs_subr.c, kern_authorization.c and
kern_credential.c; add lookup_authorize_search/namei/lookup and vn_open_auth bodies
from vfs_lookup.c/vfs_vnops.c. Source release evidence does not substitute for
actual macOS 15/26/27 observations.

### Publication and hard-link composition

Reuse PR #207's Store.Publish rather than introducing another transaction layer.
For replacement, clear only the selected record's LinkGroup and publish its new
payload and uncompressed metadata at the prepared rename boundary. Other aliases
retain the old inode/content. For in-place writes, retain the group and coordinate
all aliases. Recompression follows publication of the actual new payload baseline;
an admission failure must leave the signed uncompressed result represented.

Add composition tests for two/three-name groups, real links and degraded copies,
APFS/HFS+ repacking and native link counts. Existing writers already turn singleton
groups into ordinary files; no new LinkCount schema is needed. Include generation
conflicts, pre-rename cancellation, partial callback changes, manifest failure,
post-publication cleanup errors, and unaffected-alias bytes/metadata.

## Qualification and delivery

Keep all previous native corpora and exact inventories, including PR #207's 648
portable authority cases, 666 image-entry observations per producer, 5,994 native
readbacks, three versioned authority captures, 4 GiB boundaries, codecs, commercial
images, per-platform coverage, race/fuzz and release-build gates. Add new cases;
never replace existing failures with exclusions or inferred successful metadata.

Require above 95% coverage for new/changed production files and all existing package
gates. Keep immutable native sources/provenance, both AST targets, genuine retained
15/26/27 captures, Linux/Windows production and independent native readback. Raise
one coherent draft PR from main; qualify its final head before merge. Preserve the
user-controlled batch release. Codesign integration and its final release-pin
recaptures follow the upstream work; none of these APIs alone closes Phase 2.
