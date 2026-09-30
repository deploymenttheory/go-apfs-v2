# AppleDouble path lifecycle

The path operation creates or opens an AppleDouble destination, executes the
metadata operation, and performs Apple's permission and descriptor cleanup.
It is different from operating on descriptors the caller already owns. This
document explains `hostdata.CopyAppleDoublePath`, its measured behavior, and
the evidence used to qualify it. Captured logical metadata makes the same
policy usable on Linux and Windows; native Darwin bindings use Go and fixed
libSystem wrappers, never the native copyfile algorithm.

## Source and evidence

The published source reference is Apple's complete `copyfile.c` at commit
`9f91eb6ced021952278816cdc76ad68da8631ccb`, SHA-256
`19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`.
The relevant functions are `copyfile`, `copyfile_open`,
`copyfile_internal`, `copyfile_fix_perms`, `add_uberace`, `is_uberace`,
`remove_uberace`, `reset_security`, `copyfile_close`,
`copyfile_state_free`, `fd_volume_has_feature`,
`path_does_copy_protection`, and `do_copy_protected_open`.

Published source establishes that source version's ordering. It does **not**
exactly match the installed macOS 27 implementation: the installed library adds
held-destination permission acquisition and identity validation. The production
path policy follows the measured current behavior, not an optional obsolete
compatibility mode.

The retained `path-lifecycle-macos27-arm64.json.gz` records complete instructions
for ten installed functions on macOS 27.0 build 26A428, libcopyfile UUID
`72D95AF9-BF5E-3A84-81A6-BCC5BDB99857`. Run
`go run scripts/capture-path-lifecycle-binary.go` to capture a fresh profile from
an owned test process stopped at `main`. Its report deliberately says
`capture:true, passed:false`: disassembly is evidence to review, not a successful
behavioral qualification. `copyfile_close` is inlined in this image; its caller
`copyfile_state_free` is retained. Addresses are the actual captured image's
addresses and its base is retained; they must not be compared across image
slides as if they were stable identifiers.

The separate live gate `verify-path-copyfile-native.go` invokes native copyfile
on real disposable files, directories and links. The 552 retained cases cover
creation, replacement, ACLs, malformed unpacking, callbacks, no-follow flags,
move and explicit state-free errors. Every capture retains ordered raw xattr
names and values, size/read errors, followed and no-follow source ACLs, exact
regular source bytes, and the actual sandbox predicate before the operation.
The same complete context is captured afterwards. This includes automatically
supplied attributes such as `com.apple.provenance`; they are never filtered.
The shared native context observer also captures held object identity, numeric
owner and process IDs, mode, BSD flags, exact external ACL bytes, descriptor
access flags, filesystem type and mount flags. Followed and no-follow objects
are recorded independently. The corpus retains fixture owner/principal
identifiers needed for exact ACL and provider-context comparisons; it does not
collect account names or full directory-service records. The observer header
is hashed alongside each C helper.

`TestAppleDoublePathNativeReplay` compiles the independent C oracle, prepares
separate C and Go inputs, verifies their complete captured contexts are equal,
then compares the concrete Go API's return code, metadata, contents and
callbacks against that installed native operation. The retained baseline is
context-bound evidence: the live gate requires exact baseline equality when
the input context matches, reports differences in ambient input context, and
requires all 552 current-context C/Go comparisons in either case. An attribute
supplied on one host and absent on another is an input difference, not by itself
evidence of a different codec or macOS version policy. The native test requires
the existing Xcode/Clang qualification toolchain; production remains pure Go.
Only device/inode identifiers are excluded when comparing separately created
equivalent fixtures. Raw observations retain them for identity checks within
each operation; owner, ACL, process, filesystem and access context remain exact.

`verify-xattr-remove-effects-native.go` independently observes removal and
replacement on 228 owned fixture contexts, including regular files, directories,
held links and dangling links. Each records exact syscall input, result and
readback, before/after provider context, unchanged referents, and cleanup.
Read-write directory acquisition failures are captured explicitly. A successful
call can leave bytes unchanged; portable replay uses that observed post-state
without inventing an attribute-name rule. Matching an unpack destination uses
its measured temporary mode and ACL, derived through the separately qualified
native permission policy, rather than treating its initial permissions as the
mutation-time context. The native gate replays its current captured effects
through the Go API and compares retained results only for matching contexts.

Explicit caller-owned state-free fields belong to the C fixture;
the Go path API instead owns and closes its handles.

An extracted source function establishes source-version behavior. An extracted function executing against
controlled providers establishes error paths under those stated providers.
Calling the installed macOS `copyfile` function on real files establishes
observable host effects. These are separate evidence classes; an AST or a
controlled provider alone does not establish host behavior.

## Operation order

1. Initialize the state and replace supplied source/destination names. Replacing
   a previously associated name can close its old descriptor; those close errors
   are ignored. Same-object detection returns success without further work, or
   `EEXIST` with exclusive creation.
2. Allocate destination filesec and capture with `statx_np` or `lstatx_np`.
   Destination no-follow selects `lstatx_np`; source no-follow also selects it
   when the source is a link. Symlink filesec is captured and can receive the
   temporary ACE. Only `ENOENT` sets the `createdst` flag.
3. Skip temporary permission preparation when destination unlink was selected.
   Otherwise duplicate an existing destination's filesec. If an ACL property is present,
   prepend an allow ACE for the current **real** UID's UUID. Its rights are
   write data, append, write attributes, write extended attributes, write
   security, and synchronize. An absent ACL property does not become an empty
   ACL. If the mode property is present, add owner read/write bits.
4. Open the destination read-only, using `O_SYMLINK` for an observed link, or
   `O_NOFOLLOW` when requested for another type. Compare held device/inode/type
   against the initial capture; mismatch is `EBADF`. Apply permissive filesec
   through this descriptor. `ENOTSUP` alone falls back to held chmod with the
   original mode plus owner write. Other errors, or fallback errors, are fatal.
   Success marks permissions changed and retains the descriptor for cleanup.
5. Capture source stat/security using the selected follow policy, reject
   unsupported types (except the explicit metadata-only `/dev/null` source), open it, and compare device/inode/type against the first
   observation. Re-stat the source path and check its type. The second path
   check does not compare inode/device. Capture source quarantine; its error is
   ignored but remains useful diagnostic evidence.
6. For a regular source with extended attributes selected, inspect the resource
   fork, including when packing was selected. Above 1 MiB, open it with
   `openat(sourceFD, "..namedfork/rsrc", O_RDONLY)`, then allocate its stat
   storage and `fstat`. Open/allocation/stat failure closes any acquired fork
   descriptor and falls back to xattr IO. The threshold is not a codec limit.
7. Remove the destination first with `remove(3)` when unlink is selected
   (this can remove an empty directory, unlike failed-pack `unlink`). Query source volume
   content-protection support; query failure is fatal. For a regular file or
   directory on a supporting source volume, obtain its protection class unless
   the caller explicitly suppressed protection changes.
8. Create/open the destination according to the table below. After opening, query
   destination volume support only if source support is true. Apply an explicit
   class when the branch requires it. Failure is fatal even after creation or
   truncation. When the source fork descriptor was acquired, open the destination
   fork with held `openat` using `O_WRONLY|O_CREAT|O_TRUNC`. This **truncates an
   existing destination fork before the route**, including for pack plus xattr.
   Failure closes the source fork and restores xattr fallback. The installed
   helpers `open_src_rsrc_fork` and `open_dst_rsrc_fork` are retained in the binary
   fixture; the older published source instead assembles named-fork pathnames.
9. If a temporary permission descriptor was acquired, compare its current
   device/inode/type with the opened payload descriptor. Mismatch is `EBADF`;
   stat errors are fatal. Request `F_NOCACHE` on both descriptors and `F_SINGLE_WRITER` on the
   destination when available. These errors are ignored. The path operation
   requests no-cache independently of the optional held-operation flag.
10. Execute packing or unpacking. A negative pack result attempts to **unlink
    the destination even if it existed before the operation**; unlink errors are
    ignored. An outer result of exactly `-1` takes error cleanup. Other results
    continue success cleanup, including positive native error codes.
11. On success, restore an existing destination's BSD owner/group/mode when stat
    copying was not selected. Close the temporary permission descriptor before
    removing a matching first temporary ACE unless the
    recursive delayed-ACE state is active. Optionally remove the source for move;
    that error is ignored.
12. On failure, restore only BSD owner/group/mode through the saved permission
    descriptor, falling back to the payload descriptor if none was acquired,
    when permissions changed and the destination was not initially absent.
    Close the temporary descriptor afterward. This branch does not remove the
    temporary ACL. Preserve the original
    error through cleanup, then prefer the state error when one was supplied.
13. Release an internally allocated state. Source close failures are ignored;
    destination close failures make `copyfile_state_free` fail, but the outer
    `copyfile` ignores that return and restores its earlier errno. A caller-owned
    state retains its descriptors until explicitly freed. No fsync occurs in
    this sequence.

## Creation and retry policy

| Situation | Native action |
| --- | --- |
| Pack any supported source kind | Destination is created as a regular AppleDouble file; source directories/links do not choose directory/link destination creation. |
| Unpack | Destination opens read-only because the operation writes metadata. |
| Copy a symlink without pack | Allocate link payload using source size plus one (or `PATH_MAX+1` when zero), read it, create the link, tolerate `EEXIST` unless exclusive, and open with `O_SYMLINK`. |
| Copy a directory without pack | `mkdir` with source permissions plus owner `0700`; tolerate an existing destination unless exclusive; open read-only using selected destination follow policy. |
| Regular destination creation | Initial flags include `O_EXCL|O_CREAT`; source mode includes owner write. Packing adds `O_WRONLY`, unpacking uses `O_RDONLY`. |
| `EEXIST` | Unless exclusive, remove `O_CREAT`; add `O_TRUNC` for pack or data copy; retry and remember to apply the protection class explicitly. |
| `EACCES` | The installed current implementation fails immediately. Its new held permission acquisition replaces the older published source's path chmod/retry branch. |
| `EISDIR` | Unless prohibited by the exclusive/data combination, retry read-only after clearing write/create/truncate. Unpack overrides that prohibition. A later pack write may consequently fail. |
| Destination mount protection | Each protected-open attempt first probes the path with `statfs`; on `ENOENT` probe its parent. Failure of this path probe selects ordinary `open`, unlike the fatal held-fd volume probe. |

The API uses an explicit open-attempt budget and cancellation for providers
that repeatedly return retryable `EEXIST`/`EISDIR`. Budget exhaustion is a library
diagnostic, not an invented native errno. Symlink creation starts at
`0777 & ~umask`, independently of source link permissions; the live corpus
includes source mode `0400` with umasks `0000` and `0077` on failed unpack.
Once restoration begins, effective-identity lookup uses
`context.WithoutCancel`: caller context values remain available, while a late
cancellation or deadline cannot itself prevent temporary-ACE removal. Actual
identity lookup and restoration failures remain recorded in the cleanup trace.

## Temporary ACE removal

`is_uberace` compares the principal with the **effective** UID's UUID, the allow
tag, and the complete expected permission mask. Only the first ACE is inspected.
The template itself is built with `add_uberace`, which resolves the real UID.
Extra inheritance bits are not independently tested by this function.

`remove_uberace` falls back to ordinary chmod when filesec allocation fails,
native statx returns `ENOTSUP`, or deleting/replacing the matching first ACE or
writing its filesec fails. Other statx failures, absent ACL, missing first entry,
or a nonmatching ACE exit without that fallback. `reset_security` obtains the
desired mode from source stat when stat copying is selected, otherwise from
destination stat. The C code does not check that stat call's return: a failure
would expose uninitialized memory and must become an explicit deterministic
diagnostic in Go rather than manufactured native behavior.

## Implementation boundaries and remaining qualification

`CopyAppleDoublePath` binds this sequence to real held Darwin descriptors or
captured logical directory/image state. Applications select PACK or UNPACK and
supply the corresponding object options plus a positive `MaxOpenAttempts`.
They do not reimplement Apple policy in stage callbacks. Linux and Windows use
`CapturedPathContext` for the same creation, inheritance, ACL, protection and
cleanup rules. The source and an existing destination must be associated with
their payloads; source type must agree with the observed payload type. Creation
requires captured creator state, parent ACL and umask. Nil real/effective UUID
pointers fail as uncaptured identities before effects; a nil protection pointer
is unknown rather than a negative capability observation. Their native
filesystems do not acquire Darwin authorization or protection classes merely by
storing these observations. Temporary receiving-host backing permissions are
saved/restored independently of the logical Darwin result.

Windows payload handles share read, write and delete access. This permits the
same held-inode rename and failed-PACK unlink ordering without closing handles
early. Backing permission changes acquire `FILE_WRITE_ATTRIBUTES` on the held
object itself; they do not resolve the original pathname again. Read-only
receiving-host files can therefore receive temporary access and recover their
original attributes even when their directory entry is renamed. Exclusive
creation, truncation and long filesystem paths retain their normal semantics;
an inaccessible read-only file is not replaced to make truncation succeed.

On Linux and Windows, a no-follow destination link is opened as a metadata-only
object. A PACK data write fails on that held link and the operation then removes
the failed destination, matching the native lifecycle. Its referent is never
opened for writing or truncated, including when the link is dangling or points
outside the working directory. Receiving-host I/O errors remain observable;
Linux or Windows error numbers are not relabeled as Darwin errno values.

The path named-fork lifecycle is implemented on both bindings. For a regular
source with a fork strictly larger than 1 MiB, installed macOS opens the source
fork relative to its held data descriptor and stats that fork. After destination
protection setup it opens the destination fork with create/truncate, including
PACK. Failure falls back to the ordinary attribute route; a failed destination
open closes the source fork. Final release orders source data, source fork,
destination data, destination fork, preserving ignored and close failures in
diagnostics. Captured execution performs the same logical destination truncation
on Linux and Windows without requiring their native xattrs to store the fork.
The held-object `fcopyfile` facade has no path-open stage and does not gain this
truncation merely because a value is large.

`verify-path-fork-native.go` independently compares twelve installed C/Go cases:
PACK/UNPACK, absent/exact-1-MiB/1-MiB-plus-one source forks, and new/existing
destinations. It checks full data/sidecar bytes, native metadata and the observed
fork lifecycle. Explicit source stat copying makes new destination timestamps
deterministic without masking differences. The portable tests also exercise
public captured operations, ignored open failures, partial acquisition, source
fallback close errors and final close ordering.

These APIs are implemented; final revision CI remains the qualification gate.
The real root/nonowner supervisor, genuinely signed sandbox operation cases and
large streamed foreign-image checks must pass alongside all existing coverage,
native, fuzz and race jobs. See [object ownership and budgets](appledouble-object.md)
and [large-value transport](appledouble-large-values.md). Package refactoring is
deferred; it does not replace any functional or evidence requirement.

The path API resolves intermediate paths normally and requires the caller to
exclude concurrent namespace and metadata mutation. Its destination permission
writes and cleanup are held-descriptor operations. A contained root-relative
API must retain its stronger identity/containment guarantees. Pre/post identity observations are not proof against
replacement followed by restoration of the original entry.

The source gate retains full published outer/open/security functions and both
SDK architecture ASTs. The 579-case security oracle executes unchanged
published functions with real ACL/filesec providers and controlled failures.
The installed binary's new permission/validation helpers are not present in
that published source: their order is qualified through retained disassembly,
real path behavior, and explicit Go provider-failure tests. That distinction
must remain visible; the old source AST is not proof of the new binary body.

The capture host supports content protection. Tests exercise actual held
GET/SET of the observed class and protected creation with default class `-1`.
Provider faults cover explicit refusal; this does not prove every class is
available on every filesystem. CI must establish each supported runner's live
behavior, and additional native profiles must be retained when it differs.
No corpus or branch coverage percentage proves equality for all possible
concurrent filesystem mutations or undefined C allocation failures.

`FuzzPathLifecycle` exercises the production captured path binding on actual
files on every supported OS. Inputs select PACK/UNPACK, bounded endpoint retries,
exclusive/replacement/move options, malformed or failing source values,
cancellation between acquisition/transfer stages, and cleanup failures. Each
run limits attributes to 64 bytes and open attempts to 6. It verifies that all
acquired descriptors are closed exactly once, release is idempotent, error
cleanup restores temporary modes before releasing the permission handle,
cancellation cannot run success-only cleanup, and unpack leaves data bytes
unchanged. Errors from acquisition and release remain observable together.
The regular three-OS test jobs replay its seeds; the existing scheduled/PR fuzz
workflow mutates inputs. These invariants complement the independent native
corpus and do not manufacture native error numbers.

The canonical null source is `os.DevNull`: `/dev/null` on Darwin/Linux and `NUL`
on Windows. Captured operation requires an explicit Darwin character-device
metadata view and verifies that the actual held input is a character device.
Only this canonical input receives Apple's exception; arbitrary special files
remain rejected. Packing creates a regular AppleDouble file; unpacking the empty
input fails after regular destination creation. No null-device metadata is
modified by the operation or its native qualification fixtures.
