# Ordinary AppleDouble xattr restoration

`hostdata.RestoreXattr` executes the ordinary `copyfile_unpack_xattr` stage on a
caller-bound destination. APFS and HFS+ writer entries expose
`root.RestoreXattr(target, name, value, options)` to apply that policy to image
trees. All implementations are pure Go and available on Linux, macOS and Windows.

Use these APIs for ordinary ATTR records while assembling an unpack provider.
They preserve record-level callback behavior, intent selection and write errors.
They do not remove pre-existing destination attributes or execute the complete
AppleDouble unpack sequence. Serialized ACL text and quarantine must go through
their dedicated routes, so this API rejects those two names.

## Callback and failure behavior

The pinned Apple implementation has different callback rules from the inner
copy coordinator and the separate FinderInfo/resource-fork slots:

| Event | Quit | Continue, Skip or unknown value |
| --- | --- | --- |
| Start | Stops before writing with `ErrXattrRestoreCanceled` | Attempts the write, including for Skip |
| Error | Returns the original write error | Completes while retaining `WriteError`; no Finish event |
| Finish | Returns cancellation after the successful/suppressed write | Completes |

Without a callback, a write error is fatal. The exception is Darwin **EPERM** for
exactly `com.apple.root.installed`: it is suppressed, and a supplied callback
receives Finish rather than Error. EACCES and names with suffixes do not receive
this exception. Providers classify only EPERM with `ErrXattrRestoreNotPermitted`
and retain the actual cause with `errors.Join`.

`Applied` means the write succeeded. `Completed` means native control flow reached
the end. Neither implies the other: Finish can cancel after a successful write,
and a continued/suppressed failure can complete without applying anything.
`WriteError` remains available in both the result and later callback notice.
The result's `Copied` follows native progress state: Start resets it to zero,
Finish sets it to the value length, and a filtered/no-callback operation retains
`InitialCopied`. Even suppressed root-installed failures can report a full count.

The executor freezes value bytes before Start and gives the writer owned storage.
A nil value means a zero-length assignment. Ordinary empty attributes retain
presence; a special attribute may have native normalization. In particular, a
zero-length resource-fork assignment removes the visible fork. There is no
rollback or retry, and callbacks must not mutate source/destination state.

## Captured intent policy

Options describe a captured process context, not the operating system running Go.
The caller supplies `Sandboxed`; false selects the unboxed property table.
At zero `CopyIntent`, the last `#` starts a suffix: `N` enables never-preserve and
`n` clears it, in order. Other letters do not exclude zero intent. Any explicit
suffix, including an empty one, replaces the default property list. Without a
suffix, the sandboxed `com.apple.security.` prefix is never preserved.

**Any nonzero intent bypasses this filtering in Apple's unpack function.** This
includes known copy/save/share/sync/backup values and unknown integers. Applying
the ordinary copy/pack intent rules here would change native behavior. The
executor retains the full logical name; it does not strip the suffix.

## Image bindings

```go
result, err := root.RestoreXattr(target, "org.example.metadata", value,
    hostdata.XattrRestoreOptions{})
if err != nil {
    // Applied can still be true if a Finish callback canceled after publication.
    return err
}
if result.WriteError != nil {
    return result.WriteError // Do not report ignored failures as preservation.
}
// Selected=false is an intentional policy omission. Successful serialization
// remains required after staging into the tree.
```

The binding validates the complete graph before callbacks. Targets are entry
pointers, so symlinks are not followed. Regular hard-link aliases must agree on
ownership, resolved mode, stored security and all logical xattrs. A conflicting
alias fails before publication. Both aliases receive independently owned maps
and new values; other metadata and payload storage remain unchanged.

A write publishes before Finish, allowing the callback to observe it. Cancellation
then leaves the published metadata in place. Raw `com.apple.system.Security`
requires the security APIs; it is not an ordinary image xattr write. FinderInfo
values must be 32 bytes. Image bindings stage storage, not live authorization or
general kernel normalization; existing writer validation still applies to
compression, format bounds and the rest of the tree.

Resource-fork ATTR records on regular files use APFS xattr storage and HFS+'s
existing `Entry.ResourceFork` catalog-fork field. Empty assignment clears the
fork in both. Other attributes preserve that field. An HFS tree that incorrectly
places a resource fork in `Xattrs` is rejected, and alias comparison includes the
actual fork bytes. Non-regular targets refuse fork staging. The separate
AppleDouble resource-fork slot still needs its own callback/error coordinator,
including its native directory-empty-header exception.

## Qualification

`go run scripts/verify-xattr-restore.go` downloads SHA256-pinned Apple sources,
retains their licenses, extracts the complete unchanged `copyfile_unpack_xattr`
function and its six intent/property helpers, and captures arm64/x86_64 Clang
ASTs. The property-table initialization hook models independently captured
sandboxed/unboxed contexts; it does not claim to capture live sandbox state.

- **4,088 controlled observations** cover suffix/default selection, nonzero
  intent bypass, all callback decisions, write failures, exact-name EPERM
  suppression and progress state.
- **180 native application scenarios** execute the same Apple function against
  an actual host-Mac file, including **135 actual write attempts**. Readback checks
  binary/empty values, filtering, FinderInfo refusal, root-installed errors,
  cancellation and empty/nonempty resource-fork normalization.
- Both image APIs exercise roots, files, directories, symlinks and hard-link
  aliases. Four APFS/case-sensitive APFS/HFSX/HFS+ images round-trip ordinary and
  empty attributes plus resource forks. Their bytes match explicit tree staging;
  both APFS fixtures include a snapshot. Existing mounted-image and legacy-layout
  qualification remains a regression gate; these four new images are not claimed
  as new mounted-kernel observations.

The archived corpus runs on all three OSes with CGO disabled.
`go run scripts/verify-xattr-restore-coverage.go` rejects skipped focused tests,
requires above 95% coverage in each new production file and retains source/revision
hashes, test logs and image hashes. Focused coverage is **80/80 statements (100%)**, with **4,278 passing test
records**. The gate covers the executor, shared image binding and both writer entry points.

Sources are pinned to Apple copyfile commit
[`9f91eb6ced021952278816cdc76ad68da8631ccb`](https://github.com/apple-oss-distributions/copyfile/tree/9f91eb6ced021952278816cdc76ad68da8631ccb):

| Source | SHA256 |
| --- | --- |
| copyfile.c | `19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c` |
| xattr_flags.c | `991a340ad26bf9086f9fcbca8eafb0dee4c2ab38e41d152c60fa218e5d4226dc` |
| xattr_flags.h | `0fd2d35d0ae3efba30d30b8c470dae4bc42972455c6d8d5246fec44732f43d49` |

## Remaining integration

Destination-xattr cleanup, ordered record dispatch, quarantine, separate special
slots and deferred ACL-before-stat sequencing still need a complete unpack
provider. Held host/foreign-carrier binding, outer creation/permission restoration,
large-value/allocation behavior and final consumer qualification remain open.
All five roadmap gates remain open. Package PR72 stays draft on APFS v0.13.0;
codesign remains paused until the qualified release and downstream adoption.
