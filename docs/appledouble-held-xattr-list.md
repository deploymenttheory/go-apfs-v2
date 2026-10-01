# Held-file attribute listing

`hostdata.ListXattrNames(file, maxBytes)` lists the visible extended-attribute
names on an already-open file, directory or supported link descriptor. Use it
when restoration needs the destination namespace before cleanup, or when
capturing metadata from an object whose pathname may have changed.

The function works on Linux, macOS and Windows with pure Go production code.
It shares descriptor ownership and error handling with `XattrSize`, `ReadXattr`
and `RemoveXattr`. It does not open `File.Name`, close the caller's handle or
change file position. Windows opens a synchronous EA handle relative to the held
object, keeping reparse-point identity and checking current access rights.

## Result and limits

```go
names, err := hostdata.ListXattrNames(file, 64<<10)
if err != nil {
    return err // names is nil; do not treat failure as an empty namespace
}
for _, name := range names {
    // Capture or apply the selected operation while object state stays stable.
    _ = name
}
```

Names retain native order, bytes and casing. A successful empty list is non-nil.
No name is filtered by copy intent, sorted or converted to another namespace.
The budget counts each name's bytes plus its terminating NUL; it must be between
zero and `MaxXattrListSize` (1 MiB). Returned names and duplicate-detection state
use memory proportional to that bounded byte count. Values are not returned.

| Result | Meaning |
| --- | --- |
| `ErrXattrTooLarge` | The observed names exceed the caller's budget |
| `ErrXattrChanged` | Unix sizing/read disagreed, or Windows enumeration repeated a name or lost all EAs after it began |
| `ErrXattrListMalformed` | Invalid NUL framing, duplicate Unix names or a malformed single-entry NT record |
| `ErrXattrUnsupported` | The actual host/filesystem cannot perform the native operation |
| Other error | The native permission, I/O or descriptor error is retained |

Every error returns a nil list. There is no partial-list success or retry.
Unix enumeration sizes once and reads once. Even an empty size query is followed
by a real read to detect growth. Windows queries one complete
[`FILE_FULL_EA_INFORMATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_full_ea_information)
record at a time through
[`NtQueryEaFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwqueryeafile).
The cursor stays on one handle; a fixed 65,799-byte scratch buffer accommodates
one protocol-maximum record, including its value. Large values do not consume
the names budget. NTFS's actual aggregate/value storage limits still apply.
The same record decoder now serves named EA reads and enumeration.

The caller must exclude concurrent metadata mutation. Same-size Unix changes
and some Windows changes between records cannot be detected. Descriptor pinning
protects object identity and concurrent `Close`, not an atomic metadata snapshot.

## Native namespaces and restoration

Darwin uses ordinary `flistxattr` options through the supported `x/sys/unix`
libSystem wrapper. Hidden security/compression storage is not made visible by
reading an image's raw attribute map. FinderInfo and resource-fork visibility
comes from the filesystem. Linux uses `flistxattr` and its native namespace rules.
An `O_PATH` handle is rejected by that native operation without a path fallback.
Windows retains the names supplied by the kernel, including their raw byte
representation. Existing named Windows reads accept the documented ASCII subset;
listing does not silently discard names outside that subset. Native Windows
qualification accepts a 254-byte name and rejects a 255-byte name without
changing existing metadata. Named operations enforce that same boundary,
consistent with the [EA name specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0eb94f48-6aac-41df-a878-79f4dcfd8989).
The decoder's buffer still accommodates the full wire field range; it never
truncates an enumerated name.

This primitive does not equate Windows EAs or Linux attributes with Darwin
metadata. In particular, NTFS cannot retain a present-empty EA, and native name
rules differ. Foreign metadata still needs an explicit lossless carrier. The
best-effort `ListXattrs` API and its capability flag keep their existing contract.

A listed name is not proof that deletion will remove it: reserved provenance or
other metadata may survive a successful native removal. Restoration must inspect
its detailed result and recapture state when preservation requires it. The Mac
oracle also retains the distinction between a fresh empty resource-fork assignment
and an empty assignment over an existing fork. The latter can retain the old fork;
production write providers must qualify that behavior rather than infer deletion
from an empty byte slice.

## Qualification

`go run scripts/verify-xattrs.go` runs the strict API tests on every supported OS.
It requires above 95% aggregate strict-API coverage and above 95% in each new
listing/EA-decoder source file, rejects skipped tests and archives the full
transcript, test counts, coverage and source hashes. Controlled cases cover size
races, malformed lists/records, bounded allocations, duplicate cursors and late
errors. Both parsers also run as separate CI fuzz targets.

Live Linux/macOS tests compare descriptor enumeration with an independent native
pathname list on stable fixtures. Windows compares single-entry cursor traversal
with an independent multi-entry native query. They exercise files, directories,
renames, old-name decoys, hard links, budgets and unchanged data/file position.
Darwin and Windows also exercise held symlink identity and permission denials.
No operating-system feature check is skipped.

On macOS, `go run scripts/verify-xattr-list-native.go` builds an independent C
oracle with Clang and retains arm64 and x86_64 ASTs, compiler/SDK identity and
16 native observations. It compares complete name bytes and native errors on the
same fixtures, including empty ordinary values, Unicode names, FinderInfo/fork
transitions, security visibility, ACL denial and held file/link renames. The
entire host-provided namespace is retained, including ambient provenance; there
is no filtered comparison. This calls the real kernel through libSystem, rather
than porting or claiming to extract a proprietary filesystem implementation.
Clang is qualification-only.

## Remaining integration

Held namespace listing closes one prerequisite for the production unpack
provider. [Strict assignment](appledouble-held-xattr-write.md) is available. Special-name
policy, cleanup readback, quarantine
state, deferred ACL application and times still need a complete held/carrier
binding. Image namespace visibility/order, foreign carrier conflicts and lossless
round trips also remain. Outer creation/inheritance/permission/close handling and
streaming/allocation work are separate open gates.

All five [AppleDouble roadmap gates](../pkg/appledouble/README.md#roadmap) remain
open. Package PR72 stays draft on released APFS v0.13.0 until the qualified APFS
release is available. Codesign remains paused.
