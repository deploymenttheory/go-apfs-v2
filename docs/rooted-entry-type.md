# Rooted basic entry-type queries

`hostdata.ReadEntryType(root, name)` returns the `os.FileMode` type bits of a
contained entry without reading its data, ACL or extended attributes. Zero means
a regular file; directory, symlink, device, FIFO and socket results use Go's
corresponding type bits. No permission bits, size, owner or timestamps are
returned.

Use it when discovery needs only to establish an entry's type and must distinguish
basic-attribute authorization from later content acquisition. For example,
macOS platform-plist discovery can fail on denied `readattr`, yet still select a
plist whose ACL or extended attributes cannot be read. A full metadata stat and
a content open have different authorization requirements. This API supplies the
filesystem observation; the consumer owns plist selection and fallback policy.

```go
kind, err := hostdata.ReadEntryType(root, "Contents/Info-macos.plist")
if err != nil {
    return err
}
if kind == 0 {
    file, err := hostdata.OpenContentFileRead(root, "Contents/Info-macos.plist")
    // Handle this separate acquisition result and close file when successful.
    _, _ = file, err
}
```

## Containment and authorization

Names must be local to the supplied `os.Root`. Intermediate links must remain
inside that root. A final symlink is inspected without following its target,
including dangling links and links pointing outside the root. Renaming the root
and replacing its old pathname does not redirect the query. Nil/closed roots,
missing entries, escapes and actual authorization failures return errors; native
causes remain available through `errors.Is` and `errors.As`.

| Host | Leaf query | Authorization retained |
| --- | --- | --- |
| macOS | Descriptor-relative `getattrlistat`, requesting only `ATTR_CMN_OBJTYPE` with `FSOPT_NOFOLLOW` | Basic-attribute access; no data, ACL or EA read request |
| Linux | Rooted `Lstat` | Native path/search authorization; no file-data read |
| Windows | Existing typed NT opener with `SYNCHRONIZE` and `FILE_READ_ATTRIBUTES`, followed by held stat and close | Basic attributes; no `READ_CONTROL`, `FILE_READ_EA` or `FILE_READ_DATA` request |

Parent acquisition retains the existing rooted provider's authorization
requirements. On Windows, directory-list permission can grant visibility of a
child's attributes despite a leaf attribute denial. No synthetic Darwin ACL is
applied to a Linux or Windows kernel, and no operation changes permissions to
make a query succeed. Explicit transported policy remains the consumer's concern.

This is a point-in-time observation, not a held identity or an access guarantee.
A subsequent content or mutation operation must bind its own descriptor and
exclude or detect concurrent changes. The API does not provide a transaction
between discovery and acquisition.

## Native boundary and evidence

The approved typed Darwin extension adds one fixed `getattrlistat` import;
production remains CGo-free, with no helper executable, runtime lookup or raw
numbered syscall. Clang checks the host SDK signature for both Darwin
architectures. The response is eight bytes: the length and a four-byte vnode
type. Invalid lengths and unknown vnode types fail explicitly. Apple's
[attribute-list manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getattrlist.2.html)
describes requesting only the needed attributes and inspecting final links.

The independent [C observer](../testdata/appledouble/native/entry-type.c) compares
the minimal query with `fstatat`. The retained
[17-case corpus](../testdata/appledouble/native/entry-type.json) includes separate
read, readattr, readsecurity, readextattr and write-right denials, combined
readattr/readsecurity and data/ACL/EA denials, directories, links, FIFO, socket
and absence. In the captured Darwin cases, a full stat fails on `readsecurity`;
the basic type query succeeds. Both fail on `readattr`. Data denial alone does
not block either metadata query.

Regenerate on macOS with `go run scripts/capture-entry-type.go`. Live tests build
the C observer again and require agreement with both the retained corpus and the
Go API. Every supported host verifies the corpus shape, expected results and
source hashes. Windows tests install effective ACL/EA/data denials and prove an
ordinary generic-read open fails before accepting the narrow query's success.
Linux tests run as a non-root user and retain effective search/data denials.

`go run scripts/verify-held-metadata.go` includes every new implementation file
in its existing per-file and aggregate coverage checks, strictly above 95%, with
no skipped selected tests. The typed-wrapper gate includes the native comparison
and existing two-architecture Clang/link checks. Existing native images, foreign
imports, race, fuzz, lint and six-target build gates remain required.
