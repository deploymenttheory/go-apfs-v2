# Rooted file content reads

`hostdata.OpenContentFileRead(root, name)` opens a regular file for reading its
data beneath an `os.Root`. Use it when content selection must remain independent
of permission to query the file's ACL or extended attributes. For example,
bundle discovery can read a platform-specific plist despite a denied EA read;
a content read denial must still reach the caller for its fallback decision.

```go
file, err := hostdata.OpenContentFileRead(root, "Contents/Info-macos.plist")
if err != nil {
    return err
}
defer file.Close()
// Read with an application-specific size bound. file.Stat() identifies the
// held file; bind any later mutation to that identity.
```

The operation is implemented on Linux, macOS and Windows. It does not invoke
native executables, read AppleDouble neighbors, simulate foreign ACLs or change
permissions. Host authorization remains in force. It does not replace
`StatMetadata` for content-free discovery or metadata openers for EA operations.

## Containment and lifetime

Names must be local to the supplied root. Intermediate links may resolve within
the root; escaping links fail. Final links/reparse points are never followed.
Directories and other non-regular objects return `ErrContentType`. Unix FIFO
opens are nonblocking, so rejecting a FIFO does not wait for a writer. Nil or
closed roots, missing files and actual content-read denials fail. Native causes
remain wrapped in the returned errors.

The returned descriptor belongs to the caller and permits reading, not writing.
Validation uses its held identity without a preliminary pathname stat. Failed
validation closes the descriptor. The call does not freeze file bytes, provide a
read-size limit, preserve access time, or make subsequent pathname operations
atomic. Consumers must bound reads and exclude or detect concurrent changes.

## Access rights

On Darwin and Linux, typed `x/sys/unix.Openat` opens the leaf beneath an already
held parent with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`.
On Windows, the existing typed NT opener requests only `SYNCHRONIZE`,
`FILE_READ_DATA` and `FILE_READ_ATTRIBUTES`. In particular it requests neither
`READ_CONTROL` nor `FILE_READ_EA`. Parent-directory acquisition still needs the
host permissions required by `os.Root`; this is not a permission bypass.

Darwin's held `fstat` succeeds under the captured `readattr` denial, whereas a
Windows request for `FILE_READ_ATTRIBUTES` is subject to the Windows DACL.
These host rules are distinct from an application's macOS policy. Consumers
must decide separately when discovery itself requires pathname metadata access.

## Qualification

`go run scripts/verify-held-metadata.go` includes these operations in the
existing Linux/macOS/Windows gate. Every tracked implementation file must exceed
95% coverage, no test may skip, and the existing minimum test count remains.
Content tests cover real data denial, contained/escaping/final links, missing
objects, invalid arguments, descriptor cleanup, identity and write rejection.
Windows tests additionally deny ACL reads, EA reads and each unrelated write
right; a native open requesting that right must fail before content success is
accepted. The ACL-read test uses OWNER RIGHTS to prevent the owner's implicit
READ_CONTROL grant from invalidating the fixture, and restores the original DACL
through a pre-acquired handle. See Microsoft's [security identifier reference](https://learn.microsoft.com/en-nz/windows-server/identity/ad-ds/manage/understand-security-identifiers).

The retained [native corpus](../testdata/appledouble/native/content-open.json)
contains twelve C-runtime observations, compiler/OS versions and source hashes.
`go run scripts/capture-content-open.go` captures it on macOS. Darwin tests compile
the C reference again, reproduce actual ACL and file-type cases, compare against
the retained corpus, then compare the Go result against the live C result. All
three hosts verify corpus completeness and source hashes. Existing native image,
resource-fork, race, fuzz and downstream transport gates remain required.
