# Held metadata providers

AppleDouble restoration needs a destination that stays bound to the same file
while attributes, ACLs and timestamps change. A pathname can be replaced between
these operations. `OpenMetadataFile` resolves a name inside an `os.Root`, opens
the final entry without following it, and compares the held identity with the
original no-follow observation. The caller closes the returned file.

`NewHeldMetadata` supplies Darwin implementations of the existing security,
deferred ACL and stat protocols. Each operation uses `SyscallConn.Control`, so a
concurrent close cannot redirect a syscall onto a recycled descriptor. Neither
renaming the file nor replacing its original name redirects metadata writes.

The native boundary contains filesystem primitives and property acquisition:

- `fstatx_np` and filesec property reads preserve independent property presence.
  Only `ENOENT` means an omitted property. Failed acquisition preserves the
  original error; only the existing EPERM/ENOTSUP source rules allow fallback.
- `__fchmod_extended` preserves omitted owner/mode values, complete security
  records, and the distinct ACL removal pointer. It does not substitute an
  attribute-list write with different authorization semantics.
- `fsetattrlist` submits modification and access timestamps with nanoseconds.
- `ffsctl(FSIOC_CAS_BSDFLAGS)` reports actual observed flags; `EAGAIN` retains its
  native cause alongside the retry classification.

The libSystem calls load through pure Go bindings. Production does not invoke
Clang, copyfile, shell commands, or a native AppleDouble algorithm. `SourceCache`
is explicit operation state; deferred ACL fallback clears that cache rather than
changing source storage.

## Linux and Windows

`LogicalMetadata` implements the same security and stat protocols on every OS.
It owns an exact Darwin metadata state, including independently omitted filesec
properties. `Snapshot` returns independent storage for an image or carrier.
It preserves foreign metadata; it does not claim local enforcement of Darwin
principals or simulate host authorization failures.

The native Darwin constructor returns `errors.ErrUnsupported` on other hosts.
This is a host binding distinction: the logical provider and carrier retain the
complete values on Linux and Windows.

`OpenMetadataFile` is implemented for all three hosts. Darwin opens the final
entry with `O_SYMLINK` relative to a held parent. Combining that flag with
`O_NOFOLLOW` is incorrect: it makes Go's root resolver follow the link after
`ELOOP`. Linux uses `O_PATH` for a symlink; a native operation may reject such a
descriptor, and that refusal must remain visible alongside the carrier value.
Windows uses `NtCreateFile` with `FILE_OPEN_REPARSE_POINT`, relative to a held
parent, requesting metadata access without content writes. These are the
[documented Windows relative-handle and reparse-point semantics](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).

## Qualification

`go run scripts/verify-held-metadata.go` runs the portable logical and native
provider tests without skips and requires more than 95% statement coverage for
every selected production file. It retains test events, coverage, revision and
source hashes in `artifacts/held-metadata`.

On macOS, `go run scripts/verify-held-metadata-native.go` retains both arm64 and
x86_64 SDK ASTs. C static assertions check the stat, timespec, attrlist and BSD
flag CAS layouts. An independent C reader compares all stat timestamps, flags,
numeric ownership, mode, each filesec property and complete ACL bytes against
Go readback. The 16 cases cover regular files, directories, symlinks and dangling
symlinks before and after timestamp, permission and nonempty ACL writes. The
captured corpus in `testdata/appledouble/native/held-metadata.json.gz` replays as
logical metadata on all three operating systems. Runtime evidence identifies
the actual host, kernel, SDK and compiler; ASTs alone do not establish execution
on the other architecture.

These providers are building blocks. They do not yet claim the complete path
creation, inherited permissions, temporary access, content-protection or
cleanup lifecycle of `copyfile`. Descriptor-based `fcopyfile` has a different
outer sequence and must be qualified separately. A successful component write
also does not establish that a later stage preserved its result; callers must
retain errors and recapture final metadata.
