# Executing an AppleDouble ACL replacement

`hostmeta.RestoreACL` executes the deferred update returned by
`appledouble.File.ACLUpdate`. Use it after restoring other metadata, with an
explicit backend bound to the destination and the copy operation's cached source
security. The algorithm is pure Go and identical on Linux, macOS and Windows.
It does not open paths or select an OS-specific fallback.

The routine freezes the selected ACL, captures destination security once, and
writes a replacement retaining owner/group UUIDs, numeric UID/GID and mode.
Absent or ignored malformed updates perform no callbacks. A present empty ACL
is a real write requesting removal of entries. Zero numeric ownership and mode
are retained as values, not treated as omitted fields.

## Backend contract

`ACLRestoreBackend` has three operations:

1. `CaptureACL` returns `ACLMetadata`: current `FileSecurity`, numeric UID/GID,
   and raw Darwin `st_mode` bits. Capture failure is an error, never an empty ACL.
2. `WriteACL` applies the supplied request without changing BSD flags. Each call
   owns its request, so retaining or mutating it cannot corrupt a retry. The
   backend must preserve object identity and propagate actual filesystem errors.
   Unsupported writes wrap both `errors.ErrUnsupported` and the native cause.
   Permission and I/O errors must not be classified as unsupported.
3. `ClearSourceSecurity` discards the cached source ACL, owner-UUID and group-UUID
   properties, attempting all three even if a property removal fails. It must
   leave numeric source metadata and the destination untouched.

The backend is a transport boundary, not a built-in native filesystem or carrier
implementation. Caller adapters must hold the destination stable and exclude
concurrent metadata changes. Darwin requests cannot be applied to a Windows or
Linux native ACL by pretending their permission models are interchangeable;
shared transport still needs explicit preservation carriers for foreign metadata.

## Errors and retry behavior

Only the first unsupported write triggers a retry. The routine clears cached
**source** security and writes the **same destination request** once more. It
never recaptures metadata, clears the destination ACL, removes restrictive flags,
or loops indefinitely. The second write's failure is returned. A source-cache
reset failure stops before retry and retains both the reset and preceding write
errors through `errors.Is`.

`ACLRestoreResult` accompanies errors as well as success. `Attempts` counts actual
write callbacks; `Retried` means a second write was attempted; `Applied` is true
only after a successful write. Error messages identify capture, write attempt or
source-cache reset. Earlier side effects, including a completed source reset,
are not rolled back. A backend write failure may leave partial changes; the
routine provides no transaction or automatic rollback.

## Evidence

The existing [security-record oracle](appledouble-filesec.md) also compiles
`testdata/appledouble/native/acl-restore.c`. It reuses the existing native helpers
and complete, unchanged hash-pinned Apple functions. Tracing wrappers record
real `fstatx_np`, `fchmodx_np` and `filesec_set_property` calls. Clang ASTs retain
both arm64 and x86_64 expansions; no injected filesystem error is used in the
native corpus.

The 248 native/Go pairs comprise:

- **240 APFS cases:** regular files/directories, six actual mode settings, five
  BSD flag settings and four ACL inputs. There are 120 no-ops, 72 successful
  writes and 48 immutable/append-only `EPERM` refusals without retries.
- **8 FAT cases:** regular files/directories and the same four ACL inputs. Four
  are no-ops. Four valid replacements, including empty ACLs, return real
  `ENOTSUP` twice, reset all three source properties once and preserve the
  destination. The two request records are byte-for-byte equal.

A disposable FAT image is created, mounted and detached by the oracle. The C
helper requires `fstatfs` to report `msdos` for FAT and `apfs` for APFS, so a failed
mount cannot accidentally count a host-directory test as FAT evidence. APFS
fixture setup checks actual mode and flags, including set-GID. File identity,
security, numeric ownership, mode and flags are checked before/after; cached
source numeric metadata must also survive the reset.

Run `CGO_ENABLED=0 go run scripts/verify-appledouble-filesec.go` on macOS for live
qualification. `-capture` records observations without approving a fixture.
`artifacts/appledouble-filesec` contains raw protocol transcripts, source/helper
hashes, source files, ASTs, host/tool/revision information and the disk image.
`observed-restoration.json` records the new cases independently of the preceding
security conversion and application matrices.

All three OS jobs replay the required archived corpus and enforce greater than
95% statement coverage independently of `pkg/hostmeta/acl_restore.go`,
`pkg/hostmeta/acl_attributes.go` and `pkg/hostmeta/acl_chmod.go` using
`scripts/verify-acl-restore.go`. This is a focused restoration coverage gate, not
a claim of whole-package `hostmeta` coverage. The existing independent AppleDouble
coverage gate remains. Unit tests additionally cover capture failure, reset
failure, retry success, changed second-write errors, invalid inputs and callback
mutation. Those failure-injection tests are not represented as measured native
filesystem outcomes. Fuzzing checks bounded retries, immutable request contents
and retention of destination metadata and error causes.

## Remaining work

The [attribute-record codec](appledouble-acl-attributes.md) provides portable
Darwin request bytes. Native attribute calls differ from copyfile on empty ACL
flags and restrictive-flag failures, so they are not a qualified replacement
backend yet. The [extended chmod request builder](appledouble-acl-chmod.md)
qualifies the correct operation for the measured cases; its production call
boundary remains to be implemented.

This implements the deferred ACL write protocol, not the entire copyfile
lifecycle. Shared native/carrier adapters, live source identity acquisition,
non-owner authorization contexts and full restoration ordering remain. Quarantine
integration, size/allocation policy and APFS/HFS+ extraction/repacking must also
pass the [migration gates](appledouble-migration.md) before release, package PR
#72 readiness or resumed codesign implementation.

The source oracle is Apple's
[copyfile implementation](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c)
at SHA-256 `19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`.
