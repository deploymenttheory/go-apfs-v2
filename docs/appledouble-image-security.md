# Security capture from filesystem images

`apfs.Volume.Security` and `hfsplus.Volume.Security` read a file's ownership,
mode, UUIDs and ACL from an image into a `hostdata.SecurityCopySource`. Use them
when copying security from APFS, HFS+ or HFSX without mounting the image or
consulting the machine's account database. Both APIs are pure Go and run on
Linux, macOS and Windows.

```go
snapshot, err := volume.Security("Applications/Example.app")
if err != nil {
    return err
}
result, err := hostdata.CopySecurity(snapshot.Source, options, destination)
```

`destination` implements the existing `SecurityCopyBackend`. Capture does not
supply that backend, authorize a write, or translate a Mac ACL to Windows or
Linux permissions. Inspect `result.Failures` as well as the returned error;
completion of the copy sequence does not guarantee preservation.

## What is captured

Names use `io/fs` paths: `.` means the volume root; absolute paths and `..` are
invalid. Symbolic links are captured themselves, without following the target.
Hard links use their resolved inode's metadata. The caller must keep the image
immutable while it is being read. These readers' lazy caches are not a promise
of concurrent access safety.

Numeric UID, GID and the full Darwin file mode are always present on successful
capture. Stored `com.apple.system.Security` is interpreted like XNU's VFS
fallback and Libc's `lstatx_np` property view. The result owns its storage.
Changing it cannot change the image or a subsequent capture.

| `Disposition` | Stored record | Returned ACL/UUID properties |
| --- | --- | --- |
| `SecurityRecordAbsent` | No security attribute | Absent |
| `SecurityRecordInvalid` | Invalid extent, magic, count or truncated ACL | Absent |
| `SecurityRecordEmpty` | Valid NOACL or zero-entry ACL | Absent, including UUIDs and global ACL flags |
| `SecurityRecordACL` | Valid nonempty ACL | UUIDs, global flags and declared entries retained |

XNU accepts only a 44-byte header plus up to 128 whole 24-byte entry slots.
Aligned surplus slots beyond the declared count are accepted but omitted from
captured properties. Libc imports security properties only when the returned
filesec has room for an entry; a zero-entry record's UUIDs therefore do not
appear in this view. Unknown flag/right bits in valid records remain intact.

Only the security value is fetched, with an allocation bound of 3,116 bytes.
Unrelated resource forks and attribute streams are not read. Existing image
parsers still read their metadata indexes and cache inline attributes; this is
not a total memory bound for opening an image. Lookup, metadata-index and value
I/O errors remain errors, wrapped in `fs.PathError` with operation `security`.
Malformed bytes that native capture ignores are distinguished from missing
storage, rather than turning either into an image-read failure. `Xattrs` remains
the API for raw stored bytes.

## Qualification

The native harness creates four deterministic images using the Go writers:
APFS, case-sensitive APFS, HFSX and case-insensitive HFS+. It mounts each read-only
with ownership enabled. Each of 1,444 entries is compared against both public
`lstatx_np` and the complete unchanged `statx1`/`lstatx_syscall` functions from
pinned Apple Libc. It compares numeric properties, UUIDs, ACL bytes and inode
identity, checks file/link payloads, and verifies image SHA-256 is unchanged
across mounting. Actor IDs are the only identity substitution when replaying
observations on a different Mac; fresh images retain their own audited hashes.

The matrix covers 24 stored-record profiles, three ownership pairs, files,
directories, symlinks and pairs of hard-link names, plus each root. Profiles
include absence, empty storage, NOACL, empty ACLs, unknown bits, 127/128 entries,
aligned padding, invalid magic/count/extent, and an oversized streamed record.
APFS and HFS roots retain the supplied metadata; the APFS root writer is
separately [qualified across root layouts](appledouble-root-metadata.md).
Valid fork-backed/extent-backed records and failing reads are also
covered by portable unit fixtures.

All three OS CI jobs regenerate and read the same four image variants, comparing
every entry to the committed native corpus. A separate gate requires **over 95%
in each of the three new production files**, with no focused test skips. The
coverage report combines instrumented blocks across packages before counting
statements and retains source hashes. `FuzzImageSecurity` checks arbitrary bytes
for deterministic, bounded, non-mutating decoding and valid request preparation.

```sh
go run scripts/verify-image-security-coverage.go
# An ordinary macOS user; native tools are test-only:
go run scripts/verify-image-security.go
```

Native evidence in `artifacts/image-security/` includes commands, generated
images, full source files, unchanged extracted functions/tables, both arm64 and
x86_64 Clang ASTs, observations and a pass/fail report. `-capture` produces an
unapproved observation set; it still requires Go/native agreement and never
reports qualification success. Native corpus helper hashes normalize checkout
CRLF to LF for Windows.

Pinned sources:

- [Libc statx](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/sys/statx_np.c): `5a05eabc7d870f2c1a98c4e3b828d020e4a51e4b60c6887d955422add747730d`.
- [XNU VFS security reads](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/kpi_vfs.c): `26cd0285298c7eafe9ff86387d9fe273f5cbdf965f850458357eba4328303e53`.
- [HFS Unicode comparison](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/UnicodeWrappers.c): `7300de813b94d41d14faf9aa2a0ddf436010bb43d258f81fc92ab841bc7157f2`.
- [HFS comparison data](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/UCStringCompareData.h): `88773669ce79ebe2d6bcc84d3341c3c2586e649984ac97453adb1b8706440464`.
- [HFS private hard-link directory lookup](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/hfs_link.c): `1238abcd80ada12e254a8d0e45dd82d990693f3dea047ecd7c7345c7a1410078`.

## Related fixes and limits

Qualification found that case-insensitive HFS+ sorted the four-NUL private
hard-link directory before ordinary names. Apple's comparison maps NUL to FFFF,
placing it after them. Native lookup consequently missed the directory and
returned link placeholders, losing content and security. The corrected fold
entry and its generator now preserve that ordering; unchanged Apple
`FastUnicodeCompare` and its tables are compiled into the native helper too.
This intentionally changes catalog ordering/image bytes for affected HFS+ trees.
HFSX binary ordering and APFS output do not change.

HFS attribute-index errors now discard the incomplete cache so a later capture
cannot silently treat a failed read as absent metadata. Tests cover repeated
failures, partial index population and recovery.

This completes image-based source acquisition for the qualified cases, not the
ACL application or filesystem-transport roadmap gate. Live host capture,
production write/authorization adapters, privileged/sandbox contexts, full
restoration ordering, identity resolution and
end-to-end AppleDouble extraction/repacking remain separate work. Consumers
must not infer native authorization or byte-for-byte preservation from this
statx-compatible projection.
