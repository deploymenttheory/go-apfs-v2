# Security records and ACL replacement

`FileSecurity` preserves the owner UUID, group UUID and ACL in a Darwin
`kauth_filesec` security record. Use it when transporting filesystem security
metadata or preparing an AppleDouble ACL replacement against captured destination
security. It runs in pure Go on Linux, macOS and Windows.

`ACL.MarshalBinary` exports an ACL with zero ownership fields, matching Apple's
ACL export functions. Using that export as a complete destination security record
would lose ownership information. `ACLUpdate.FileSecurity(destination)` retains
the captured destination UUIDs while replacing the ACL. Numeric UID/GID, mode and
BSD file flags are separate metadata and must also be retained by the eventual
filesystem adapter.

## Representations and decisions

| API or field | Meaning |
| --- | --- |
| `ParseFileSecurity`, `MarshalBinary` | Big-endian disk security representation. |
| `ParseDarwinFileSecurity`, `MarshalDarwinBinary` | Little-endian arm64/x86_64 Darwin memory representation, independent of the Go host. |
| `ACL == nil` | `KAUTH_FILESEC_NOACL`; different from a present zero-entry ACL. |
| `NoACLFlags` | Four opaque bytes present with NOACL. XNU leaves these bytes unchanged during endian conversion. Must be zero with a present ACL. |
| `Trailing` | Preserved bytes beyond the declared entries; never interpreted as extra entries. |
| `ACLUpdate.FileSecurity` returning nil | Preserve destination security. No destination capture is needed for a no-op. |
| Non-nil replacement | Requires captured destination security; retains owner/group UUIDs, owns the selected ACL, discards old trailing/reserved bytes. |

The decoder rejects bad magic, truncated records and counts exceeding 128 entries.
The `0xffffffff` NOACL sentinel is accepted only by the full security decoder;
`ParseACLBinary` retains its existing ACL-only contract. Unknown ACL bits and UUID
bytes are preserved. All returned buffers and entries have independent storage.
These APIs do not reinterpret raw AppleDouble attributes automatically.

## Native qualification

Run `CGO_ENABLED=0 go run scripts/verify-appledouble-filesec.go` on macOS. The
harness compiles a test-only C adapter with Clang, retains ASTs for arm64 and
x86_64, and verifies pinned Apple source hashes before extracting complete,
unchanged `copyfile_unpack_acl`, `copyfile_unset_acl` and
`kauth_filesec_acl_setendian` functions. The local copyfile state scaffold is not
Apple's private ABI. The application comparison executes the extracted ACL stage
with real `fstatx_np`, `filesec_*` and `fchmodx_np` calls; it does not stand in for
the entire copyfile preparation/cleanup workflow. Existing whole-copyfile ACL
acceptance tests remain in place.

The 72 conversion cases cover NOACL, 0/1/2/127/128 entries, nonzero owner/group
UUIDs, unknown flags/rights, opaque NOACL flags and trailing bytes. Present ACL
payloads are also compared with the independent public `acl_copy_int` and
`acl_copy_ext_native` functions. C reads owner/group fields through the SDK
struct, whose size and field offsets are compile-time assertions.

The 240 application pairs cover regular files and directories, six mode choices
(including mode zero and set-ID bits), five BSD flag choices, and absent,
malformed, empty or populated ACL text. Each pair compares the Apple stage with
a Go-prepared request applied through the native test adapter. Before/after
security, numeric ownership, mode, flags and inode identity are recorded. The
reviewed observations contain 120 no-ops, 72 successful replacements and 48
`EPERM` refusals under immutable or append-only flags. Failed writes preserve the
original ACL. Fixtures use the process's effective group so set-GID setup is permitted; the
harness requires every requested mode/flag bit to be present before comparison.
Test flags are cleared during cleanup.

The checked-in native fixture is replayed without skips on all three operating
systems. Live comparisons allow the capture host's numeric UID/GID to differ;
all other recorded semantics must agree. Raw source, ASTs, input/output bytes,
requests, command transcripts, host/SDK/compiler identity and revision are retained
in the `appledouble-filesec` CI artifact. `-capture` records evidence but does not
approve the fixture or report a qualified run.

## Remaining work

This codec prepares records; it neither grants permission nor applies filesystem
metadata. Shared transport still needs source acquisition, ordered restoration,
actual write-error propagation, and metadata carriers where native storage cannot
represent a value. The [shared restoration executor](appledouble-acl-restoration.md) qualifies the
source-cache reset and bounded ENOTSUP retry with a real FAT volume. Non-owner
authorization remains outside the owner-operated matrices. Nonzero ownership UUIDs are
qualified as bytes, not as live ownership reassignment. Full copyfile lifecycle
ordering and APFS/HFS+ extraction/repacking remain separate acceptance work.

Package PR #72 stays draft and codesign stays paused until the broader
[migration gates](appledouble-migration.md) and qualified APFS release are complete.

## Sources

- [Apple copyfile application stage](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c), SHA-256 `19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`.
- [XNU security-record conversion](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_authorization.c), SHA-256 `6909f51300732fe195252b9de1ce0a2fb5d086af9072dc5746269a8ffeb2e249`.
- [Libc extended chmod](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/sys/chmodx_np.c) explains separate numeric metadata and ownership UUID properties; pinned executable evidence above defines this increment's qualification.
