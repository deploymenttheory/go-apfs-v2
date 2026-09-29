# Copyfile-compatible extended chmod requests

`ACLMetadata.DarwinChmodRequest` prepares the argument data for the extended
chmod call used by Apple's `fchmodx_np`. Use it when a restoration adapter needs
to apply the metadata selected by `RestoreACL` through that native operation,
or preserve the request for replay. The builder is pure Go and identical on
Linux, macOS and Windows; it neither calls macOS nor authorizes a write.

This addresses the request-transport choice behind the measured
[attribute-list differences](appledouble-acl-attributes.md). `fsetattrlist` can
accept an empty ACL replacement on an immutable/append-only destination where
copyfile returns `EPERM`; it can also clear an empty ACL's `no_inherit` flag.
The correct extended chmod request, consumed by the native extended chmod
operation, matches copyfile's refusal and leaves the flags intact in every
qualified case. The attribute API itself still differs and is not interchangeable.

## Request contract

`DarwinChmodRequest` holds separate `UID`, `GID`, `Mode` and `Security` arguments;
it is **not a packed syscall struct**. An adapter must pass them through a
supported libSystem wrapper while retaining the destination's identity.

- Numeric UID/GID values are retained. Zero is a value; `0xffffffff` keeps its
  Darwin no-change sentinel meaning when the request is applied.
- Mode narrows to Darwin's 16-bit `mode_t`, as `FILESEC_MODE` does before the C
  wrapper promotes it to an integer. This differs from the attribute wire
  profile's 32-bit field. The native operation decides which mode bits apply.
- Security is a complete little-endian `kauth_filesec` with the owner/group UUIDs
  embedded. Unlike `EXTENDED_SECURITY` attribute writes, this is the extended
  chmod ownership transport. Its bytes own their storage.
- A nil ACL is a `NOACL` record; a present empty ACL remains distinct. Unknown
  flags/rights and opaque `NOACL` flag bytes are retained. Security must be
  non-nil, contain no opaque trailing bytes and satisfy the 128-entry limit.
  Invalid input returns a zero request and `appledouble.ErrFileSecurity`.

The builder represents complete captured metadata. It does not represent absent
filesec properties, null security pointers or the special pointer-valued
`_FILESEC_REMOVE_ACL` argument. These cannot be inferred from a nil ACL. It does
not clear source caches, open paths, issue a syscall, reinterpret native errors
or turn a Darwin ACL into Linux/Windows permissions. `RestoreACL` owns the
write/retry protocol; the backend still owns transport and actual errors.

A separate preflight `chmod` followed by an attribute write is not introduced:
the extra write could change metadata before a later failure. Tests submit the
prepared request directly to the extended chmod operation.

## Source and native qualification

The test oracle pins Apple's
[Libc chmod wrapper](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/sys/chmodx_np.c)
(SHA-256 `31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff`)
and retains its complete, unchanged `chmodx1` function. Real `filesec_*` property
operations feed it, and its callback captures the resulting arguments. The
helper checks the SDK mode width and emits arm64/x86_64 Clang ASTs.

The corresponding pinned
[XNU chmod path](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c)
(SHA-256 `b30d68fb85f34b864b5e71e3127541c2674e0fb52e59d6ee072c8b0ecbb46a4f`)
is retained as source evidence. `chmod_vnode` calls `vnode_authorize` even when
`vnode_authattr` reports no required action; the attribute-list path conditionally
omits that call. The test-only C helper invokes libSystem's `__fchmod_extended`,
the same operation used by `fchmodx_np`. Production Go does not import this symbol,
use deprecated syscall numbers, link C code or start a helper process.

The required corpus has:

- **84 Libc argument captures:** zero/nonzero UUIDs, zero/high numeric values,
  mode narrowing, `NOACL`, empty and 1/2/127/128-entry ACLs, unknown ACL bits and
  opaque `NOACL` flag bytes. Go request arguments must match the independent
  C construction exactly.
- **192 real APFS pairs:** unchanged copyfile ACL application versus Go-prepared
  requests consumed directly by extended chmod. Files/directories, absent/empty/
  1/128-entry starting ACLs, modes `0000`/`06755`, ordinary/immutable/append-only
  flags, and absent/malformed/empty/nonempty replacements are included. There
  are 96 no-ops, 32 accepted writes and 64 `EPERM` refusals. All before/after
  attribute bytes, errors, ownership, modes, flags and held-object identities
  match copyfile. All 16 error differences and eight flag differences from the
  attribute-write corpus are accounted for explicitly.

The helper requires the destination to be APFS and records actual failures,
without injected errno or a permission-changing preflight. Raw `fgetattrlist`
responses verify empty-ACL flags that the narrower `fstatx_np` view omits.
The preceding security, restoration and attribute matrices remain required.

Run `CGO_ENABLED=0 go run scripts/verify-appledouble-filesec.go` on macOS. Its
`-capture` mode records unapproved observations. The normal run requires
`testdata/appledouble/native/acl-chmod.json.gz` and compares it with the live
observations, adjusting only host-specific numeric account IDs. Source/helper
hashes, full pinned sources, ASTs, raw requests/responses and host/revision data
are retained in `artifacts/appledouble-filesec`, including `observed-chmod.json`.

All three OS jobs replay the required corpus with no skips. The focused hostmeta
coverage gate now requires greater than 95% independently in `acl_restore.go`,
`acl_attributes.go` and `acl_chmod.go`. Unit tests also check invalid inputs and
storage ownership; `FuzzDarwinChmodRequest` checks mode narrowing, unchanged
security bytes, bounded output and independent request storage. This does not
claim whole-hostmeta coverage or native Darwin syscalls on Windows/Linux.

## What remains

The request-level compatibility gap is resolved for the qualified owner-operated
APFS cases. A production adapter still needs a supported pure-Go libSystem call
boundary, stable destination capture and real error propagation.
[Controlled owner/non-owner contexts](appledouble-acl-nonowner.md) are qualified
on SDK-written APFS/HFSX images. Privileged/sandbox contexts, live source identity
acquisition and full restoration ordering remain unqualified. Shared carriers must preserve foreign metadata on every supported
OS. Quarantine, large-value/allocation behavior and APFS/HFS+ roundtrip gates
also remain; see the [roadmap](../pkg/appledouble/README.md#roadmap).

Package PR #72 stays draft and codesign remains paused until the completed
integration is qualified and APFS is released.
