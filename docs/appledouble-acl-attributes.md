# Darwin ACL attribute records

`hostmeta.ParseDarwinACLAttributes` and
`ACLMetadata.MarshalDarwinACLAttributes` decode and encode the attribute-list
representation of ACLs, numeric ownership, mode and ownership UUIDs. They are
pure Go, with the same implementation on Linux, macOS and Windows. Use them to
inspect captured Darwin metadata or construct an explicitly selected Darwin
attribute request. They perform no filesystem access or permission evaluation.

The separate ownership fields matter: Darwin ignores owner/group UUID slots
inside the `EXTENDED_SECURITY` blob. Passing a full security blob alone does not
restore those identities. The decoder takes UUIDs from the outer attribute fields;
the encoder writes them there and zeros the ignored embedded slots without
mutating its input.

## Exact profile and layout

Use `DarwinACLCommonAttributes` (`0x01c38000`) as the common mask, with all other
attribute masks and options zero. This selects `OWNERID`, `GRPID`, `ACCESSMASK`,
`EXTENDED_SECURITY`, `UUID` and `GRPUUID`. Adding `RETURNED_ATTRS`, requesting
`PACK_INVAL_ATTRS`, or changing the profile changes the layout and is outside this
API's contract. The bytes do not identify which mask the caller requested.

| Field | Get response offset | Set request offset |
| --- | --- | --- |
| Total response length, uint32 | 0 | Absent |
| UID, GID, raw Darwin mode, three uint32s | 4 | 0 |
| Security reference: signed relative offset, uint32 length | 16 | 12 |
| Owner UUID, 16 bytes | 24 | 20 |
| Group UUID, 16 bytes | 40 | 36 |
| Security blob in canonical layout | 56 | 52 |

Integers are little-endian on every Go host. The reference offset is relative to
its own first byte; the canonical value is 40. The maximum get buffer is
`DarwinACLAttributeBufferSize` (3,172 bytes), including 128 ACL entries. A native
read must succeed before decoding its buffer. Failure cannot mean absence.

The parser rejects truncated frames, negative or overlapping references,
out-of-frame extents, oversized blobs, invalid security headers/counts and bytes
trailing inside the security record. Safe gaps and unused buffer capacity are
allowed; only the declared, bounded reference is decoded. Results own their
storage. Numeric zero values, unknown ACL flags/rights, and UUID bytes survive.
A zero-length reference means no ACL. A `NOACL` blob and its opaque flag bytes
are retained; a present empty ACL remains distinct. The encoder requires non-nil
security and an exact security extent without opaque trailing bytes.

## Native API differences that callers must retain

The attribute API cannot currently be substituted for copyfile's
`fstatx_np`/`fchmodx_np` path in `RestoreACL` while claiming identical behavior:

- `fgetattrlist` returns a present empty ACL where `fstatx_np` reports `NOACL`.
  It also retains `no_inherit` on an empty ACL that `fstatx_np` hides. The codec
  preserves the complete attribute response; it does not collapse these states.
- In 16 qualified immutable/append-only cases, an empty replacement through
  `fsetattrlist` succeeds while copyfile returns `EPERM`. In eight of those cases,
  the attribute call actually clears the empty ACL's `no_inherit` flag; copyfile
  refuses the write and leaves it set. These are both error and metadata
  differences, not merely two encodings of the same result.

Raw before/after responses and the independent copyfile results are archived.
Tests compare the shared stat view separately, permitting only the observed
empty-ACL omissions there. Full attribute comparisons retain every flag and byte.
No production adapter, preflight permission approximation, error rewriting or
restrictive-flag removal is introduced by this codec.

## Native and portable qualification

The oracle uses Apple's pinned
[XNU attribute packing implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_attrlist.c),
SHA-256 `3fcbca58e2d63963115ecd4aa1e27c3d1f7dc21f124897c8bdfdf9916b503c06`.
It extracts the complete, unchanged `_attrlist_buf`, `attrlist_pack_fixed`,
`attrlist_pack_variable2` and `attrlist_pack_variable` definitions. The retained
full source also documents the separate UUID fields and ignored blob ownership.
Clang compiles the helper and emits arm64 and x86_64 ASTs. C and SDK code are
research/test dependencies only.

`go run scripts/verify-appledouble-filesec.go` runs:

- **84 packing cases**, using the extracted C functions: absent, `NOACL`, empty,
  1/2/127/128 entries; three ownership/ID/mode patterns; four global flag patterns.
  Go reads the C responses and produces byte-identical C set requests. For an
  absent reference there is no flag payload; the C expected state explicitly
  zeros that otherwise unrepresented field.
- **192 APFS scenarios**, each executed on three separate held destinations:
  independent C attribute requests, Go attribute requests, and the unchanged
  copyfile ACL stage. Files/directories, absent/empty/1/128-entry initial ACLs,
  modes `0000`/`06755`, ordinary/immutable/append-only flags and four updates are
  covered. The helper requires `fstatfs` to report APFS. Real outcomes are 96
  no-ops, 48 accepted attribute writes and 48 `EPERM` refusals. C and Go attribute
  paths agree on every outcome and raw response. The 16 copyfile differences
  above remain explicit controls, not attribute parity successes.

Ownership, mode, BSD flags and held-object identity are checked. Failure must
preserve the complete before-state, including empty-ACL flags. The existing
72 security conversions, 240 application pairs and 248 restoration pairs also
remain required. No filesystem failures are injected into native evidence.

`-capture` records unapproved observations. Normal qualification compares the
required `testdata/appledouble/native/acl-attributes.json.gz` fixture, normalizing
only host-specific numeric UID/GID fields. Helper/source hashes, raw requests,
responses, command transcripts, host/tool/revision data and ASTs are retained
under `artifacts/appledouble-filesec`.

All three OS jobs replay this fixture without skips. Unit tests additionally cover
all truncations of a representative frame, reference/length overflow, ownership
precedence, invalid exports, storage ownership and safe gaps. `FuzzACLAttributes`
checks bounded canonical roundtrips. `scripts/verify-acl-restore.go` requires
**greater than 95% coverage independently for both** `acl_restore.go` and
`acl_attributes.go`, retaining per-file coverage, test transcripts and source
hashes. This is not a whole-package coverage claim.

## Outstanding integration

The [extended chmod request builder](appledouble-acl-chmod.md), consumed by the
correct native operation, resolves the measured owner-operated APFS differences.
A production native backend must still integrate that call path, use supported
system-call wrappers, and preserve held object identity. Foreign-host carriers must retain the same metadata without
pretending Linux or Windows permissions implement Darwin authorization. Live
identity acquisition, privileged/sandbox contexts and full metadata ordering still need
qualification. Quarantine, size/allocation policy, shared carriers and APFS/HFS+
roundtrip gates remain in the [migration plan](appledouble-migration.md).
Package PR #72 stays draft and codesign remains paused until those gates and the
qualified APFS release are complete.

[Controlled owner/non-owner tests](appledouble-acl-nonowner.md) qualify ordinary-user
APFS/HFSX authorization through the matching extended chmod operation.
