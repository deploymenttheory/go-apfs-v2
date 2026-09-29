# Optional properties in extended chmod requests

`hostmeta.DarwinChmodProperties.ChmodArguments` prepares libSystem-compatible
extended chmod arguments when individual filesec properties may be absent. Use
it for ordinary ACL-copy adapters, explicit ACL removal and other operations
that must distinguish omission from a supplied zero value. It complements
`ACLMetadata.DarwinChmodRequest`, which supplies complete captured metadata.
Both builders run in pure Go on Linux, macOS and Windows.

## What the request represents

| Property | Omitted | Explicitly present |
| --- | --- | --- |
| UID/GID | `0xffffff9b` (-101), Darwin `KAUTH_UID_NONE` / `KAUTH_GID_NONE` | Exact supplied 32-bit value |
| Mode | Integer `-1` | Narrowed to 16 bits, then promoted to a nonnegative integer |
| Owner/group UUID | Not present; the corresponding output record slot is zeroed | Exact UUID, including all zeroes |
| Raw security | No raw record supplied | A complete record, including a present `NOACL` record |
| ACL removal | Not requested | Explicit removal property; cannot coexist with raw security |

**`0xffffffff` is not omitted ownership.** Native tests refuse those explicit
UID/GID values with `EPERM` while omitted ownership succeeds in the same mutable
contexts. Earlier documentation describing `0xffffffff` as the extended-chmod
no-change sentinel was incorrect. The existing complete-metadata builder already
preserved the value literally and is unchanged in behavior.

`DarwinChmodArguments.SecurityArgument` distinguishes:

- `DarwinSecurityNone`: null security pointer; `Security` is nil.
- `DarwinSecurityRecord`: a pointer to the owned `Security` bytes.
- `DarwinSecurityRemove`: `_FILESEC_REMOVE_ACL`; `Security` is nil.

These are argument kinds, not interchangeable metadata states. If either UUID
property is present, libSystem sends a record even when no ACL was supplied or
removal was requested. The raw record's embedded UUIDs are overwritten by the
separate UUID properties, or zeroed when absent. Explicit zero UUID properties
therefore differ from omitted properties.

A `NOACL` record is also distinct from a null argument. In the qualified APFS
cases, a null argument preserves the existing ACL; a `NOACL` record or removal
sentinel can remove it. Supplying just a zero UUID property can therefore produce
a record that clears an existing ACL. Preserve the native argument distinctions
instead of interpreting `NOACL` as a universal instruction to leave the ACL alone.

## API contract

Pointers in `DarwinChmodProperties` encode presence. Zero-valued properties are
real values, not omission. `RawSecurity` supplies `FILESEC_ACL_RAW` data; it keeps
unknown ACL bits and opaque `NOACL` flag bytes, but opaque trailing bytes are
rejected. Invalid records or simultaneous raw security and removal return a zero
argument result and an error matching `appledouble.ErrFileSecurity`.

The builder does not modify or retain its inputs. Every returned record owns its
storage. It does not store a native pointer, issue a syscall, open a file or
resolve identities. Capture adapters must propagate failed property reads; an
error must not become an omitted property. Call adapters must translate the
three security kinds through a supported native boundary, preserve signed mode
and the ownership sentinels, and propagate real write errors.

## Source and native qualification

The harness uses the complete unchanged `chmodx1` function from pinned Apple
[Libc](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/sys/chmodx_np.c),
SHA-256 `31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff`.
It independently populates real `filesec_*` properties and captures the resulting
call arguments. The pinned [XNU header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/kauth.h)
(SHA-256 `9009cb706a24501dff4f47024c63dc730618249d85dd050f2bf97515a3ca6098`)
and SDK static assertions verify the ownership sentinels. The previously pinned
XNU extended-chmod implementation remains retained as source evidence.

- **896 argument captures:** all 32 presence masks for numeric and UUID
  properties, four value profiles, and seven security states. The profiles cover
  zero, ordinary, high-width and sentinel values; absent/removal, ordinary and
  opaque `NOACL`, empty, one-entry and 128-entry records. Results include 32 null
  arguments, 32 removal sentinels and 832 records. Input fixtures store binary
  security bytes so unknown bits are not lost through ACL text serialization.
- **1,260 real write pairs:** public `fchmodx_np` versus Go-prepared arguments
  consumed by libSystem's extended chmod operation. APFS files/directories,
  absent/empty/one-entry initial ACLs, ordinary/immutable/append-only flags and
  ten property profiles cover actual application. There are 446 accepted writes
  and 814 `EPERM` refusals. All 126 explicit `0xffffffff` ownership cases are
  refused. The held identity, file contents and BSD flags remain intact; both
  paths must agree on the exact before/after security and attribute observations,
  numeric metadata, return code and errno. Refused writes retain the original
  metadata; omitted modes remain unchanged.

Run `CGO_ENABLED=0 go run scripts/verify-appledouble-filesec.go` on a Mac.
`-capture` records unapproved observations. Normal qualification requires
`acl-chmod-properties.json.gz` and compares it with fresh observations,
normalizing only host account IDs. The artifacts retain raw property inputs,
argument bytes, protocol transcripts, full pinned sources, unchanged extracted
functions, arm64/x86_64 Clang ASTs and host/revision identity. All earlier
security, copy, restoration and owner/non-owner matrices remain required.

Required corpus replay, validation/storage tests and `FuzzDarwinChmodProperties`
run on all three OSes. Focused coverage is independently enforced above 95% for
the new property builder and each existing ACL/HFS implementation file. The
separate AppleDouble codec gate remains above 95%.

## Remaining work

This completes the represented optional-property argument forms, not a production
native or carrier backend. Live capture and identity acquisition, supported call
adapters, ordinary-copy fallback handling, privileged/sandbox contexts and full
metadata ordering still need integration. The [five roadmap gates](../pkg/appledouble/README.md#roadmap)
remain open. Package PR #72 stays draft; codesign stays paused until completed
APFS qualification, release and downstream adoption.
