# Executing ordinary security copies

`hostmeta.CopySecurity` coordinates the ordinary `copyfile_security` stage from
captured source properties and stat metadata. Use it when copying an existing
object's ACL, mode or combined security to a held destination. It runs the same
Go implementation on Linux, macOS and Windows; an explicit backend supplies
capture and write operations for the host or a foreign-metadata carrier.

This is separate from `appledouble.CopyACL`, which only selects entries, and
`hostmeta.RestoreACL`, which applies a deferred AppleDouble replacement. An
AppleDouble replacement later in the lifecycle must still replace the merged
ordinary-copy ACL.

## Sequence and property selection

| Requested stage | Operations |
| --- | --- |
| Neither ACL nor stat | No callbacks; completed no-op |
| Stat only | One chmod using captured stat mode, with applicable set-ID filtering |
| ACL only | Capture destination ACL, select entries, update source cache, omit numeric UID/GID/mode, submit extended security |
| ACL and stat | Capture destination ACL, select entries, update source cache, submit combined properties with applicable set-ID filtering |

ACL-only copies **retain owner/group UUID properties**. Apple's POSIX-clearing
helper removes numeric IDs and mode only. Omitted UUIDs and explicit zero UUIDs
remain distinct, as described in [optional chmod properties](appledouble-acl-chmod-properties.md).
Confirmed absent ACLs are nil; a failed capture is an error. A present raw NOACL source cannot be materialized as an ACL by Libc: when ACL copying is selected, it returns `appledouble.ErrFileSecurity` before destination capture, matching native EINVAL. Stat-only execution still accepts that separate raw source property. Selection retains
explicit source entries followed by inherited destination entries and discards
global ACL flags. If both ACLs are absent, the source cache remains unchanged.
A present empty selection remains present in the request.

The source's filesec properties and stat values are independent inputs. Combined
writes use the former; fallback mode and ownership use the latter, even if a
filesec property is omitted or different. Set-ID filtering removes `06000` when
stat copying is selected, always-copy is false and either forbid-copy or a
positively captured source/destination `MNT_NOSUID` condition applies. Always-copy
wins over forbid-copy. Filtering affects the working request and fallback mode,
not the returned source cache. Mode narrowing follows Darwin's 16-bit `mode_t`.

## Fallbacks and incomplete preservation

After any failed combined write, native copyfile attempts:

1. Mode, if stat copying was requested.
2. Source stat UID/GID, **including for ACL-only copies**.
3. The selected ACL, if present, including an empty ACL.

These operations continue even if an earlier fallback fails. They are not a
retry of the combined request, and are not limited to unsupported-operation
errors. Stat-only chmod errors are also historically ignored by this stage.
Neither absence of a returned stage error nor `Completed` proves preservation.

`SecurityCopyResult` makes these native semantics observable:

- `Completed` says the sequence finished. Validation, capture and ACL selection
  failures instead return an error and leave it false.
- `Fallback` identifies entry into the separate-write sequence.
- `Writes` counts attempted backend writes, including unsuccessful ones.
- `Failures` retains each failed write's operation and original error, in order.
  It includes the failed combined operation even if later operations recover.
- `Source` owns the resulting cache, including the selected ACL even when later
  writes fail. It is populated after successful input validation for a selected
  stage. A no-op returns no source snapshot. The source filesystem is not written.

Consumers requiring lossless preservation must inspect these diagnostics and
recapture the destination when needed. Do not treat historical native success
as an implicit metadata-loss success. Do not reinterpret every recorded failure
as terminal either: fallback may recover the requested state. The executor does
not roll back partial writes or infer the final filesystem state.

## Backend and storage contract

The caller captures source properties, stat metadata and volume policy before
execution. Failed reads must not become omitted properties or absent ACLs.
Every backend operation must refer to the same held target and exclude concurrent
mutation. No callback opens a path on behalf of the executor.

Inputs are validated and copied before callbacks. Each write owns its request;
callback mutation cannot change another request, the input or the returned cache.
ACL-removal properties are rejected as source metadata. Malformed/oversized raw
records and trailing bytes return errors before a callback. Selection limits use
`appledouble.ErrACLCopy`; read errors retain their original cause. Pure-Go
allocation/property assignment has no simulated libSystem setter failure.

## Native qualification

The test-only helper compiles the complete unchanged `copyfile_security`,
`copyfile_unset_posix_fsec` and volume-feature helper from pinned Apple
[copyfile](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c),
SHA-256 `19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`.
The complete unchanged [Libc chmodx1](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/sys/chmodx_np.c)
captures exact combined-write arguments, pinned at SHA-256
`31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff`.

- **2,160 controlled cases** combine six ACL input pairs, all three selected
  stages, five set-ID policies, four property-presence masks and six fault
  profiles. Call-boundary faults are explicitly simulated here; they qualify
  ordering and error handling, not host authorization. Cases include 640 fatal
  outcomes (capture/selection), 1,520 completed stages and 1,000 ignored write
  errors. Exact requests, source-cache changes and every callback are checked.
- **216 actual APFS pairs** compare the unchanged stage using real libSystem
  calls with Go-prepared operations applied through real APIs. Files/directories,
  three stages, three set-ID policies, four ACL input pairs and ordinary,
  immutable and append-only targets exercise successful and refused operations.
  These cases inject no errors. All stages complete, but 120 cases contain a
  total of 216 write refusals. Their exact errors, call order and resulting
  security metadata agree. Held identities, source metadata, separate payloads
  and destination BSD flags are preserved.
- **24 public `fcopyfile(COPYFILE_ACL)` controls** independently compare native
  public results and final metadata with the qualified ACL-only stage. This does
  not claim the stat-only/combined stage is the entire public copyfile lifecycle.

For real pairs, the harness first replays observed errors to generate Go requests,
then applies that sequence to a separate real target. Every actual response must
match the replay, along with the final metadata. Controlled errors are never
substituted for actual filesystem results.

Run `CGO_ENABLED=0 go run scripts/verify-security-copy.go` on macOS. `-capture`
records unapproved observations. Normal qualification requires the archived
binary-safe corpus and compares fresh observations, normalizing only validated
actor IDs. Reports retain full pinned sources, unchanged function extractions,
arm64/x86_64 Clang ASTs, raw commands/inputs/outputs, target payloads and host and
revision identity. Cleanup resets restrictive target flags/modes after the
reported observations; retained targets' cleanup metadata is not the observation.

All three OSes replay the required corpus without skips. Independent coverage
above 95% is enforced for `security_copy.go`, alongside the existing ACL/HFS
files and the separate AppleDouble codec gate. `FuzzSecurityCopy` checks request
validity, write bounds, diagnostics and input preservation.

## Remaining work

The executor is now connected to both [image writer trees](appledouble-image-security-copy.md),
including inherited ACL selection, omitted properties, UUID-only removal and set-ID
side effects. Native host/carrier adapters and full restoration ordering remain open. Live source and identity acquisition,
privileged/sandbox contexts, volume-query diagnostics, libSystem allocation and
property-setter failures, and integration with stat/flags/times/xattr and final
AppleDouble stages remain open. The [five roadmap gates](../pkg/appledouble/README.md#roadmap)
remain open; package PR72 stays draft and codesign stays paused.
