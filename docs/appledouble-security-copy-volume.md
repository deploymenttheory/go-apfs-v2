# Security-copy volume policy

`SecurityCopyOptions.VolumePolicy` lets ordinary security copying acquire mount
policy at the point where Apple checks it. Use it when policy must come from
held host handles or previously captured foreign mount state. The shared Go
executor and both APFS/HFS+ image writers support this on Linux, macOS and Windows.

Set-ID filtering depends on runtime mount policy. The filesystem format does
not say whether a particular mount has `MNT_NOSUID`. An image writer therefore
must not infer this property from APFS/HFS+ bytes, nor substitute the workstation's
mount settings for a foreign source's captured settings.

## API and sequencing

Implement `hostmeta.SecurityCopyVolumePolicy.NoSetID(volume)` and supply it in
`SecurityCopyOptions.VolumePolicy`. The endpoint is either
`SecurityCopySourceVolume` or `SecurityCopyDestinationVolume`. The implementation
must bind each endpoint to the copy's actual source/destination or captured
foreign mount state, exclude concurrent mutation and leave the tree untouched.

The existing `CopySecurity` entry points accept this provider directly. No new
writer-specific policy implementation is needed. The existing precaptured
`SourceNoSetID` and `DestinationNoSetID` fields remain available when the provider
is nil. Mixing a provider with either true precaptured field returns
`os.ErrInvalid` before callbacks for a selected stage. A no-op remains a no-op.

Execution follows the complete Apple `copyfile_security` function:

1. Validate source properties; capture and select the destination ACL if requested.
2. Skip volume queries without `Stat`, with `AlwaysCopySetID`, or with
   `ForbidCopySetID`. Always-copy takes precedence over forbid-copy.
3. Otherwise query the source. A positive result skips the destination query.
4. A negative or failed source query allows the destination query.
5. Clear `06000` only when forbid-copy applies or a successful query is positive.
   Filter the working mode and fallback stat mode; retain the original source cache.
6. Perform the ordinary security writes and historical fallbacks.

Fatal validation, capture and ACL-selection errors prevent queries and writes.
Image graph/alias validation also precedes queries and publication. The provider
is invoked once per required endpoint per copy; results are not cached globally.

## Diagnostics

`SecurityCopyResult.VolumeQueries` records attempted queries in order:

| State | Representation | Native filtering effect |
| --- | --- | --- |
| Not queried | No entry for that endpoint | None |
| Observed negative | `NoSetID: false`, `Err: nil` | None |
| Observed positive | `NoSetID: true`, `Err: nil` | Clear set-ID when stat copying is selected |
| Lookup failed | `NoSetID: false`, original `Err` | No positive policy established; continue |

A provider returning both true and an error is treated as unknown; the diagnostic
boolean becomes false and the original error is retained. Query failures do not
increment `Writes`, enter `Failures`, trigger write fallback or set `Completed`
false. This matches Apple's `fd_volume_has_feature(...) > 0` test. Consumers
requiring fully observed policy must examine `VolumeQueries` as well as write
failures. Completion alone does not establish preservation.

## Native and portable evidence

`go run scripts/verify-security-copy-volume.go` compiles complete unchanged
`copyfile_security` and `fd_volume_has_feature` functions from Apple
[copyfile](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c)
(SHA-256 `19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`).
It reuses the existing request instrumentation and unchanged Libc `chmodx1` from
[Libc](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/sys/chmodx_np.c)
(SHA-256 `31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff`).
Both source downloads are hash checked. Reports retain source files, complete
extracted headers, arm64/x86_64 Clang ASTs, helper hashes, commands and observations.

The required corpus contains:

- **3,888 controlled native cases:** all three selected stages, normal/forbid/always
  policies, absent/explicit/inherited/empty/overflow ACL combinations, sparse/full
  properties, capture/write failures, and independent positive/negative/failed
  source and destination queries. These cases inject lookup errors to measure
  native sequencing; they are not claims of actual mounted-volume failures.
- **288 real native/Go request pairs:** files and directories, four ACL pairs,
  three stages and three policy overrides, across host-to-host, host-to-nosuid,
  nosuid-to-host and nosuid-to-nosuid APFS copies. Source properties come from real
  `fstatx_np`; queries use real `fstatfs`; writes use real native functions. The
  harness requires observed host-negative and mounted-image-positive policy,
  compares readback and cache behavior, and checks unchanged source metadata,
  inode identity, payloads and BSD flags. The temporary test image is built in Go.
- **Portable image integration:** 81 copies per filesystem with two regular-file
  hard-link aliases each, across APFS, case-sensitive APFS, HFSX and HFS+. Queried
  and precaptured policies must produce identical complete image hashes, exact
  modes/ownership/ACL presence and unchanged payloads after serialization/readback.
- **Portable policy cases:** all override combinations, no-op/early-error behavior,
  query order, original error retention, and true-with-error normalization.

Linux, macOS and Windows replay the native corpus and image integration without
feature skips. `go run scripts/verify-security-volume-coverage.go` requires more
than 95% statement coverage independently for both production security-copy
files, rejects skipped focused tests and records source hashes and revision.
The native harness runs on macOS in CI; all three OSes publish coverage evidence.

## Remaining work

This provides the portable acquisition protocol and connects it to image copying.
It does not implement live host source/volume providers, translate Linux ACLs or
Windows DACLs into Darwin ACLs, or finish native authorization and ordered
restoration. Those bindings must retain foreign metadata explicitly where native
semantics differ. Source acquisition, creation inheritance, ordinary copying,
stat/flags/times/xattrs, deferred AppleDouble replacement and cleanup still need
qualification as one lifecycle. All five roadmap gates remain open; package
PR72 stays draft, no release is authorized by this increment, and codesign waits
for the qualified APFS release and downstream adoption.
