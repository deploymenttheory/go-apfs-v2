# Ordered stat restoration

`hostmeta.CopyStat` implements the final stat-restoration stage used by Apple's
copyfile. It restores modification/access times, numeric ownership, permissions
and BSD flags in the order that allows ordinary metadata writes before a file
becomes immutable or append-only. The same pure-Go executor runs on Linux, macOS
and Windows; the caller supplies a backend bound to a held destination or an
explicit foreign-metadata object.

Use it when constructing an ordered metadata-restoration pipeline. It follows
ordinary security copying, which has its own ACL selection and fallback rules.
It is separate from AppleDouble's deferred ACL replacement. It does not open
paths, acquire source metadata, authorize writes or implement a complete host
adapter. Image timestamp storage is provided separately by
[the APFS/HFS+ timestamp APIs](appledouble-image-times.md).

## Contract

```go
result, err := hostmeta.CopyStat(source, hostmeta.StatCopyOptions{
    VolumePolicy: capturedOrHeldVolumePolicy,
    PreserveDestinationTracked: true,
}, heldDestinationBackend)
if err != nil {
    return err // Invalid backend/options; no operations were attempted.
}
// Inspect result.Failures and result.VolumeQueries even when Completed is true.
// Recapture the destination if the consumer needs proof of preservation.
```

`StatCopySource` contains Darwin numeric ownership, mode, flags and `FileTimes`.
Mode uses Darwin bits, not `os.FileMode`. Birth and metadata-change times are not
explicitly copied. Modification/access times retain nanoseconds and Unix zero;
the destination filesystem controls precision, birth-time changes and other
side effects. No wall clock or host identity database is consulted.

The sequence is:

1. Apply set-ID policy. `AlwaysCopySetID` takes precedence over forbidding or
   nosuid policy. Otherwise `ForbidCopySetID` prevents queries, then source and
   destination policy are queried in order. A positive source skips destination;
   a failed source does not. Lookup failures remain unknown, not positive.
2. Submit modification/access times, then ownership, then mode without file-type
   bits. Continue after each failure, retaining its original error.
3. Omit source `UF_TRACKED`, `SF_RESTRICTED`, `SF_NOUNLINK` and `UF_DATAVAULT`.
   `MakeInvisible` adds `UF_HIDDEN`.
4. Read destination flags. Retain `SF_RESTRICTED`, `SF_NOUNLINK`, `UF_DATAVAULT`,
   plus `UF_TRACKED` when requested. A failed read prevents flag writes because
   the protected bits have not been observed.
5. Try compare-and-swap at most four times. A successful comparison confirms the
   write. A mismatch supplies the next expected value and recomputes protected
   bits. Classified Darwin `EAGAIN` retries without accepting returned flags.
   Other errors immediately fall back to `Chflags`. Four unsuccessful attempts
   also fall back. The fallback uses the last observed protected bits.
6. If the requested flags include `UF_COMPRESSED` without user/system immutable
   or append bits, submit the times again. This happens even when flag copying
   failed, matching native behavior.

`VolumePolicy` can use the existing `SecurityCopyVolumePolicy` interface. It must
not be combined with either precaptured positive `NoSetID` option. This stage
queries afresh; callers must not silently reuse an earlier security-stage query
when reproducing native call order.

## Errors and backend responsibilities

Native copyfile reports success despite failures in this stage. `Completed`
therefore means the sequence ran, not that restoration succeeded. `Failures`
retains write errors, flag-read errors and recovered CAS errors in order.
`VolumeQueries` separately records policy reads. `Writes` counts attempted writes,
including failed comparisons; `FlagComparisons`, `FlagsFallback` and
`FlagsApplied` describe flag execution. A successful fallback does not erase the
failure that prompted it. There is no rollback.

Backends keep every operation bound to the same object. They own native/carrier
permissions, race handling, timestamp precision and side effects. The CAS return
value is the flags observed **before** the attempted write. With nil error,
`actual == expected` means success; a mismatch means the write did not happen.
Return `ErrStatFlagsAgain` joined with the original Darwin `EAGAIN` error only for
that condition. Permission, unsupported and arbitrary I/O errors must not be
reclassified as contention.

This does not emulate Darwin flags using unrelated Windows attributes or Linux
inode bits. A foreign-host backend must preserve the Darwin metadata explicitly.
There are no OS-specific feature stubs in this executor. Built-in native and
foreign-carrier bindings remain outstanding.

## Qualification

The test-only harness downloads hash-pinned Apple sources and compiles the
complete unchanged `copyfile_stat`, `copyfile_set_bsdflags` and
`fd_volume_has_feature` functions. It retains Clang ASTs for arm64 and x86_64,
command logs, requests, errno values and before/after observations.

- **1,031 controlled native cases** cover flag masks, set-ID precedence, failed
  volume reads, each write/read failure, all-error execution, bounded EAGAIN,
  changing protected bits, unsupported CAS and failed fallback. Compression's
  second timestamp request and all four protection bits are covered here.
- **192 real APFS file/directory pairs** compare Apple-function execution with
  the exact Go-generated requests submitted to the real native operations.
  Ordinary, hidden, nodump, tracked, immutable and append scenarios include
  actual permission failures. Source metadata, object identities, payloads,
  destination ACLs and unrelated xattrs remain unchanged.
- **24 public `fcopyfile(COPYFILE_STAT)` comparisons** check resulting metadata
  for the ordinary-destination subset. Public copyfile also runs the preceding
  security stage, so these are outcome comparisons rather than a claim that its
  full event sequence equals the isolated stat stage.
- Linux, macOS and Windows replay the same archived native observations without
  cgo. The focused coverage gate requires **above 95% in each new production
  file**, and rejects skipped focused tests. The current files cover **57/57
  statements** across 1,233 passing test records.

Run `go run scripts/verify-stat-copy-coverage.go` on any supported OS. On macOS,
`go run scripts/verify-stat-copy.go` re-runs native qualification and compares
with the approved corpus. `-capture` records observations for review only; it
neither approves nor replaces the corpus. Native tools are never used by
production code.

Live qualification here is ordinary-user APFS files/directories. It does not
establish live compressed-file, symlink, HFS+, privileged/sandbox, or concurrent
kernel-race behavior. Compression and contention paths have controlled native
function evidence. Metadata-change time is kernel-owned and not part of the
stable comparison record. Host bindings, image write integration, xattr ordering,
deferred ACL replacement and lifecycle cleanup still need qualification together.
All five AppleDouble completion gates remain open.

Sources: Apple's pinned [copyfile implementation](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c),
[flag masks](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile_private.h),
and [XNU CAS ABI](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/fsctl.h).
