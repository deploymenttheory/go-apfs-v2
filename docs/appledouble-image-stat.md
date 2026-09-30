# Ordered stat staging in image trees

Both APFS and HFS+ writer entries expose `root.CopyStat(target, source, options)`.
It applies the shared final stat stage to an offline image tree: modification and
access times, numeric ownership, permissions, then selected BSD flags. Regular
hard-link aliases update together. This connects the timestamp and flag storage
APIs to the existing stat policy without duplicating that policy in each writer.
The implementation is pure Go on Linux, macOS and Windows.

Use it when assembling a metadata-restoration pipeline after ordinary security
copying. The separate AppleDouble unpack route applies its deferred ACL
replacement **before** this final stat stage. See [route ordering](appledouble-copy-pipeline.md).
This component does not create the complete restoration lifecycle automatically.

## Use and publication

```go
// Resolve all four destination timestamps from captured metadata first.
destination.Times = &destinationTimes
result, err := root.CopyStat(destination, capturedSource, hostmeta.StatCopyOptions{
    PreserveDestinationTracked: true,
})
if err != nil {
    return err // Invalid tree, destination metadata or options; no tree changes.
}
if !result.Applied {
    // Inspect result.Execution.Failures. Nothing was published into the tree.
    return fmt.Errorf("stat staging failed: %v", result.Execution.Failures)
}
// Also inspect result.Execution.VolumeQueries for unknown volume policy.
// CreateContainer/CreateImage must still succeed to serialize the staged result.
```

The source is `hostmeta.StatCopySource`, with Darwin mode bits rather than
`os.FileMode`. Source birth/change times are not selected. Destination birth and
change times remain intact. The tree does not synthesize wall-clock metadata or
live kernel timestamp side effects. For example, this API does not emulate a
mounted filesystem changing birth time when modification time moves earlier.

Every destination alias must have explicit `Times`. A nil value cannot establish
birth/change metadata without knowing the eventual writer's default time and
clamping options, so it is refused. A `Volume.FileTimes` capture can supply these
fields. Explicit epoch zero is valid. Existing format bounds apply; HFS truncates
subseconds when serialized. A later `ClampModTimes` writer option still applies.

The complete tree shape is validated before staging. Nil, cyclic, repeated or
unreachable entries and invalid types fail. Regular-file aliases must agree on
ownership, resolved mode, stored security, all four timestamps and resolved BSD
flags. Equal timestamp instants in different Go locations agree. Unrelated
legacy entries do not need explicit times. Targets are entry pointers; symlinks
are not followed, and root default mode resolves as a directory.

Each operation acts on a private metadata copy. A destination validation error
returns an error before execution. An operation failure, such as an out-of-range
source timestamp or incompatible compression flags, remains in
`result.Execution.Failures`; the native sequence continues on that private copy.
**No entries change unless the entire staged sequence succeeds.**
`Execution.Completed` and `Execution.FlagsApplied` describe that private execution;
only `Applied` means publication into all aliases. Each updated alias receives
its own timestamp and flag values. Data, resource forks, ACL/UUID storage and
unrelated xattr maps are not rewritten.

The caller must exclude concurrent tree mutation. A volume-policy provider must
not mutate the tree while it is queried. This is not a live-path lock, native
permission check or host/carrier adapter. It stages foreign metadata equally on
all three OSes, without translating Darwin flags into unrelated host attributes.

## Shared policy and format checks

The existing [stat executor](appledouble-stat-copy.md) owns set-ID precedence,
lazy volume queries, protected destination flags, source tracked/protected flag
omission, optional invisibility/tracked retention and the compressed-file second
time request. A failed volume query remains visible even when publication succeeds.
These queries are fresh for the stat stage, independent of prior security copying.

The image binding owns format validation and publication. Nil `BSDFlags` infers
compression as the writer already does; explicit flags must agree with destination
decmpfs storage. CopyStat neither copies compressed data nor adds/removes decmpfs.
A request that would leave flags inconsistent with existing storage is refused.
HFS-unrepresentable bits and out-of-range times are errors, not silently discarded.
Writer serialization still validates payloads and other metadata independently.

## Qualification

`go run scripts/verify-image-security.go -stat` provides two independent checks:

- **32 controlled policy observations** execute complete unchanged pinned Apple
  `copyfile_stat`, `copyfile_set_bsdflags` and `fd_volume_has_feature` functions.
  Their successful requests supply expected ownership, mode, times and flags.
  They cover ordinary/nodump/immutable/append/tracked/protected/compressed sources,
  set-ID removal, invisibility and destination tracked retention.
- The actual APFS and HFS+ writer APIs stage those scenarios into roots, files,
  directories, symlinks and hard links. **580 mounted native observations** across
  APFS, case-sensitive APFS, HFSX and HFS+ compare all selected fields, retained
  birth/change times, inode identity, payloads/link targets and unrelated xattrs.
  Compressed cases use regular files and hard links with real decmpfs payloads.

`fsck_apfs` and `fsck_hfs` validate all four images; both APFS fixtures include a
snapshot. Read-only mount hashes remain unchanged. Public statx and complete
unchanged pinned Libc `statx1` agree on captured security properties. The artifact
retains four Clang ASTs (policy and capture, arm64 and x86_64), pinned sources,
commands, policy requests, native readback and whole-image hashes.

This establishes offline staging policy and image serialization/readback. The
controlled policy oracle supplies successful writes; it is **not** evidence that
live protected files permit the same updates. Host authorization, kernel time
side effects, concurrent kernel CAS behavior and full copyfile integration remain
separate qualification. Existing live stat tests retain their measured failures.

`go run scripts/verify-image-stat-coverage.go` replays the same evidence on all
three OSes, checks the four image hashes, rejects skipped focused tests and
requires above 95% coverage in each new production file. Current coverage is
**68/68 statements (100%)**, with **618 passing test records**. Tests additionally
cover failed staging with no publication, alias conflicts, sentinel ownership,
unknown volume policy, explicit root mode zero and independent ACL/stat
metadata preservation. That preservation test is not a native unpack sequence.
Existing flag/timestamp-image and legacy layout hashes remain gates.

The pinned source provenance is shared with [stat execution](appledouble-stat-copy.md)
and [image security capture](appledouble-image-security.md). Native helpers are
qualification-only; production has no C or macOS dependency.

## Remaining work

Source/host/provider bindings, creation inheritance and the outer copy lifecycle
still need integration. Ordinary copy runs quarantine,
xattrs, data, security and stat; unpack owns its deferred ACL-before-stat route. Live
kernel timestamp side effects and authorization are not implemented by offline
staging. Shared carriers, quarantine contexts, large values/allocation and final
consumer qualification remain open. All five AppleDouble roadmap gates remain
open; package PR72 stays draft on its published dependency, and codesign stays
paused until the qualified APFS release is adopted downstream.
