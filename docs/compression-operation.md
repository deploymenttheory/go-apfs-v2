# Recompression operations

`hostdata.Recompress` composes read/write acquisition, native default eligibility,
encoding, compression installation and owned-handle cleanup. Use it when an
operation must recreate filesystem compression after modifying logical file
contents. The lower-level `decmpfs.Encode` and `InstallCompression` APIs remain
available for callers that already own acquisition and staging.

The protocol runs on Linux, macOS and Windows. `OpenNativeCompressionInput` binds
it to actual Darwin descriptors using typed `x/sys` wrappers. Explicit foreign
providers supply Darwin metadata and observed mount policy; a Linux filesystem
flag or Windows attribute is never substituted for a Darwin compression flag.
The complete carrier publication integration is still being implemented.
[OS version profiles](../pkg/osversion/README.md) identify explicit macOS targets
on every host; observed volume flags remain an independent input.

## Admission, declines and failures

`RecompressionResult.Accepted` records read/write open plus the first successful
stat. It remains true if encoding or installation subsequently fails. This
separation matters to `codesign`, which checks admission to Apple's compression
queue independently of later compression completion.

The native default policy declines zero-length files, lengths up to 16 KiB,
lengths above 512 MiB and final path components beginning with `._`. These are
compression eligibility decisions, not codesign payload-size limits. They occur
after opening and statting the file. Incompressible content and an independent
resource fork can cause later declines with different cleanup behavior.

For eligible input, a second stat captures restoration metadata. The protocol
then issues the zero-byte write, duplicates the held input, opens the resource
fork without truncation, observes volume flags, encodes into private staging and
installs the result. `MNT_CPROTECT` prevents inline storage even if requested.
The original and duplicate inputs, fork writer and private stage have explicit
ownership and cleanup on all paths.

A content decline synchronizes/closes the fork, synchronizes the data file and
restores timestamps. An encoding/read failure closes the fork and data handles
without pretending those restoration operations succeeded. Installation retains
its existing ordered partial-failure contract, including temporary permissions,
atomic flag comparisons and ignored native restoration errors.

Cancellation is checked before destructive installation. After successful data
truncation, activation and restoration finish before cancellation is returned.
Cancellation raised during cleanup is retained too. Neither this protocol nor
the native operation promises rollback or an immutable filesystem snapshot;
callers must exclude unrelated edits during the operation.

## Acquiring compressed input and observing results

Read/write open can decompress an existing Darwin file before the first stat.
Consequently, restoration must use the acquired file's metadata, not an assumed
pre-open timestamp. Opening an inline-compressed file preserves an independent
resource fork. The retained native corpus covers these cases on mounted APFS and
HFS+ as well as the host volume.

Even read-only observation can alter metadata. On the captured HFS+ profiles,
opening a file whose compression uses the resource fork changes its access time.
The acceptance tests assert the restored timestamp before that observer open,
then separately compare the open's effect with the independent C observation.
They still require exact logical contents, compression storage and inode identity.

The native fault corpus also retains a framework process crash after an injected
volume-query failure, including the surviving file bytes. The Go protocol
reports the operation error and cleans up its handles. This is an explicit
exception to process-level failure parity; it does not deliberately crash a
calling Go application or label the native process as having accepted the file.
The interposer records caller/worker identity. After this specific volume-query
fault, worker fork sync/close is mandatory and ordered; the crash can preempt
the caller's final data close. The checker validates every recorded cleanup
event against that partial order, and rejects missing worker cleanup, duplicates,
wrong threads, wrong errors or other process-failure profiles. Independent tests
exercise all permitted interleavings and rejected mutations.

## Evidence and qualification

- `testdata/appledouble/native/compression-operation.c` and its confined
  interposer capture 330 native cases per OS profile, with both Clang architecture ASTs, SDK
  headers, framework identity/disassembly and source hashes.
- `scripts/capture-compression-operation.go -check` independently recaptures every
  case, retaining full storage, surviving process-failure state and raw traces.
  Timestamp comparisons use the observed post-open snapshot; absolute wall-clock
  values remain in the artifact. Mounted-image cleanup uses the shared bounded
  busy-detach helper, and any terminal cleanup failure fails the capture.
- The existing 591-case lifecycle corpus remains unchanged. Portable protocol
  tests compare 66 complete native storage controls and exercise failures and
  cancellation through acquisition, staging, installation and close.
- `scripts/verify-compression-lifecycle.go` keeps all existing suites mandatory,
  enforces coverage above 95% for each affected production file and separately
  requires complete-package coverage above 95%.
- `scripts/verify-compression-installation-native.go` now requires 462 actual
  installation/recompression readbacks on host/APFS/HFS+, including every codec
  and the native read-open observation controls. CI runs the native capture and
  mounted checks on both existing macOS runners. The macOS 26 and 27 acquisition
  traces have separate complete profiles; macOS 15 recapture and installation
  qualification has been added and remains required before claiming that release
  is supported. Current source provenance must be recaptured on each release.

## Remaining integration

Complete concrete foreign carrier acquisition and publication, including source
association, explicit volume policy, hard-link aliases, changed payload baselines,
retained partial compression state, generation conflicts and publication failures.
Qualify independently produced Linux/Windows outputs through native macOS
readback. Extend the source-change, large-file eligibility and private-storage
failure matrix before declaring the high-level integration complete. Codesign's
`--preserve-afsc`, representation-specific post-commit behavior and full Phase 2
streaming qualification remain downstream work.

## Older kernel resource-fork acquisition

The shared `osversion` target model distinguishes macOS 15, 26 and 27. Native
resource-fork bindings detect the actual host version because a requested
compatibility target cannot add a missing kernel operation. The portable codecs
and logical foreign state remain available independently of that native binding.

The retained 540-case C opening matrix covers six methods, read/write access,
live/renamed/replaced/unlinked/empty-fork files, and host/APFS/HFS+ volumes on all
three releases. macOS 15 rejects descriptor-relative regular-file fork opens
with `ENOTDIR`; its `F_GETPATH` plus path open succeeds for live and renamed files.
The Go route uses a finite typed libSystem extension, verifies the stream's device
and inode, and defers requested truncation until that check succeeds. An injected
namespace replacement test proves that a different file's existing fork is not
truncated or overwritten.

This older path lookup cannot reopen an unlinked resource fork and cannot provide
an atomic namespace snapshot. Its native errors are retained; unrelated namespace
edits must be excluded during acquisition. The newer descriptor-relative route
continues to support unlinked held files. These are independently observed native
constraints, not reasons to remove logical resource-fork support on Linux or
Windows or to drop the corresponding test cases.

`F_GETPATH` uses x/sys's three-argument runtime calling convention. On ARM64,
padding that variadic `fcntl` call to six arguments places the wrong value in its
stack argument slot; native tests cover both the successful path and captured
`EBADF`. The generated bindings retain both architecture targets and the existing
strict wrapper coverage gate.

Mounted acceptance now requires **492** checks: all previous 462 remain, plus ten
native resource-fork opening/readback outcomes on each of the three volume roles.
Every retained release is independently recaptured in CI; portable source and
case-inventory checks require all 990 recompression and 540 opening observations.
The older release's broader quarantine qualification remains outstanding.
