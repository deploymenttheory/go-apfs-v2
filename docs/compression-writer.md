# Writing native compressed storage

`pkg/compression/decmpfs.EncodeFork` converts logical file contents into a native
compression resource fork and its 16-byte `com.apple.decmpfs` attribute. Use it
when an operation changes a compressed file's contents and needs new compressed
storage. Reusing the old fork would describe the wrong bytes.

The implementation is pure Go and works on Linux, macOS and Windows. It accepts
zlib (types 3/4), LZVN (7/8), stored blocks (9/10), LZFSE (11/12) and LZBITMAP
(13/14), returning the resource-fork form of the selected codec. Input is an
`io.ReaderAt`; output is an `io.WriterAt`. Each source read is at most 64 KiB.
Index entries are written individually, so neither the logical payload nor the
complete index needs to be retained in memory. Native 32-bit physical offsets
remain a format constraint even when logical contents exceed 4 GiB.

The caller owns both handles and any temporary file. On success, truncate a
reused destination to `EncodedFork.Size`. On failure, discard partial output;
the returned result is zero and the original I/O error remains discoverable.
Cancellation is checked between I/O and codec calls. A blocked I/O call must
return before cancellation can be observed.

This API creates storage bytes. It does not choose inline storage, decide whether
a host should compress a file, install attributes or set `UF_COMPRESSED`. Those
operations require filesystem lifecycle policy, including protection of logical
data until storage installation succeeds. Native queue acceptance alone does
not mean that a file was compressed. The native producer capture records the
actual flags, attribute, fork and full logical readback for that reason. A separate
33-request native selection audit records that unsupported numeric requests
select the default codec; the actual on-disk type, not the requested number,
establishes which codec was used. The format API intentionally accepts explicit
codec types rather than reproducing a host queue's option fallback.

## Native content policy

`decmpfs.Encode` shares the same bounded encoder and applies the native default
content decisions. `EncodeOptions.Type` selects a codec; zero selects LZVN.
`ResourceForkOnly` disables the default preference for inline storage. These
decisions and codecs work identically on Linux, macOS and Windows.

The default native size window is greater than 16 KiB and at most 512 MiB. This
is a decision to leave contents uncompressed, not a reader size limit.
`EncodeFork` remains available for explicitly requested storage outside that
window. For compressing codecs, the payload budget is 80% of the logical file's
4 KiB page count, rounded down to whole pages, less fork framing. Stored blocks
bypass the savings check. A single block with at most 3,786 payload bytes uses
inline storage when allowed; the complete attribute is at most 3,802 bytes.

`EncodedFile.Attribute == nil` means the content policy declined compression.
Otherwise the attribute is complete and `ForkSize` gives the exact resource-fork
extent, or zero for inline storage. Inline results leave the destination
untouched. A later block can exceed the savings budget after earlier blocks
have been written: callers must stage privately and discard partial output on
decline or error. The API does not close or truncate caller-owned handles.

File eligibility and installation are
separate lifecycle work. This content API does not check entry types, names,
permissions, existing resource forks or live file identity, and it does not
change file flags. It must not be used as a complete live-file recompression
operation until those checks and installation are integrated.

The shared reader uses each zlib descriptor's explicit length, including for
small indexes. Resource Manager map bytes and inter-block gaps are not part of
the compressed stream. Tests read every retained native fork and reject any
attempt to consume the map as payload; checksum validation is retained.

## Active and inactive storage

The recorded `UF_COMPRESSED` flag selects compressed or ordinary file data.
Leftover attributes after a partial installation remain opaque when the flag is
clear. Image readers, explicit writer flags and metadata carriers preserve that
distinction; see [compression storage state](compression-state.md) for the API
contract and complete native/portable qualification matrix.

## Inspecting compression metadata

`decmpfs.Query` reports the native metadata fields from a caller-supplied stable
`Metadata` snapshot. It accepts sized borrowed attribute readers, reads at most
24 bytes and does not read or allocate the resource fork. Native held-file
capture, explicit AppleDouble metadata and image metadata can supply the same
input on every host. The caller must use observed flags: setting compression
on invalid metadata can cause the kernel to clear the flag again.

The result preserves native type, overhead, stored and logical sizes, and the
opaque eight-byte extension on fork-based attributes. Missing required forks
are reported explicitly while the metadata query succeeds, matching native
behavior. Type 5 uses native unknown-size sentinels. The 32-bit overhead field
has native wraparound semantics and must never be used as an allocation bound.
Unknown types remain visible without assigning them an invented codec.

A successful query is not proof that the payload is readable. Compression
readers continue to validate the actual format, indexes and compressed blocks.
Querying does not install attributes or change filesystem flags.

## Held native metadata and activation

`hostdata.QueryCompression` pins a caller-held Darwin descriptor while capturing
compression metadata and applying the portable query. It reads only the decmpfs
attribute within an explicit allocation budget and obtains fork length without
reading the resource fork. Changed flags or logical size cause an error; callers
must still exclude same-size concurrent edits. Explicit image/carrier metadata
supplies `decmpfs.Metadata` directly on every OS.

`hostdata.CompressionVolumeFlags` observes the held file's actual Darwin mount
context. `MNT_CPROTECT` (`0x80`) prevents inline compression on that volume. A
newly mounted APFS image and the host APFS volume can differ on the same macOS
release. Foreign operations must retain the producer's context instead of
inferring it from the receiving OS or filesystem name.

`hostdata.ActivateCompression` performs the compressor's final flag operation
against either held native metadata or logical foreign metadata. It reads flags
afresh before each of at most four comparisons, preserves concurrent unrelated
flag changes and retries contention. Other errors stop immediately; exhausted
comparisons never fall back to an unconditional flag overwrite. Results retain
attempt counts and recovered errors. This operation assumes completed compressed
storage and an already truncated data fork; it is not a complete installer.

The retained lifecycle corpus contains 591 independent host/APFS/HFS+ cases,
including 272 activation sequences. Eligibility, existing forks, modes, ACLs,
links, all supported codecs, temporary permissions and injected storage,
truncation, flag, synchronization, close and timestamp errors retain actual native
outcomes. Test-only interposition is confined to the disposable target inode.
The production implementation does not load the native framework or interposer.

`hostdata.InstallCompressionFork` installs staged fork bytes with native write
boundaries: the full index, each encoded block, then the zlib resource map. It
retains partial writes, declines fork output when an independent fork exists,
and synchronizes/closes its writer even for inline output or failure. Sync and
close errors stay visible without changing native continuation policy. All 501
retained fork-stage sequences are replayed, including multi-block EIO/ENOSPC
after the index and after the first block, plus positive short writes at all\nthree frame boundaries. The caller owns the stable stage,
existing-fork observation, earlier authorization and later commit decision.

`hostdata.InstallCompression` composes fork installation with the final commit
against a native or explicit foreign backend. It preserves a pre-existing
independent fork, synchronizes the data handle and restores times on that
decline path. It never reaches data truncation after a failed or short fork
write. `InstallHeldCompression` supplies the Darwin binding and keeps the
caller's held data file open; Linux and Windows bind the same operation to
explicit foreign state rather than reinterpreting host flags.

The portable suite installs 66 independent native storage choices into real
ordinary and resource-fork files and verifies complete bytes, physical data-fork
truncation, logical flags, modes, timestamps and handle ownership. The macOS
harness runs 396 held-file kernel readbacks across the host volume and separately
mounted APFS/HFS+ volumes. It records each volume, all cases and every ordinary
detach attempt. A skipped case or missing storage choice fails qualification.
These APIs still require the caller to qualify eligibility, select volume policy,
stage fresh encoded storage and publish foreign metadata; they are not a complete
path-based recompression operation.

`hostdata.CommitCompression` installs the attribute and performs truncation,
activation and restoration after the resource-fork writer has completed. Native
`EACCES` alone permits mode 0600 and one attribute retry; even `EPERM` does not.
The result records each mutation and recovered or ignored failure. Exhausted
successful flag comparisons still restore timestamps, matching the native trace,
while reporting that activation failed. Cancellation before truncation stops at
the next boundary. Once truncation succeeds, flag activation and restoration
finish before a late cancellation is returned. No rollback is promised.

`hostdata.CommitHeldCompression` binds that transition to the caller-held native
Darwin file. It uses typed x/sys operations and the existing held metadata
adapter, including native microsecond timestamp restoration. The resource-fork
writer must already be complete and closed. Native tests replay 36 independently
captured storage choices, verify full kernel readback through held and reopened
files, and ensure a rename plus replacement at the original name cannot redirect
the transition. The shared `CommitCompression` protocol supplies the same policy
for explicit foreign metadata on Linux, macOS and Windows.

Complete installation, eligibility and foreign carrier publication remain
integration prerequisites. Queue acceptance alone does not establish successful
compression, and errors after truncation can leave partial native state. These
observations must be honored by the eventual high-level operation.


## Native-readable LZ4 storage

The shared APFS/HFS+ decoder also reads types 15/16 using Apple's framed LZ4
format. `pkg/compression/lz4.DecompressReader` reads at most 32 KiB at a time,
including expanded encoded blocks larger than 64 KiB. Cross-block history and
the native output-capacity stopping rule are retained. Only `0xff` selects a
stored decmpfs LZ4 block; all other first bytes enter the framed decoder.

Native file compression requests for 15/16 currently fall back to LZVN; the
filesystem queue does not produce these types. Read support is independently
qualified with native Compression API output installed on both APFS and HFS+,
including full kernel readback on macOS 27. `Encode` and `EncodeFork` continue to accept
the explicitly documented writable codec types.

## Native encoding decisions


Buffer capacity affects native output. `lzbitmap.EncodeBuffer`, the existing
`lzfse.EncodeBuffer`, and `lzfse.EncodeLZVNBuffer` expose bounded buffer operations.
A zero result means the native-style capacity checks declined the stream; it is
not evidence of corrupt input. Their allocating convenience APIs retain their
own documented output-size and ownership contracts.

LZBITMAP uses a fixed hash history table, sixteen history candidates plus the
current period per group,
native tie ordering and descriptor selection. Its destination checks include
intermediate literal space, the uncollapsed descriptor table and a 31-byte safety
margin. A final stream that would fit can therefore still be declined. The
filesystem writer then uses the native stored-block marker. LZFSE and LZVN have
their own bounded-buffer decisions, including LZVN's eight-byte minimum input.

Filesystem zlib blocks use native level-five raw DEFLATE behind `0x785e`, without
an Adler-32 trailer. Exact-capacity output is declined. For a one-byte tail, the
retained host framework's 32-bit capacity subtraction wraps and accepts the
five-byte compressed block; the Go writer reproduces those bytes without an
out-of-bounds write or allocating the wrapped capacity.

Canonical LZBITMAP encoding intentionally changes from the earlier approximate
reference encoder. Five historical scalar streams retain their original hashes
and remain decoder compatibility fixtures. Independently captured native outputs
for those same inputs now qualify encoding. The original native `aa` fixtures,
8 MiB incompressible performance check and fuzz properties remain required.

## Native runtime profiles

macOS 26.6.2 (25G83) does not register decmpfs LZ4 types 15/16: every retained
kernel control fails at open with `EIO`, and its metadata query treats these
numbers as unknown storage. macOS 27.0 (26A428) and 27.0.1 (26A434) recognize
these types. Their complete buffer, kernel and query captures agree. The public
native LZ4 codec's 140 buffers and 900 capacity/terminator observations agree
between both runtime families. `Query` describes the current recognized storage
layouts uniformly on every Go host, including hosts with older native kernels.

The older complete observations are retained in `compression-lz4-macos26.json.gz`
and `compression-query-macos26.json.gz`. Native recapture checks the complete
matching profile; an unknown or changed outcome fails the gate. No case is
removed because a host kernel does not support it.

The four-by-four carrier/image harness includes all 144 current-kernel accepted
LZ4 cases on every producer OS. Both `macos-latest` and `xcode-27` independently
mount and inspect the resulting images, including foreign Linux/Windows output.
The former must reproduce the observed open-time `EIO`; the latter must read
all logical bytes through the kernel. An additional Clang-built C oracle reads
compression storage from each mounted image and decodes every byte through
Apple's public LZ4 API on both runtimes. The report's `LZ4Reads` records the kernel
outcome and independent native-codec byte count/hash separately. This preserves
strict assertions for the old kernel and complete positive kernel acceptance
on the current runtime, while the Go reader supports the storage on every OS.

## Reproducing qualification


The retained observations are in `testdata/appledouble/native/`:

- `compression-blocks.json.gz`: 1,871 independently captured native codec
  outputs, 5,050 destination-capacity observations, and one constructed legacy
  LZFSE V1 control independently accepted by the native decoder. Its nonempty
  readback distinguishes success from a native decode failure.
- `compression-writer.json.gz`: 630 actual filesystem producer observations,
  including 592 compressed forks and recorded unchanged results. Short tails
  cover compressible and incompressible data across codec boundaries. Every
  logical byte is read back through the host kernel. The same fixture also
  retains the separate 33-request type-selection audit.
- `compression-zlib-source.json`: complete pinned Apple zlib C implementation
  qualification against all 366 native zlib samples.
- `compression-policy.json.gz`: 4,632 independently captured APFS/HFS+ cases,
  including exact size, savings and inline transitions, every resulting storage
  byte, full kernel readback, and guarded path/held metadata queries. Native
  codec measurements select the transition inputs; Go output never supplies
  expected observations.

- `compression-lz4.json.gz`: 140 native buffers, 900 capacity and terminator
  observations and 1,172 kernel storage cases. Every possible first-byte marker
  is retained, including rejected controls. Truncated bodies, missing/wrong
  terminators and ignored trailing bytes are distinguished.
- `compression-query.json.gz`: 676 guarded path/held queries on APFS and HFS+,
  covering all types 0–32, absent/empty resource forks, invalid headers and
  partial/complete attribute extensions. Reopen failures remain in the record;
  initial held queries provide metadata observations for unreadable payloads.

On macOS, run:


```sh
go run scripts/capture-compression-blocks.go -check
go run scripts/capture-compression-writer.go -check
go run scripts/verify-compression-zlib-source.go
go run scripts/capture-compression-policy.go -check
go run scripts/capture-compression-lz4.go -check
go run scripts/capture-compression-query.go -check
go run scripts/capture-compression-lifecycle.go -check
```

These commands preserve fresh artifacts before comparing the retained evidence.
They retain compiler/SDK provenance, source hashes and arm64/x86_64 Clang ASTs.
The zlib probe compiles complete pinned `deflate.c` and `trees.c` bodies. The
native library and filesystem framework captures also retain implementation
disassembly and UUIDs; unpublished implementation behavior is checked through
runtime observations rather than inferred from SDK declarations.

On every supported host, run:

```sh
go run scripts/verify-decmpfs-formats-coverage.go
go run scripts/verify-compression-lifecycle.go
```

The existing gate retains its per-file checks and additionally requires complete
coverage above 95% for the shared decoder/writer and all affected public codec
packages, rejecting skipped tests. Existing large-file, mounted-image, foreign
producer, race and fuzz jobs remain mandatory. See
[compression storage](appledouble-compression-storage.md) for the separate
native and kernel-accepted large-file controls.

The compression lifecycle gate requires every new production file above 95%
coverage and separately runs the complete hostdata package above 95%. Its focused
transcript permits no skipped cases. The evidence audit inventory includes this
gate alongside all 24 pre-existing portable reports.
