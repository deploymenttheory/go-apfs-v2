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

## Native-readable LZ4 storage

The shared APFS/HFS+ decoder also reads types 15/16 using Apple's framed LZ4
format. `pkg/compression/lz4.DecompressReader` reads at most 32 KiB at a time,
including expanded encoded blocks larger than 64 KiB. Cross-block history and
the native output-capacity stopping rule are retained. Only `0xff` selects a
stored decmpfs LZ4 block; all other first bytes enter the framed decoder.

Native file compression requests for 15/16 currently fall back to LZVN; the
filesystem queue does not produce these types. Read support is independently
qualified with native Compression API output installed on both APFS and HFS+,
including full kernel readback. `Encode` and `EncodeFork` continue to accept
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
```

The existing gate retains its per-file checks and additionally requires complete
coverage above 95% for the shared decoder/writer and all affected public codec
packages, rejecting skipped tests. Existing large-file, mounted-image, foreign
producer, race and fuzz jobs remain mandatory. See
[compression storage](appledouble-compression-storage.md) for the separate
native and kernel-accepted large-file controls.
