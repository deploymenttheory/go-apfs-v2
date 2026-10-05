# Writing native compressed resource forks

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

The shared reader uses each zlib descriptor's explicit length, including for
small indexes. Resource Manager map bytes and inter-block gaps are not part of
the compressed stream. Tests read every retained native fork and reject any
attempt to consume the map as payload; checksum validation is retained.

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

On macOS, run:

```sh
go run scripts/capture-compression-blocks.go -check
go run scripts/capture-compression-writer.go -check
go run scripts/verify-compression-zlib-source.go
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
