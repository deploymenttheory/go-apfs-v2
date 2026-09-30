# Compression attributes and resource forks

A compressed macOS file keeps its logical contents in `com.apple.decmpfs` and,
for fork-based storage, `com.apple.ResourceFork`. Its ordinary data fork is empty.
AppleDouble and the managed carrier preserve those original bytes; file reads
return decompressed contents. Repacking an unchanged carrier verifies the
materialized payload before reusing the compressed storage. Edited payloads
require explicit decompression rather than silently attaching stale compressed
metadata to new data.

## Supported storage

| decmpfs type | Data location | Decoder |
| --- | --- | --- |
| 1 | Inline attribute, directly after the 16-byte header | Raw bytes, exact declared length |
| 3 / 4 | Inline / resource fork | zlib |
| 7 / 8 | Inline / resource fork | LZVN |
| 9 / 10 | Inline / resource fork | Raw chunks with native `0xcc` marker |
| 11 / 12 | Inline / resource fork | LZFSE |
| 13 / 14 | Inline / resource fork | LZBITMAP, or stored chunks with `0xff` marker |

All these decoders and image writers run in pure Go on Linux, Windows and macOS.
The LZBITMAP implementation moves from the existing macos-pkg package into
`pkg/compression/lzbitmap`; its MIT provenance and native `aa` fixtures travel
with it. `DecompressLimit` checks the output bound before allocating each chunk.
The corresponding macos-pkg compatibility wrappers remain a downstream draft72
change after APFS qualification and release, avoiding a circular dependency.

Inline compression does not own a separate resource fork. Such a fork can carry
independent metadata and must survive both compressed transport and explicit
decompression. Native type 1,9 and13 observations independently establish this
case. Fork-based compression owns its fork instead; decompression consumes it.

Apple XNU limits the complete compression attribute to **3802 bytes**. This is
a native compression-header/payload limit, not the ordinary xattr or resource-fork
limit. Writers reject larger compression attributes explicitly. The native
kernel clears the compression flag for an oversized type 1 attribute rather than
presenting its bytes as decompressed contents. The retained accepted boundary
contains exactly 3802 attribute bytes. Empty type 1 is valid; its attribute consists
of the header alone.

Type 5 is an external generation-store reference, not a codec. Its content cannot
be reconstructed from a compression attribute and resource fork alone. Returning
zero-filled data would be incorrect. Unknown types and dataless provider markers
also require their actual external content/provider semantics; this change does
not manufacture unavailable content. These prerequisites remain distinct from
lossless transport of the original metadata bytes.

## Evidence and gates

`go run scripts/verify-decmpfs-formats.go` runs on macOS. AppleFSCompression
produces type 10 and14 multi-block forks for compressible and mixed incompressible
payloads. Native blocks also populate inline containers, which the kernel must
accept and read back independently. Type 1 follows Apple's published implementation
and receives the same kernel readback. The report distinguishes framework-produced
forks from explicitly assembled, kernel-qualified inline containers.

The 14 cases retain complete plaintext, compression attribute and fork bytes in
`testdata/appledouble/native/decmpfs-formats.json.gz`. Use `-capture` to regenerate
the fixture deliberately. Source hashes, host/compiler/SDK versions, command
observations and both arm64/x86_64 Clang ASTs accompany capture. Public source pins:

- [Apple XNU decmpfs.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/decmpfs.c): built-in type 1 validation and fetch behavior.
- [Apple XNU decmpfs.h](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/decmpfs.h): 3802-byte maximum and storage header.
- [fscmp](https://github.com/Siguza/fscmp/tree/905322c0e96c706e78b58237dab7e65c4f7a31f8): experimental native producer ABI reference, used only by the qualification tool.
- [libzbitmap](https://github.com/eafer/libzbitmap/tree/574abeae25b25c3319b9b6a9225cc7464e08ae88): MIT codec origin; the existing Go translation is reused.

`go run scripts/verify-decmpfs-formats-coverage.go` replays the retained native
cases on every supported operating system and enforces greater than 95% statement
coverage per new codec/storage file, with no skipped tests. Existing decoder
regressions still run. The 16 image/carrier journeys additionally carry every
retained compressed case through all four source/destination filesystem variants;
macOS independently mounts every result and compares logical payloads and raw
compression metadata. Linux/Windows image artifacts receive the same native
qualification in the dependent CI job.

This closes the listed storage codecs, not every outer copy lifecycle or every
corrupt image behavior. Full completion continues to require the
[completion matrix](appledouble-completion-matrix.md), including downstream
release gates and independent native host projection qualification.
