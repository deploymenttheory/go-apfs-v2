# Bounded AppleDouble values and sequential restoration

`appledouble.Value` combines `io.ReaderAt` with `Size() int64`. It describes an
immutable value without requiring a byte slice; `bytes.Reader`, `os.File` with a
size adapter, and `io.SectionReader` can supply it. The caller owns the source
lifetime. Indexing and encoding never close a source or change its file position.

Use `DecodeStream(ctx, source, limits)` to index a sidecar. It retains its bounded
header and ordered records, but borrows value spans. It validates all referenced
ranges before returning. Duplicate records and overlapping values remain distinct
references; aliasing does not force payload copies. Later IO can still fail, and
the underlying source must remain open and unchanged until consumers finish.

Use `StreamFile.EncodeTo(ctx, writer, limits)` for lossless canonical encoding.
It validates names, wire widths and budgets before output, sorts a copy of the
record list stably, and copies values through a fixed 64 KiB buffer. It does not
change the caller's record order or apply filesystem normalization. Partial output
can remain after an IO error or cancellation; the returned byte count records
what the writer accepted. A context cannot interrupt a blocked custom IO method.

```go
limits := appledouble.DefaultStreamLimits()
limits.MaxFileBytes = 256 << 20
limits.MaxValueBytes = 128 << 20
limits.MaxTotalValueBytes = 256 << 20
metadata, err := appledouble.DecodeStream(ctx, source, limits)
if err != nil {
    return err
}
_, err = metadata.EncodeTo(ctx, destination, limits)
return err
```

The defaults permit format-width limits; they do not allocate those amounts.
Applications handling untrusted input should choose workload and disk budgets.
Zero means zero permitted bytes, rather than an implicit default. The aggregate
value budget counts aliases once per reference, bounding total copying work.
`ErrStreamBudget` identifies a caller limit; `ErrTooLarge` identifies a format
width or address-space limitation. The existing `File`, `Encode` and `Decode`
contracts remain unchanged.

## Native capture and carrier lifetime

`hostdata.CaptureXattrValuesAt` captures a relative object through a held payload
root without following its final symlink. Ordinary native attributes still need
whole-value reads: their syscalls do not support arbitrary chunked reads. Name,
individual-value and aggregate capture budgets remain explicit, and exceeding a
budget is an error rather than an empty attribute or a skipped value.

Darwin regular-file resource forks use a separate held named stream with 64-bit
offsets. They can exceed the ordinary attribute allocation budget while each read
remains bounded. Linux symlinks use the held-parent no-follow provider, including
dangling links and links whose targets are outside the payload root. This captures
the link namespace, not the target namespace.

Extraction records both its initial native baseline and its post-projection
baseline using these sized values and `StoreAttributeValues`. Projection readback
uses the contained root on every OS, including Linux no-follow symlinks, and
checks identity against the descriptor that received the projection. Failed
readback retains the prior baseline and reports the failure; it never replaces
known host metadata with a fabricated empty namespace. Neither baseline
requires materializing a resource fork. The carrier retains complete logical
values when native projection has a capacity or platform constraint; projection
outcomes remain separate from preservation success. Borrowed sources and stores
must remain open and unchanged until their consumers finish.

AppleDouble's fork length field remains unsigned 32-bit. A larger fork is kept in
the carrier as a raw streamed blob, with its optional AppleDouble representation
omitted. APFS and HFS+ streamed image APIs preserve the full 64-bit length. See
[large resource forks](appledouble-large-values.md) for real-byte boundary tests,
native descriptor qualification, memory and disk budgets, and cross-host CI.

## Explicit sequential execution

`hostdata.RestoreAppleDouble` remains the safe snapshot operation: it decodes the
complete source before changing a destination. `RestoreAppleDoubleSequential`
explicitly selects native source-read/effect order through the same held backend:

1. Allocate/read and validate the base header.
2. Clean the destination's visible namespace.
3. Validate, allocate and read each ATTR record immediately before executing it.
4. Validate/apply FinderInfo after the records.
5. Allocate a fork buffer, capture destination stat, read the fork, then run its
   callbacks and write. Finally apply deferred ACL and optional stat.

A late malformed record or short read can therefore leave earlier cleanup and
writes applied. Native fork failures can be replaced by later ACL/stat return
codes. `UnpackResult.Failures` retains them even when `Code == 0`; neither success
code nor `ReachedEnd` is proof that every value was preserved.

`UnpackSequentialOptions` supplies `StreamLimits` plus `MaxActiveBytes`. The latter
bounds owned header, deferred ACL and value/callback-copy bytes. The backend's
retained allocations are its responsibility. A value is still materialized for
the existing `UnpackBackend` byte-slice contract; this execution API is distinct
from the bounded streaming transport representation. Explicit budget refusal
matches `ErrUnpackValueAllocation` and `ErrStreamBudget`; it does not fabricate a
host `ENOMEM` or deliberately exhaust process memory.

## Qualification

`go run scripts/verify-appledouble-stream.go` runs portable tests, rejects skips
and requires above 95% coverage in each tracked implementation file. It checks
the 44 reviewed native record cases, exact native 300 KiB fixture bytes, stable
duplicates/special records, bounded copying of 20 MiB values and forks, indexing
beyond 4 GiB, aliases, budgets, malformed input, short IO and cancellation.
`FuzzStreamDecode` checks canonical parity without unbounded allocations.

`go run scripts/verify-unpack-sequential.go` preserves the existing unchanged
Apple unpack oracle and adds 34 controlled and 30 live malformed/truncated-source
cases. The live helper independently verifies 60 seed removals and 24 successful
writes. Native traces establish cleanup-before-late-failure, read-before-filtering,
fork-stat-before-read and ACL/stat masking. All OSes replay the archived corpus
and both preceding native unpack profiles. Captures retain complete pinned Apple
source, generated headers, arm64/x86_64 ASTs, commands and source hashes. C is
qualification-only; production remains pure Go.
