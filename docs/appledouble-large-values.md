# Large resource forks and streamed metadata

Image metadata can be much larger than an ordinary native extended attribute.
The carrier and image APIs use `appledouble.Value`, a sized `io.ReaderAt`, so a
resource fork can move between APFS, HFS+, Linux and Windows without allocating
its complete contents. Owners remain open and values remain immutable throughout
capture, publication and image creation.

The extraction baseline uses `CaptureXattrValuesAt` against the held payload
root and publishes its values through `StoreAttributeValues`. This applies both
before optional native projection and after projection. Ordinary native attributes
still obey the caller's name, individual-value and aggregate allocation limits.
Darwin regular-file resource forks use a held native stream and do not consume a
whole-value allocation budget. Linux link capture uses the documented held-parent
no-follow provider. A failed capture never becomes an empty baseline.

## Format bounds and preservation

AppleDouble stores a resource-fork entry length in an unsigned 32-bit field. A
fork of 4,294,967,313 bytes exceeds that field. `StreamFile.EncodeTo` rejects it
before publishing a header or payload. The carrier retains the complete raw blob
and omits the unrepresentable optional AppleDouble representation. APFS and HFS+
retain the exact 64-bit fork length and bytes through their streamed writer and
reader APIs. This is a format boundary, not permission to drop metadata on a host.

The fast tests use a reader that defines every byte, including nonzero markers on
both sides of the 32-bit boundary. They test the largest legal AppleDouble fork
length, absolute wire offsets beyond 32 bits, exact final-span reads, cancellation
and rejection before output. They do not substitute a reported size for undefined
payload bytes.

## Real-byte qualification

Run `go run scripts/verify-large-resource-fork.go`. It consumes a complete
4 GiB + 17 byte source, publishes a real carrier blob, and reconstructs both an
APFS and an HFS+ image. Every stage checks the full SHA-256 and boundary markers;
this is not sampling-only verification. The logical source supplies fixed modes,
numeric ownership and four timestamps so images are reproducible across hosts.

On macOS, the harness mounts both images and reads each complete resource fork
through an independently compiled C oracle. The oracle uses `openat` relative to
the held data-file descriptor, 64-bit offsets and CommonCrypto SHA-256. It also
creates a native fork across the boundary, qualifies Go's held capture, and checks
a full Go replacement after the data-file pathname is replaced. The replacement
must affect the original held object. Source and SDK-header hashes, compiler/SDK
versions, and Clang ASTs for arm64 and x86_64 accompany the results.

`-foreign <artifact-directory> -foreign-goos linux|windows` mounts images produced
on another host and verifies the full native fork. Add `-reference <mac-artifacts>`
to require byte-identical image hashes against the matching native run. Foreign
revision, source hashes, image inventory, image length, complete image hash and
complete fork hash must all agree. Reports are never rewritten to accommodate a
host difference.

The harness needs about 9 GiB of free workspace. It keeps at most one 4 GiB + 17
byte carrier and one 4.125 GiB image at a time, or one native fork after carrier
cleanup. Native resource-fork truncation can allocate the entire length; sparse
allocation is not assumed. Raw images live in a temporary workspace and are
removed. Retained gzip images are capped at 64 MiB each. Go's memory soft limit is
256 MiB; the report includes a sampled heap high-water mark and fails above
512 MiB. These observations supplement the explicit 64 KiB source/copy buffers;
the sampled measurement is not a guarantee about an unsampled transient peak.
Disk exhaustion, native refusal, failed cleanup, changed values, short I/O and
mismatched hashes are failures, not skips.

The report and compressed images live under `artifacts/large-resource-fork` by
default (`-out` changes the location). The dedicated
[`large-resource-fork.yml`](../.github/workflows/large-resource-fork.yml) workflow
runs the complete harness on Linux, Windows and macOS with a 45-minute timeout
per job. Each job requires 9 GiB free on the volume containing its explicit
temporary workspace; insufficient space fails the job. Separate macOS jobs read
the Linux and Windows images against the native reference, with matching source
hashes and complete image hashes required. All jobs upload available logs and
evidence even after a failure. The workflow does not replace the existing unit,
coverage, acceptance or native qualification gates.
