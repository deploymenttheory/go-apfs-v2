# Owned compression inputs and volume context

Use these `hostdata` APIs when a macOS operation must acquire a new writable file
inside an existing namespace boundary and then run the shared compression
lifecycle. They let a consumer retain `os.Root` containment without copying the
SDK's native metadata, resource-fork or compression implementation.

```go
result, err := hostdata.Recompress(ctx, func(ctx context.Context) (hostdata.CompressionInput, error) {
    file, err := root.OpenFile(name, os.O_RDWR, 0)
    if err != nil {
        return nil, err
    }
    owned, err := hostdata.NewNativeCompressionInput(ctx, file)
    if err != nil {
        return nil, errors.Join(err, file.Close())
    }
    return owned, nil
}, hostdata.RecompressionOptions{
    Name: filepath.Base(name),
    Encoding: encoding,
    NewStage: newPrivateStage,
})
```

The caller acquires a fresh `O_RDWR` file. That acquisition can decompress active
storage or fail authorization before this constructor runs. Binding makes no
native calls: it does not open, stat, duplicate, seek, truncate or check access
mode. Successful binding transfers ownership to the compression input; failed
binding leaves the file with its caller. `Recompress` retains its existing
admission-stat, eligibility, restoration-stat, zero-byte-write, duplicate,
resource-fork, volume, staging, installation and cleanup checkpoints. A closed or
readonly descriptor consequently fails at the same operational checkpoint instead
of being reclassified as a binding failure.

Never reuse a previously authorized replacement writer to avoid a fresh native
write-open. Doing so bypasses post-replacement permissions and compression
acquisition effects. Native `openat` supplies a descriptor-relative starting point;
Go's `os.Root` additionally prevents namespace escape. These are distinct contracts.
An open root survives directory renames; held inputs survive subsequent leaf
renames. Callers still exclude unrelated mutations for the operation's lifetime.

`QueryCompressionVolume(ctx, file)` obtains the filesystem name and raw Darwin
mount flags in one descriptor-bound observation. It preserves observed zero flags
and unknown filesystem names. `CompressionVolumeFlags` remains available through
the same native observation. Retain this context with foreign metadata rather than
inferring flags from an APFS label, a filename or the receiving operating system.

`OpenResourceForkContext` carries cancellation through version selection and
native acquisition. Its compatibility wrapper, `OpenResourceFork`, remains
available. The SDK uses held-path resolution with inode validation on macOS 15,
and descriptor-relative acquisition on macOS 26/27. This SDK strategy is separate
from AppleFSCompression framework traces that can use different native entry
points. The macOS 15 route cannot reopen an unlinked fork and does not provide an
atomic namespace snapshot. No version fallback silently selects the newest route.

Cancellation checks occur before and between native calls; one kernel call cannot
be made retrospectively interruptible. An acquired fork is closed if cancellation
is observed after acquisition. Cleanup ignores cancellation and preserves errors.
A completed native open may already have created a fork or decompressed storage;
cancellation does not claim to undo it.

Linux and Windows use explicit foreign metadata through
[`recompression`](../pkg/recompression/README.md), with complete portable codecs,
credentials, target macOS version and volume context. These native Darwin handle
bindings never reinterpret receiving-host permission or filesystem flag bits.

## Qualification

The owned-input capture compiles an independent C oracle against the host SDK and
retains both arm64 and x86_64 Clang ASTs, compiler/SDK details and source/binary
hashes. It records 72 plain, active and inactive compression cases across host,
APFS and HFS+ volumes, including direct/root-relative acquisition and root/leaf
rename timing. Every capture runs the public Go binding against those observations
on each still-mounted volume, checking full data, raw attributes, filesystem name,
mount flags and unchanged binding state. Separate tests cover context, ownership,
closed/readonly handles and `os.Root` escape rejection.

CI requires genuine macOS 15/26/27 retained baselines, fresh recapture, and complete
hostdata plus every changed binding file above 95% coverage. Missing baselines fail
after fresh artifacts are retained; they are not treated as successful comparison.
Existing codec, carrier, 4 GiB, native permissions and commercial-image gates remain
mandatory. These primitives do not implement codesign option applicability,
post-rename scheduling, representation-specific alias handling or error mapping.
