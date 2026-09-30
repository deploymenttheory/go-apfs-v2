# Security source acquisition

`hostdata.CaptureSecuritySource` implements fresh descriptor-style source
acquisition before ordinary security copying. It preserves the distinction
between optional filesec properties, independent stat fields, and read failures.
`CopySecurityFrom` connects acquisition to copying on Linux, macOS and Windows.
Both image writers expose the same operation and use the existing graph,
hard-link and staged-publication implementation.

Use `hostdata.ImageSecurityCapture(sourceVolume, name)` to bind an APFS/HFS+
reader directly to either writer:

```go
capture := hostdata.ImageSecurityCapture(sourceVolume, "Payload/file")
result, err := root.CopySecurityFrom(target, capture, hostdata.SecurityCopyOptions{
    ACL: true,
    Stat: true,
})
```

Check `err`, `result.Capture.Failures`, `result.Copy.VolumeQueries` and
`result.Copy.Failures` before claiming preservation. `result.Copy.Completed`
means staged for an image writer; serialization can still fail. Native-compatible
sequence completion alone is not proof that every field was observed or written.

## Capture and fallback contract

`SecuritySourceCapture` binds two callbacks to the same held source or immutable
foreign object. The coordinator does not open a path, consult the host's identity
database, or translate Linux POSIX ACLs/Windows DACLs into Darwin ACLs.

1. `ReadSecurity` returns the stat/filesec state left by the extended read,
   including partial state on failure. The coordinator validates and owns a
   snapshot before invoking another callback.
2. Only errors classified with `ErrSecuritySourceNotPermitted` or
   `ErrSecuritySourceNotSupported` permit plain-stat fallback. Providers should
   join the classification with the original cause. They represent Darwin's
   **EPERM and ENOTSUP**, respectively; EACCES and generic permission failures
   must not be classified as EPERM.
3. `ReadStat` receives the previous stat state and returns the state left by the
   fallback, including on error. Apple ignores this error. The Go coordinator
   retains it and checks the resulting file type, just as the native sequence does.
4. Only regular files, directories and symlinks pass the source-type gate.
   Unknown, FIFO, device and socket modes return `ErrSecuritySourceType`.
5. The acquired source enters ordinary security copying only after successful
   completion of this gate. Target ACL capture and volume queries occur later.

A failed fallback can leave a previously captured supported type and allow
execution to continue. It can also leave zero/unsupported type and cause refusal.
These states remain distinct. Fallback stat fields never fill omitted filesec
properties: the separate values have different roles in later writes/fallbacks.

`SecuritySourceResult` contains:

| Field | Meaning |
| --- | --- |
| `Source` | Owned acquisition cache, available for diagnostics on read/type errors when validation succeeded |
| `Completed` | The native acquisition/type-gate sequence completed; does not imply a fully observed ACL |
| `Fallback` | A classified extended-read error selected plain-stat fallback |
| `Failures` | Original extended/stat read errors in order, including ignored failures |

Missing callbacks fail when needed. Invalid source operation properties (such
as ACL removal) fail validation. No requested ACL/stat stage is a completed no-op
with no source reads. Fatal acquisition errors prevent destination capture,
policy queries and writes. On image writers, invalid trees/aliases are rejected
before source reads, and staged changes are published only after copy success.

`SecuritySourceCopyResult.Capture.Source` retains pre-selection properties.
`Copy.Source` owns the ordinary copy's selected ACL cache. Callback/request
mutation cannot make the two caches alias each other.

## Image binding

`ImageSecurityReader` is implemented by APFS and HFS+ volumes.
`ImageSecurityCapture` delegates to their existing bounded `Security(name)`
readers. Names follow `fs.ValidPath`; final symlinks are not followed. Roots,
resolved hard links, numeric zero fields and ignored malformed storage retain
the readers' existing statx-compatible behavior. The image must remain immutable.
Only security metadata is read; unrelated payload/fork streams are not loaded.

Reader I/O and lookup errors remain errors. Image readers do not classify them
for native plain-stat fallback. Raw stored bytes and `SecurityRecordDisposition`
remain available through the original reader APIs; acquisition does not redefine
ignored malformed storage as a new format or repair it.

## Native qualification

Run `go run scripts/verify-security-source.go` on macOS. The helper compiles the
**complete unchanged `fcopyfile` function**, alongside unchanged
`copyfile_security` and its existing request instrumentation, from pinned Apple
[copyfile](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c)
(SHA-256 `19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`).
It reuses unchanged `chmodx1` from pinned
[Libc](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/sys/chmodx_np.c)
(SHA-256 `31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff`).

The generated shared test helper adds only the internal state's `err` field
needed by `fcopyfile`; the repository's shared helper and Apple function bodies
stay unchanged. Reports retain original hashes, generated headers, complete
arm64/x86_64 Clang ASTs, command inputs/outputs, observations and revision.

The oracle explicitly isolates this scope: preamble supplies a fresh state,
quarantine is a no-op, and `copyfile_internal` invokes only ordinary security
copying. Native `fcopyfile` still executes its destination stat/temporary-mode
wrapper. Go request replay uses that same wrapper. This is **not qualification
of the entire copyfile lifecycle**, cached-state reuse or path opening.
The reused volume shim supplies precaptured negative mount policy; the separate
[volume-policy oracle](appledouble-security-copy-volume.md) qualifies actual
source/destination mount queries and their failures.

- **2,160 controlled cases** cover three selected stages, six source type
  patterns, successful/EPERM/ENOTSUP/EACCES/EIO extended reads, successful and
  failed stat fallbacks with retained/zeroed state, sparse/full properties and
  four source/destination ACL pairs. Injected read failures measure native
  decisions; they are not claims that real filesystems produced those errors.
- **108 actual native/Go pairs** cover files, directories and held symlinks;
  zero, ordinary and set-ID modes; three stages and four ACL pairs. Extended
  reads use real `fstatx_np`; requests use real native writes and metadata
  readback. Source metadata, inode identity, payloads and BSD flags are checked.
- Zero-mode directory payloads use descriptors held before permission changes.
  Darwin denies `readlink` on unreadable symlinks: after all metadata observations,
  the harness grants read access on the held link solely to check its payload.
  `PayloadPermissionCleanups` records this cleanup explicitly. It is not a copy
  operation or part of the metadata comparison.
- All **16 image source/destination combinations** use APFS, case-sensitive
  APFS, HFSX and HFS+. Each performs **361 acquisitions**, including roots,
  files/directories/symlinks, regular aliases, actor/zero/foreign ownership and
  valid/ignored security-storage profiles. Serialized output must match the
  existing manually captured path byte for byte; source image hashes stay fixed.

`go run scripts/verify-security-source-coverage.go` replays the corpus and image
integration on every OS, rejects focused skips and independently requires more
than 95% coverage for each new production file. CI publishes coverage/source
hashes on Linux/macOS/Windows and the native oracle artifact on macOS. Existing
codec, policy, image and layout gates continue to run.

## Remaining work

The shared acquisition coordinator and image bindings are implemented. Live host
read/write and volume providers, foreign carriers, authorization/sandbox contexts,
path opening and cached copyfile-state reuse remain separate work. Bind those
adapters into creation inheritance, ordinary copying, stat/flags/times/xattrs,
deferred AppleDouble replacement and cleanup before claiming full restoration.

All five roadmap gates remain open. Package PR72 stays draft on the published
dependency until APFS qualification and release; codesign remains paused.
