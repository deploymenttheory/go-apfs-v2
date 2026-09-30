# Metadata carrier qualification

An explicitly selected metadata carrier lets extraction preserve Darwin file
metadata even when the destination filesystem cannot represent it natively.
The payload directory contains ordinary file contents. A separately selected
carrier stores logical names, attribute blobs, timestamps, ownership, modes,
flags and link relationships. Existing files beginning with `._` remain content;
selecting a carrier does not authorize treating arbitrary user files as metadata.

The production path is `Extractor.MetadataRoot` followed by the APFS or HFS+
writer's `WalkOptions.MetadataRoot`. Both ends must explicitly select the carrier.
Image readers supply `Metadata(name)` for numeric inode properties and four times;
`XattrValues` supplies borrowed raw attribute and security readers. Inode IDs establish aliases
within one immutable source volume, never across different volumes.

This is preservation, not native permission enforcement on Linux or Windows.
A carrier can retain an empty Darwin attribute or a large resource fork when the
host's native xattr/EA namespace cannot. The host projection is a separate concern.
`OpenEntryTreeFromDir` keeps payload and carrier readers open through image creation;
callers must close the resulting tree afterwards. APFS and HFS writers borrow
`DataValue` and `XattrValues`; HFS also borrows `ResourceForkValue`. Large forks
and attributes stream in bounded chunks, while small inline values use bounded
copies. Supplying both eager bytes and a borrowed source for the same value is an
error. Borrowed readers must remain open and immutable until writing completes.
The legacy `Xattrs` convenience API still materializes complete values.

## Complete image journeys

Run the qualification from the repository root:

```sh
CGO_ENABLED=0 go run scripts/verify-metadata-transport.go
```

The script creates APFS, case-sensitive APFS, HFS+ and HFSX source images. It
extracts each through the production carrier and repacks each into all four
formats using the borrowed-reader API: sixteen journeys per operating system.
No filesystem pair is skipped.
Every result must preserve payload bytes, logical attribute names/bytes,
ownership, Unix type/permissions, BSD flags, independent timestamps, link targets
and hard-link relationships. Distinct source files must remain distinct inodes.
HFS timestamps are compared at their actual whole-second precision.

Fixtures include root/directory metadata, real `._` content, Windows-reserved and
colliding materialized names, Unicode, empty/binary/case-distinct attributes,
FinderInfo, ACL/security and quarantine storage, an ordinary value above 16 MiB,
a resource fork above 16 MiB, and symlinks materialized as portable files. Their
logical symlink targets must reconstruct correctly on every destination format.
APFS's internal `com.apple.fs.symlink` storage is checked through link-target
semantics; the native kernel does not expose it as an ordinary xattr.

Every journey also carries the 14 retained native compression storage cases,
covering raw, LZBITMAP, empty/boundary type 1 and independent resource forks.
The [compression storage contract](appledouble-compression-storage.md) describes
their native source evidence and bounds. Both byte and borrowed image APIs retain
compressed metadata while presenting decompressed content through file reads.

The test distinguishes source metadata from attributes the host creates while
materializing payloads. An unchanged extraction must not introduce host-generated
metadata into the reconstructed image. Changes to native attributes require an
explicit, tested reconciliation contract; filtering a familiar name such as
`com.apple.provenance` would hide that problem.

## Independent macOS validation

On macOS the script additionally builds the C oracle in
`testdata/appledouble/native/metadata-transport.c` against the host libSystem.
It retains arm64/x86_64 Clang ASTs and checks the actual reference counts for
`lstat`, `lstatx_np`, `getxattr` and `filesec_get_property`. Compiler, SDK, relevant
SDK header hashes, source hashes and the exact checkout revision accompany the
observations. AST compilation for an architecture is not runtime qualification
on that architecture.

Every source and output image receives native filesystem validation and a
read-only `hdiutil` mount with ownership enabled. Native no-follow stat values,
file contents, symlink targets and full xattr reads are compared independently.
Protected security storage is observed through `lstatx_np`/filesec and converted
from Darwin memory byte order before comparing the complete record. Large
attribute reads retain their length and SHA-256; compressed images retain the
underlying complete values for replay. The test's C allocation bound is 64 MiB,
which is a qualification-fixture bound, not a claimed format limit.

The HFS FinderInfo prerequisite has a separate 80-case native matrix: files,
directories, symlinks, hard links and roots on both HFS variants, including zero,
private fields, invisibility/explicit flag precedence and rejected lengths/types.
The oracle first writes FinderInfo with native `setxattr` and observes native
results, then independently mounts the Go-produced equivalent. Apple HFS commit
`d1bac2f062e6e9c0dfcce302d9aacb10173d0eea` supplies the unchanged
`hfs_zero_hidden_fields` function and Finder extension structures. Full upstream
files, their SHA-256 hashes, extracted source, both ASTs and the explicitly
disclosed mode-only `cnode` shim accompany these observations.

HFS FinderInfo resides in the catalog, with native private-field normalization.
An attribute-tree value disagreeing with that catalog is an explicit logical
transport conflict; equal duplicates coalesce. That conflict is a library
preservation decision, not a claim that native `getxattr` reports that error.
Raw lower-level attribute inspection remains available. Invalid UTF-8 names and
names exceeding HFS's 127 UTF-16-unit attribute-key limit fail explicitly.
The existing pinned Apple-function and native codec/policy experiments continue
as separate mandatory gates.

## Foreign-host proof and artifacts

The dedicated CI workflow runs all sixteen journeys on Linux, macOS and Windows.
It uploads the complete gzip-compressed output images plus metadata observations,
image hashes and provenance. A dependent macOS job downloads Linux and Windows
outputs, requires the same revision and source contents, checks their image hashes
against the native Mac run, and independently mounts and reads all 32 images.
Source validation requires exact byte hashes; .gitattributes pins LF checkouts on all operating systems. Case inventories must be complete and unique.

For a local replay of downloaded CI artifacts:

```sh
go run scripts/verify-metadata-transport.go \
  -foreign artifacts/foreign/metadata-transport-linux \
  -foreign-goos linux \
  -reference artifacts/foreign/metadata-transport-darwin \
  -out artifacts/metadata-transport-linux-native
```

`report.json` retains the sixteen results and all native command observations.
Incomplete output after a failure is diagnostic evidence, not a successful
qualification. The workflow fails on mismatched metadata, missing cases,
wrong revisions, hash mismatches, unreadable values and native tool failures.
The existing HFS gate's explicit clean-volume verdict rule is retained for the
ordinary-user raw-device permission behavior.

## What this does not close

The [completion matrix](appledouble-completion-matrix.md) remains authoritative.
These image journeys do not establish every outer native restoration lifecycle,
privileged/sandbox authorization context, quarantine process state, native host
projection, cancellation/late-write failure, allocation boundary or special-object
behavior. Those retain their own implementation and qualification requirements.
All existing codec, native C, coverage, fuzz, race, vendor-DMG and downstream
release gates remain required. Package PR72 remains draft pending completion,
release and downstream adoption; codesign remains paused.
