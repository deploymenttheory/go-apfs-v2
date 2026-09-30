# Vendor DMG acceptance fixtures

Published application images exercise layouts and bundles that our generated
fixtures do not choose. CI retains Firefox and Zed and appends two commercial
applications: Charles and BBEdit. All four run the same portable CLI acceptance
suite on Linux, macOS and Windows with CGO disabled.

| Image | Filesystem | Additional observed coverage |
| --- | --- | --- |
| Firefox 150.0, en-GB | HFS+ | Existing large browser bundle |
| Zed 0.196.5, aarch64 | APFS | Existing editor bundle |
| Charles 5.2.1 | HFS+ | UDBZ/bzip2, Apple Partition Map, bundled Java runtime, 134 regular files and one symlink |
| BBEdit 16.0.3 | APFS | ULFO/LZFSE, GPT, binary Info.plist, framework links, 933 regular files and 14 symlinks |

The new images' filesystems, compression and partition maps were inspected with
macOS `hdiutil imageinfo`; our `info` command independently reports HFS+ and APFS.
Versioned vendor URLs and SHA-256 checks prevent silently changing the new test
inputs. CI also asserts the expected filesystem for all four images.

## Sources and integrity

Download directly from the vendors. Images are cached in `.acceptance-cache/`,
not committed or uploaded as test artifacts. Tests read/extract application
contents without installing or launching the applications.

| Image | Pinned download |
| --- | --- |
| Firefox | [Mozilla release archive](https://ftp.mozilla.org/pub/firefox/releases/150.0/mac/en-GB/Firefox%20150.0.dmg) |
| Zed | [Zed release asset](https://github.com/zed-industries/zed/releases/download/v0.196.5/Zed-aarch64.dmg) |
| Charles | [Charles 5.2.1](https://www.charlesproxy.com/assets/release/5.2.1/charles-proxy-5.2.1.dmg) |
| BBEdit | [BBEdit 16.0.3](https://s3.amazonaws.com/BBSW-download/BBEdit_16.0.3.dmg) |

Charles SHA-256:
`d233395a7fbb487f0fe20ddff16e02a65990add20d5aa9ce1e87a8f9ff0fe0d5`

BBEdit SHA-256:
`acf2ae9e5c68beacdfd7534861fa8c992e1bdd5391a71b3c08b3ed879c2b3572`

Both hashes were calculated from downloaded bytes and agree with the respective
Homebrew cask checksums at selection. Firefox and Zed retain their existing
version pins; their existing jobs do not enforce SHA-256 pins.

## Assertions and evidence

Every platform checks volume identity, nonempty contents, recursive listing
against superblock counts, application and bundle identity, Mach-O executable
magic, whole-volume extraction with source checksum verification, and repacking.
Repacking must preserve the entire raw disk image byte-for-byte and reproduce
the extracted regular-file manifest, including its count. Traversal, read and
extraction errors fail the comparison instead of silently omitting files.

macOS additionally mounts each original image read-only and compares every
regular file's SHA-256 against the Go extraction. Linux and Windows run every
portable assertion; only the independent `hdiutil` comparison requires macOS.
New-image JSON test logs are uploaded as `vendor-dmg-<runner>` artifacts and
observations appear in the GitHub Actions summary.

These tests broaden real-world container, filesystem and file-content coverage.
They do not claim complete AppleDouble restoration or native xattr/ACL/resource
fork equivalence: those remain governed by the focused metadata suites and the
[AppleDouble roadmap](../pkg/appledouble/README.md).

## Run a new fixture locally

For BBEdit, after downloading the pinned image:

```sh
CGO_ENABLED=0 \
APFS_ACCEPTANCE_DMG="$PWD/.acceptance-cache/BBEdit.dmg" \
APFS_ACCEPTANCE_VOLNAME='BBEdit 16.0.3' \
APFS_ACCEPTANCE_APP=BBEdit.app \
APFS_ACCEPTANCE_BUNDLE_ID=com.barebones.bbedit \
APFS_ACCEPTANCE_BINARY=BBEdit \
APFS_ACCEPTANCE_FILESYSTEM=apfs \
APFS_ACCEPTANCE_SHA256=acf2ae9e5c68beacdfd7534861fa8c992e1bdd5391a71b3c08b3ed879c2b3572 \
go test -v -count=1 -run TestAcceptance ./acceptance/
```

For Charles, use `Charles.dmg`, volume `Charles Proxy v5.2.1`, app
`Charles.app`, bundle ID `com.xk72.Charles`, executable `Charles`, filesystem
`hfs+`, and its SHA-256 above. PowerShell users can set the same names with
`$env:NAME = 'value'` before invoking `go test`.

When changing a pin, verify the actual disk format again, calculate and review
its checksum, run the native comparison, update this document and the cache key,
and require all three CI platforms to pass. Do not substitute a latest-download
redirect or remove a failing platform from the matrix.
