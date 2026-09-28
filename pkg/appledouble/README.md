# Shared AppleDouble codec

This pure-Go package owns AppleDouble byte encoding and decoding for the APFS
SDK, package tooling and future metadata transport consumers. It has no filesystem,
CGo or subprocess dependency. Filesystem reads/writes, native attributes, sidecar
naming conflicts and extraction/packing policy belong in `pkg/hostmeta`, not here.

The implementation and its existing tests were relocated from
[`go-macos-pkg` v0.7.2](https://github.com/deploymenttheory/go-macos-pkg/tree/6785561c02967366e61327607abc7594a3e8ffe3/pkg/appledouble).
The MIT license is retained in this directory. The old package will delegate to
this package with type aliases and forwarding functions; it will not keep a second
codec. APFS must not depend on the package-tooling module.

## Relocation provenance

Source revision: `6785561c02967366e61327607abc7594a3e8ffe3`.

| Original file | SHA-256 |
| --- | --- |
| `pkg/appledouble/appledouble.go` | `fadfc6ad2f0385f792bf23c8d0d5b06c8f449813901be322fbf379bc348ac9b2` |
| `pkg/appledouble/appledouble_test.go` | `5e005e7e4b5b95b0d26e3b5f18de0b06974211323ae722f6bb69de3793efc690` |
| `pkg/appledouble/bomb_test.go` | `f0afaa3bee7f34b31dbb6c4839493cc94381f6477d90b672970988fdec0c5aa0` |
| `pkg/appledouble/padname_test.go` | `5250edac0eb7f91837d3b9abd6dd0037885ac24cdb85a05fbfbefae172d2f3b4` |
| `testdata/cli/component-links.probe.json` | `450b5a23661072a6de625c55e37de0af2602253f1ab71b063e889fbb71985865` |

Production logic was unchanged in the relocation. Its only source edits explicitly
acknowledge the ignored errors from writing fixed-width integers into a
`bytes.Buffer` (`_ = binary.Write`), to satisfy this repository's linter. The
native fixture is copied byte for byte and its absence now fails tests rather
than skipping them. Additional boundary tests exercise existing behavior.

The fixture came from the package project's `scripts/gen-fixtures.sh` and
`scripts/decode-payload.py`: Apple's `pkgbuild` produced `component-links.pkg`,
then the probe retained the complete sidecar bytes. These are archived native
observations; the relocation does not claim a fresh full native compatibility run.

Run `go run scripts/verify-appledouble.go` from the repository root. CI runs this
on Linux, macOS and Windows, fails on any skipped codec test or unit coverage at
or below 95%, and retains raw events, coverage and source hashes. `FuzzDecode`
checks parsing bounds and encoded-output readability in the existing fuzz matrix.

## Native size and empty-value correction

The encoder now separates the entry table from value storage: `MaxHeader` is
65,554 bytes (copyfile's buffer), with a largest aligned table of 65,552 bytes.
Values do not count against this limit. Wire offsets/lengths and the host's `int`
range are checked before allocation. Empty attribute records use native zero
offsets and remain present when decoded.

The [native size investigation](../../docs/appledouble-native-sizes.md) records
pinned source, Clang AST/layout evidence, the portable native fixture and live
pack/unpack checks. The codec is still pure Go on every platform; the native
harness is a test oracle only.

## Behavior still requiring native investigation

The size correction does not establish full native parity. Outstanding items:

- Native copyfile packing replaces an ordinary value above 16 MiB with an empty
  value on the observed host. The byte codec permits values within its wire/address-space
  bounds and never silently discards them. Define and validate packing-policy
  behavior separately, including oversized aggregates and resource forks.
- Reserved special-attribute names still require investigation.
  Ordinary UTF-8 byte limits,
  NUL termination and padded records are covered by the native name fixtures; see
  [name validation](../../docs/appledouble-native-names.md).
- FinderInfo now requires exactly 32 bytes; invalid constructor input is retained
  until Encode reports an error. Zero FinderInfo, absent/empty forks and ordered
  fork writes are covered by [native special-attribute probes](../../docs/appledouble-native-special.md).
  [ACL text parsing and portable external bytes](../../docs/appledouble-native-acl.md)
  are available through an explicit pure-Go policy API. ACL application/formatting,
  quarantine handling, associated file flags and destination-type policy remain
  outstanding. The codec retains serialized policy records for consumers.
- Decode now follows the native two-entry profile, fixed ATTR position, duplicate
  name ordering and overlap/read-bound behavior; see
  [record validation](../../docs/appledouble-native-records.md). It no longer
  accepts arbitrary tables or an unaligned ATTR fallback. Unused summary sizes
  do not constrain actual reads. General reserved-field policy and special-name
  handling are not established by these record fixtures.
- Establish integer/aggregate allocation limits for large forks and attribute
  sets, including 32-bit builds. Retain the existing alias-amplification guards.

The [migration and validation plan](../../docs/appledouble-migration.md) records
the release gate and the later host-transport work.
