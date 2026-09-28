# AppleDouble codec and ACL interpretation

`pkg/appledouble` provides pure-Go encoding and decoding of macOS AppleDouble
sidecars, plus explicit parsing of their serialized ACL records. The same
implementation runs on Linux, macOS and Windows with `CGO_ENABLED=0`. Production
code does not call macOS tools, use cgo or access a host account database.

This page describes **main through merged PR #140**. The relocation was released
in [v0.13.0](https://github.com/deploymenttheory/go-apfs-v2/releases/tag/v0.13.0);
the later native compatibility corrections and ACL API described below are
merged on main and are not part of that release. The latest qualification for
[PR #140](https://github.com/deploymenttheory/go-apfs-v2/pull/140) measured **98.8%
AppleDouble unit coverage on all three operating systems**, with 248 passing test
records and zero skips per OS. This is evidence for the implemented cases, not a
claim of complete native parity.

## Implemented behavior

| Area | Current behavior | Native evidence |
| --- | --- | --- |
| Sidecar bytes | `File`, `Attr`, `FromXattrs`, `Encode`, `Decode` and `Xattrs` carry FinderInfo, resource forks and ordered ATTR records. Encoding is deterministic; duplicate names retain their relative order. | [Record validation](../../docs/appledouble-native-records.md) |
| Header and value sizes | `MaxHeader` is 65,554 bytes, with a largest aligned table of 65,552 bytes. Values are bounded separately by wire fields and address space. Empty ordinary attributes remain present and encode with zero offsets. | [Sizes and empty values](../../docs/appledouble-native-sizes.md) |
| Attribute names | Logical names contain 1–127 UTF-8 bytes. Decoding handles the terminating NUL and declared padding separately; canonical encoding removes padding. | [Name validation](../../docs/appledouble-native-names.md) |
| Record selection and bounds | Decoding follows the native two-entry profile and fixed ATTR position. Actual reads are checked even when summary fields disagree. Overlaps and duplicates follow the measured rules, subject to the allocation guard below. | [Record validation](../../docs/appledouble-native-records.md) |
| FinderInfo | Exactly 32 bytes are required. Invalid constructor input is retained until `Encode` reports an error. Zero/absent values and dedicated-slot precedence follow the measured native behavior. | [Special attributes](../../docs/appledouble-native-special.md) |
| Resource forks | Ordered writes replace a prefix without truncating the existing suffix. Empty writes do nothing. The codec can carry fork bytes regardless of the destination OS or object type. | [Special attributes](../../docs/appledouble-native-special.md) |
| ACL interpretation | `ParseACLText` handles the native text dialect, including its observed quirks and 128-entry limit. `ACL.MarshalBinary` emits portable big-endian `acl_copy_ext` bytes. | [ACL interpretation](../../docs/appledouble-native-acl.md) |
| Sidecar names | `IsSidecarName`, `SidecarName` and `OwnerName` provide lexical naming helpers. They do not establish filesystem ownership or resolve carrier conflicts. | [Migration and transport plan](../../docs/appledouble-migration.md) |

`Sniff` is a format hint, not full validation; use `Decode` to validate a sidecar.
`Decode` retains ordered wire records in `File.Attrs`. `Xattrs` computes ordinary
last-write values and FinderInfo/resource-fork semantics. It preserves other
reserved payloads, including ACL and quarantine records, without applying them.
`Empty` describes stored content, not whether every record produces a visible
native xattr. Check `Encode` errors even after constructing data with `FromXattrs`.

Canonical re-encoding of padded or noncanonical inputs need not reproduce their
original bytes. Native-produced cases with byte-equality guarantees and
noncanonical cases with semantic comparisons are identified in the evidence docs.

## Usage

```go
package main

import (
    "fmt"

    "github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func main() {
    metadata := appledouble.FromXattrs(map[string][]byte{
        "com.example.note": []byte("hello"),
        "com.example.empty": {}, // Present and empty, rather than absent.
    })
    wire, err := metadata.Encode()
    if err != nil {
        panic(err)
    }
    decoded, err := appledouble.Decode(wire)
    if err != nil {
        panic(err)
    }
    attrs := decoded.Xattrs()
    _, emptyPresent := attrs["com.example.empty"]
    fmt.Printf("note=%s empty-present=%t\n", attrs["com.example.note"], emptyPresent)

    // Explicit UUIDs need no source identity resolver on any operating system.
    text := []byte("!#acl 1\nuser:01234567-89AB-CDEF-0123-456789ABCDEF:::allow:read\n")
    acl, err := appledouble.ParseACLText(text, nil)
    if err != nil {
        panic(err)
    }
    external, err := acl.MarshalBinary()
    if err != nil {
        panic(err)
    }
    fmt.Printf("ACL entries=%d external-bytes=%d\n", len(acl.Entries), len(external))
}
```

Output:

```text
note=hello empty-present=true
ACL entries=1 external-bytes=68
```

For name/UID/GID-only ACL entries, provide an `ACLResolver` backed by **source
identity information**. A missing resolver returns `ErrACLResolver`; the package
does not consult the receiving host's users or groups. A source lookup with no
matching account returns a zero UUID and nil error, matching native parsing;
lookup failures return an error. Explicit UUIDs take precedence over names and
IDs. See the [ACL contract](../../docs/appledouble-native-acl.md) for details.

The external ACL bytes have a 44-byte header and 24 bytes per entry. Owner/group
header UUIDs are zero, as in `acl_copy_ext`. This is not a complete ownership or
filesystem security record, and producing it does not change filesystem access.
Raw ACL text remains available through the normal codec API even when the policy
parser rejects it.

## Validation and reproduction

Run portable unit tests and the coverage gate from the repository root:

```sh
go test ./pkg/appledouble
go run scripts/verify-appledouble.go
```

The verification script disables cgo, fails on any skipped codec test or coverage
at or below 95%, and records unit events, coverage, revision and source hashes in
`artifacts/appledouble/`. CI runs it on Linux, macOS and Windows; Linux also
executes 386 regressions. Both `FuzzDecode` and `FuzzACLText` run in the fuzz
workflow. Coverage is measured from portable unit tests independently of native
acceptance checks.

On macOS, run the independent native oracles:

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble-native.go
CGO_ENABLED=0 go run scripts/verify-appledouble-acl.go
```

These test-only harnesses use Clang and public libSystem APIs. They retain pinned
Apple source, host/compiler/SDK identity, Clang AST/layout evidence, raw inputs,
sidecars, readbacks and diagnostics in `artifacts/appledouble-native/` and
`artifacts/appledouble-acl/`. CI uploads all three artifact groups.

The current evidence includes:

- Native size checks through 16 MiB, a 300 KiB portable fixture and a maximum-table
  native consumer check.
- 14 name cases and 44 record-selection/read-bound cases.
- 30 special-attribute producer/setter probes and 25 wire-consumer probes. Four
  wire probes are explicitly unresolved ACL/quarantine policy observations;
  they are not counted as completed policy parity.
- 59 native ACL parser cases: 48 accepted and 11 rejected, with exact external
  bytes. File and directory checks exercise native pack → Go interpretation and
  Go encode → native unpack, then compare the actual destination ACLs.

The copyfile AST evidence covers its complete wire structures and public helper.
The ACL harness additionally extracts the complete native `acl_from_text` function
and token tables. Both record arm64 and x86_64 syntax/layout evidence; runtime
checks execute on the native runner architecture. The linked research documents
state the exact source revisions, hashes, observations and limits.

## Outstanding work and known differences

The following are still open; none is satisfied merely by the existing coverage:

- **ACL policy:** canonical text formatting, external-binary import, deferred and
  duplicate record application, source identity transport, inheritance, ownership,
  file flags and destination policy. The parser and external-byte exporter are
  implemented; filesystem ACL application is not yet integrated.
- **Quarantine policy:** serialized envelope validation and runtime normalization.
  Initial probes found a `q/` prefix and trailing NUL, with timestamp/agent changes
  during unpacking. These observations are not yet a qualified portable API.
- **Large-value packing:** on the observed host, native packing replaced an
  ordinary value above 16 MiB with a present-empty value. The byte codec preserves
  values within its wire/address-space bounds and does not silently adopt that
  policy. Oversized aggregates and large forks need further qualification.
- **Allocation policy:** the decoder rejects cumulative retained value/fork bytes
  exceeding input length. Native unpack can process some aliased records beyond
  that budget sequentially. This remains an explicit policy difference. The codec
  is in-memory; address-space checks do not guarantee available memory.
- **Shared filesystem transport:** lossless metadata handling for files,
  directories, roots and links; native refusal and normalization; carrier naming
  and conflict rules; and APFS/HFS+ extract/repack parity across all three OSes.
  Filesystem operations belong in `pkg/hostmeta`; lexical naming helpers and raw
  byte support do not complete this integration. Native refusal to attach a fork
  to a directory must not become cross-platform metadata loss.

[Package PR #72](https://github.com/deploymenttheory/go-macos-pkg/pull/72) remains
**open and draft**, using published APFS v0.13.0. It provides the old import path
through aliases and forwarding functions while the shared codec is qualified.
Further downstream changes belong on that PR. After the outstanding APFS work is
qualified and released, that PR must adopt the published version and pass its
consumer checks. Codesign remains paused until that gate is complete. See the
[migration and implementation plan](../../docs/appledouble-migration.md).

## Relocation history and provenance

The implementation and existing tests moved from
[`go-macos-pkg` v0.7.2](https://github.com/deploymenttheory/go-macos-pkg/tree/6785561c02967366e61327607abc7594a3e8ffe3/pkg/appledouble).
The MIT license remains in this directory. APFS must not depend on package tooling
or introduce a second downstream codec.

The following hashes describe the original relocation, not the current source.
The later changes and native validation are documented above.

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
