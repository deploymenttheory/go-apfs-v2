# Native AppleDouble record validation

The decoder now follows the two-entry macOS `copyfile` profile. Previously it
accepted arbitrary entry tables and searched for ATTR relative to FinderInfo,
while rejecting unused summary sizes and unused empty-value offsets. Those
choices disagreed with native unpacking.

## Observed behavior and implementation

The pinned source is Apple's
[`copyfile.c` at 9f91eb6ced021952278816cdc76ad68da8631ccb](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c),
SHA-256 `19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`.
Read `copyfile_unpack`, `swap_adhdr`, `swap_attrhdr` and `swap_attrhdr_entry`
together: unpack reads values from the file but FinderInfo from a buffer that
has already had its numeric fields endian-converted. The existing native harness
retains full source and Clang AST/layout evidence; its AST scope is documented in
[the size investigation](appledouble-native-sizes.md).

| Record condition | Native observation and Go behavior |
| --- | --- |
| Header shorter than 82 bytes, entry count other than two, first ID other than FinderInfo (9) | Reject |
| Second entry ID other than ResourceFork (2), including another FinderInfo | Ignore the second entry |
| FinderInfo declared length 0, 31 or 32 | Read 32 bytes of FinderInfo, skip ATTR |
| FinderInfo length above 32, including beyond EOF | Require the ATTR header at fixed offset 84 |
| Missing ATTR magic with FinderInfo length above 32 | Reject |
| Shifted FinderInfo offset | Read FinderInfo there; ATTR stays at offset 84 |
| FinderInfo overlaps the numeric header | Read the little-endian converted header bytes, as on current Mac architectures |
| ATTR total_size, data_start or data_length disagree with the file | Ignore these summary fields; check actual reads |
| Repeated ordinary attribute name | Preserve record order; Xattrs and native restoration use the last value |
| Overlapping value regions or a value pointing into the header | Read raw file bytes, subject to the allocation guard below |
| Nonempty value/fork extends beyond EOF | Reject |
| Empty ordinary value points beyond EOF | Keep the attribute present and empty; no bytes are read |
| Truncated attribute table/name/value/fork | Reject when the required read is unavailable |

Header and attribute entries must fit the first 65,554 bytes, matching native
copyfile's header buffer. FinderInfo always needs 32 bytes inside that buffer.
Nonempty value ranges are checked in uint64 before conversion to int, including
on 386. Zero-length reads do not convert an unused uint32 offset to int.
The caller's input is never changed by the endian conversion.

This intentionally tightens the former generic decoder: one-entry files,
reordered tables, and an unaligned ATTR-header fallback are no longer accepted.
It also intentionally accepts unused summary fields that older releases rejected.
The earlier `total_size=0xffffffff` negative-int regression is superseded by this
native evidence: the field is not used or converted at all. Actual read bounds
remain enforced on every architecture.

## Evidence and reproducibility

`testdata/appledouble/native/records.json` retains 44 synthetic wire inputs,
per-input SHA-256, native acceptance/diagnostics, native restored attributes and
destination baselines, plus host, source and helper provenance. They were measured
on macOS 27.0 (26A428), arm64. Expected logical attributes come from native
`listxattr` and `getxattr`, not from the Go decoder. The record names describe the
mutations of the canonical two-attribute (`a=ALPHA`, `b=BETA`) and `RSRC` fork case.
These are native consumer observations, not claims that native packing produces
malformed records.

Run from the repository root:

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble.go
# macOS independent oracle; public native APIs are test-only dependencies:
CGO_ENABLED=0 go run scripts/verify-appledouble-native.go
```

The portable unit suite replays every input on Linux, macOS and Windows, checks
acceptance and logical values, and verifies canonical encode/decode semantics.
The native harness replays every original input and, for each accepted input,
unpacks Go's canonical encoding into a fresh destination and enumerates every
restored attribute. Byte equality is not asserted for canonicalization of
noncanonical inputs. Existing native producer byte comparisons still run.

Native records can leave partially restored attributes before rejecting a later
record. The harness retains those after-failure observations; it does not treat
them as successful restoration. Native header failures may retain stale errno
(such as EEXIST). A rejection must be the helper's explicit copyfile failure,
never a crash or fixture-setup failure; errno is evidence, not a portable error
contract. Decode returns an error rather than a partially populated File.

On the observed host, protected `com.apple.provenance` survives native unpack.
The live harness records before/after maps and excludes it from logical comparison
only when it was absent from the expected sidecar attributes and is byte-identical
to the destination baseline. It does not broadly discard unknown attributes.

Local validation: 177/180 codec statements covered (98.3%), with no skipped codec
tests; all 44 record, 14 name and nine size/native-consumer comparisons pass.
CI independently enforces over 95% codec coverage on all three operating systems
and runs the 386 regressions on Linux. CI artifacts retain commands, full maps,
sidecars, readback files, coverage and source/fixture hashes.

## Explicit remaining limits

The existing cumulative allocation guard rejects inputs whose retained ordinary
values plus fork exceed the input byte length. Native unpack can process some
aliased records beyond this budget sequentially. This is a documented safety
policy difference, not a native parity success. The regression constructs a valid
two-entry header and verifies that it reaches the allocation guard.

This phase does not establish reserved/special-attribute semantics, FinderInfo
normalization, oversized native packing policy, or shared filesystem transport.
Those remain the next work in the [migration plan](appledouble-migration.md).
Package PR #72 stays draft and codesign remains paused.
