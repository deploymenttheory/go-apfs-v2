# Native FinderInfo and resource-fork behavior

This increment fixes three measured differences: FinderInfo values were silently
padded/truncated, zero FinderInfo in an ATTR record was exposed as a present
attribute, and repeated resource-fork writes discarded the previous suffix.
The shared codec now validates FinderInfo and reproduces the observed logical
FinderInfo/resource-fork values without using native code in production.

## Native observations

The pinned source is Apple's
[`copyfile.c` at 9f91eb6ced021952278816cdc76ad68da8631ccb](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c),
SHA-256 `19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`.
`copyfile_unpack` applies ATTR records in order, then nonzero dedicated FinderInfo,
then a nonempty dedicated resource fork. Native setters supply the remaining
semantics, which cannot be inferred merely from the AppleDouble layout.

Measured on macOS 27.0 (26A428), arm64:

| Input/action | Native result |
| --- | --- |
| FinderInfo length 0, 1, 31, 33 or 64, on a file or directory | Setter rejects it with ERANGE; no silent resizing |
| FinderInfo length 32, repeated 0x41, sequential bytes or all 0xff | Preserved byte for byte on files and directories |
| All-zero 32-byte FinderInfo | Accepted, but not exposed as a present native xattr |
| Noncanonical ATTR FinderInfo followed by a nonzero dedicated slot | Dedicated slot wins |
| Invalid-length ATTR FinderInfo followed by a valid dedicated slot | Rejected before the later slot is applied |
| Zero-length fork on a fresh file | Accepted, but not exposed as a present native xattr |
| Fork on a directory, including an empty value | Native setter rejects it with EPERM |
| Repeated fork write: `ORIGINAL`, then `NEW` | Restores `NEWGINAL` |
| ATTR fork `ORIGINAL`, dedicated fork `NEW` | Restores `NEWGINAL` |
| Empty fork write after a nonempty one | Existing fork is retained |
| A later longer fork value | Replaces the whole prior value and extends the fork |

The codec does not know the destination object type. It must remain able to carry
resource-fork bytes on every operating system, including when a destination
filesystem refuses to attach them. Directory refusal and carrier preservation
belong in the shared host metadata layer; this change introduces no platform
stubs or host-dependent codec behavior.

## API behavior

`FromXattrs` keeps its existing signature. Valid 32-byte FinderInfo is lifted into
its dedicated slot as before. Invalid-length input is retained verbatim in Attrs;
`Encode` returns an error instead of silently changing it. It remains nonempty,
including when the invalid input is zero bytes, so consumers cannot accidentally
drop the validation error through an Empty check. Callers must check Encode's
error. `Decode` also rejects invalid-length FinderInfo ATTR records, including
ones followed by valid data that would otherwise hide them.

`Decode` retains the ordered wire records in `File.Attrs`; `Encode` stably sorts
by name while preserving duplicate write order. `Xattrs` computes the
logical FinderInfo/fork values by applying those records and then the dedicated
slots. Zero ATTR FinderInfo removes any earlier FinderInfo; a zero dedicated slot
is omitted, matching native unpack's conditional write. Fork writes overwrite a
prefix without truncation; empty writes do nothing. Constructing the merged fork
does not mutate wire records or retain aliases to their byte slices.

Ordinary attributes still use the last record's value and preserve present-empty
values. Other reserved names retain their serialized payloads: Xattrs is not a
complete simulation of native ACL, quarantine or file-flag application.
`Empty` describes stored wire content, not whether every record will produce a
visible native xattr.

This is a compatibility correction: callers that relied on malformed FinderInfo
being padded/truncated now receive an error. No public types or signatures have
been removed, and downstream compatibility aliases continue to use the shared
implementation.

## Evidence and checks

`testdata/appledouble/native/special.json` retains 30 native producer/setter probes
and 25 native wire-consumer probes, with raw sidecars, exact values, hashes,
source/helper/host provenance, native diagnostics and before/after attribute maps.
Sixteen producer probes intentionally exercise setter refusal; the fourteen
accepted producers require native pack → Go exact re-encoding → native unpack.
Twenty-one wire probes cover FinderInfo/resource-fork parity (15 accepted, six
rejected). The other four are explicitly marked PolicyOnly and record outstanding
ACL/quarantine behavior; they are not counted as effective-attribute parity.

Run from the repository root:

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble.go
# macOS independent oracle only:
CGO_ENABLED=0 go run scripts/verify-appledouble-native.go
```

The native harness creates fresh files/directories, enumerates all attributes,
checks setup, distinguishes explicit native refusals from crashes/setup errors,
and checks both directions. Packed data must agree byte for byte; canonical wire
restoration must match independently read native values. Protected host provenance
is removed from a probe's logical comparison only when absent from the expected
attributes and unchanged from the captured baseline. Full maps and readbacks
remain in CI artifacts. Source byte comparisons still include provenance when
native packing includes it. Existing Clang AST/layout/source artifacts remain
part of the same run; their scope is documented in the size investigation.

Portable unit coverage locally is 201/204 statements (98.5%), with 164 passing
test records and no skips. CI requires over 95% independently on Linux, macOS and
Windows, and executes 386 regressions on Linux. Local package/internal suites,
codec race tests, lint and a 30-second fuzz run pass. The downstream package suite
and native build/extract/manifest acceptance pass with the new codec through an
external temporary modfile. A further package-builder probe checks all six
FinderInfo lengths for both replacement and merge overrides: invalid values
produce path-qualified errors, while 32-byte values build successfully.

## Remaining special-attribute work and release gate

Native `copyfile_unpack` dispatches `com.apple.acl.text` and
`com.apple.quarantine` to specialized handlers. The four archived empty/invalid
payload probes are accepted by native unpack without producing ordinary xattrs.
The byte codec deliberately retains those serialized payloads. Dropping them
would destroy metadata needed by a future native-equivalent consumer. Valid ACL
text, quarantine normalization, associated file flags and policy application
still need independent fixtures and portable implementation. Native refusal on
directories and the source's empty-resource-fork placeholder exception also need
host-transport acceptance coverage.

After that special-attribute work come the remaining size/allocation policies and
shared host transport, as recorded in the migration plan. The stricter cumulative
alias allocation guard is still an explicit policy difference. Package PR #72
remains open and draft, its submitted dependency remains the published v0.13.0,
and codesign remains paused until APFS qualification and release complete.
