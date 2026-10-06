# Filename compatibility

Image readers, image writers, and foreign pathname authorization share filesystem
name conversion. They produce the same results on Linux, macOS, and Windows;
they do not use the receiving host's Unicode tables or locale.

APFS comparison and directory hashes use canonical decomposition, canonical
combining order, and full default case folding where the volume is insensitive.
The retained native directory records independently qualify those hashes. HFS+
and HFSX instead use Apple's frozen HFS decomposition and UTF-16 comparison rules.
HFS case folding is not interchangeable with APFS full folding.

## Existing names and new names

Creation and lookup have different native contracts. APFS can report ENOENT when
looking up an absent name that native creation rejects with EILSEQ. Therefore
`apfs.ValidateCreateName` requires an explicit macOS target, while
`apfs.ValidateLookupName` checks the separate existing-object component boundary.
`apfswrite.CreateOptions.TargetVersion` defaults to macOS 27 consistently on all
hosts. Explicit targets 15, 26, and 27 select their independently captured scalar
admission results. Readers never apply creation admission to existing disk keys.

Native APFS creation rejects malformed UTF-8 before checking decoded component
length; length is checked before scalar admission. APFS measures the original
UTF-16 spelling, whereas HFS measures the converted, decomposed UTF-16 spelling.
Both have a 255-unit component limit. Directory search authorization and whole
path length are separate checks with their own native ordering.

HFS converts illegal UTF-8 bytes, U+FFFE, and U+FFFF into uppercase percent escapes.
For example, a raw byte component `x\x80y` identifies the HFS name `x%80y`; it does
not identify `x�y`. `hfsplus.NormalizeLookupName` exposes that conversion for a
caller handling raw native bytes. The public Go `io/fs` adapter retains its valid
UTF-8 path contract: normalize an explicitly raw component before passing the
result to that adapter. This does not authorize directory search or reinterpret
an entire path.

Both image writers reject equivalent sibling names before any output writes.
HFS validation uses its observed catalog conversion and volume case policy.
APFS validation additionally uses its explicit target creation policy. File-entry
rules do not substitute for volume-label or snapshot-name rules.

## Evidence and tests

The retained 15/26/27 collation corpus contains 3,753 controls per filesystem,
including canonical decompositions, full folds, combining-mark order, case policy,
component limits, native directory identities, and raw APFS directory records.
Each profile covers APFS, APFSX, HFS+, and HFSX. The admission corpus independently
attempts every non-NUL, non-slash Unicode scalar on APFS and APFSX. The pathname
lookup corpus exercises actual write-open acquisition, malformed names, aliases,
authorization ordering, and component boundaries.

Primary sources, full native probe C, compiler/SDK inputs, both architecture ASTs,
raw observations, cleanup results, and source hashes are retained with each
capture. Generated tables are reproducible without changing files:

```sh
go run scripts/generate-name-tables.go -check
go run scripts/generate-name-admission.go -check
```

The filename-comparison workflow creates real native images on all three macOS
profiles, then exercises 90,072 public reader lookups on each consumer host.
Native consumers also mount those same images independently. The strict coverage
wrapper rejects skipped or incomplete tests and requires greater than 95% for
every changed production file, including the existing reader and writer files.
Whole-package coverage for the new normalization package and APFS writer must
also exceed 95%; older broad APFS/HFS package totals are reported separately.

Writer acceptance separately produces images with Go and checks the resulting
names and alias behavior through native mounts. Cross-version native failures
remain qualification failures until understood; an absent profile or mount is
not treated as a successful skip.
