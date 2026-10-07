# Filesystem filename rules

These pinned primary sources explain the pure-Go name comparison and conversion
rules shared by APFS/HFS image readers, writers and foreign pathname operations.
`../name-collation-source` supplies Unicode17 decomposition and full default case
folding. This directory supplies Unicode3.2 BMP normalization and Apple's complete
HFS comparison tables. Each complete compressed source retains its original
license and has a URL and decompressed SHA256 in `sources.json`.

`hfs_catalog.c` enables `UTF_ESCAPE_ILLEGAL` and canonical decomposition when
building HFS catalog keys. The pinned XNU `vfs_utfconv.c` expands illegal UTF-8
bytes, U+FFFE and U+FFFF to uppercase percent escapes before measuring the catalog
name. It canonically orders combining marks through `push`; the older livefiles
plugin's converter is not used as the kernel oracle.

`go run scripts/generate-name-tables.go` regenerates comparison tables.
`go run scripts/generate-name-admission.go` independently generates APFS creation
admission intervals from every actual scalar creation in the retained15/26/27
corpora. Creation admission never determines whether an existing name can be
looked up. No receiving-host Unicode table or OS-version inference is used.

The native collation, lookup, exhaustive admission and cross-version image
readback workflows qualify these source interpretations independently on macOS.
Linux and Windows run the same production tables and image-reader tests.
