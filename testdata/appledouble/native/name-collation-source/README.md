# Native filename collation corpus

This corpus tests which names macOS treats as the same file, which names it rejects, and how native APFS stores their directory-key hashes. It supports the shared filesystem comparison, lookup and writer work. The captures establish behavior before changing the production algorithms.

`sources.json` pins the Unicode 17.0.0 `UnicodeData.txt` and `CaseFolding.txt` inputs by original URL and decompressed SHA-256. Their compressed files preserve the original bytes; `LICENSE.txt` retains the Unicode data license. Unicode 17 supplies the test inventory, **not an assumed filesystem policy**. Older macOS may reject characters or compare them differently. Those exact outcomes remain evidence.

The generator creates 3,753 controls per volume: every canonical decomposition and full default case fold in the pinned data, adjacent nonzero combining-class reorderings, thirteen explicit controls, and twenty component-length boundaries. Explicit controls include final sigma, sharp s, joiners, variation selectors, soft hyphen, replacement characters, Hangul and characters assigned after Unicode 9. Boundary controls distinguish original UTF-16 length from UTF-8 length and decomposed length.

The C oracle performs actual `openat` creation and lookup in independent directories. It records exact input bytes, native errno, held inode identities, filesystem name, mount flags and volume capabilities. It leaves the fixture files in the owned disk image so the Go capture can read the actual native directory records after unmounting. The capture does not use production name hashing or comparison to derive expected APFS hashes: it selects raw directory records by the parent's captured inode and matches the file's captured inode, retaining the original key and value bytes. HFS captures retain the stored catalog spelling.

Run from the repository root:

```sh
go test scripts/capture-name-collation.go scripts/capture-name-collation_test.go
go run scripts/capture-name-collation.go -out artifacts/name-collation -check
```

The native matrix creates APFS, case-sensitive APFS, HFS+ and HFSX images on macOS 15, 26 and 27: 15,012 controls per runner. Case sensitivity must agree between the observed native capability and the on-disk filesystem flags; a filesystem label alone is insufficient. The artifact includes all four complete images, independent C output, raw directory records, source hashes, compiler and SDK provenance, both architecture ASTs, attachment data and cleanup results. Manual workflow dispatch uses separate concurrency so an in-progress evidence capture survives a new PR push.

`-check` first writes the complete fresh artifact, then requires the corresponding retained native archive. Missing baselines, changed source provenance, missing controls or changed stable native outcomes fail the gate. First captures must be reviewed and retained from the actual runner; fabricated fixtures or relaxed checks are not permitted.

Production normalization remains a separate qualification step. The existing lowercase approximation fails native sharp-s and final-sigma cases and several native directory hashes. Local macOS 27 observations also contradict treating the historical APFS Unicode 9 documentation as a complete description of current behavior. The same control corpus must establish macOS 15 and 26 behavior. If older systems admit names with different hashes, their exact images must be mounted on newer systems to establish lookup and possible migration behavior before choosing reader/writer rules. No Unicode version is inferred solely from an image label or its producer OS.
