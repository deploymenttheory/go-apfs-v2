# AppleDouble ownership, native parity and release gates

The filesystem SDK owns `pkg/appledouble` (bytes) and `pkg/hostmeta` (filesystem
operations). `go-macos-pkg` consumes the codec; codesign eventually consumes the
shared metadata APIs. There must be no APFS-to-package-tooling dependency cycle.

Status: relocation was released in APFS v0.13.0. The downstream package migration
remains in draft PR #72 until APFS compatibility work is complete; further package
changes belong on that PR. The subsequent native size/empty-value correction is
documented in [appledouble-native-sizes.md](appledouble-native-sizes.md). This is
one codec increment, not completion of the codec or host transport phases.
The next [name-validation increment](appledouble-native-names.md) establishes
ordinary name byte limits, UTF-8 and NUL/padding behavior with native fixtures.
The [record-validation increment](appledouble-native-records.md) adds native
observations for duplicate/overlapping records, header selection and actual read
bounds. The [FinderInfo/resource-fork increment](appledouble-native-special.md)
fixes FinderInfo lengths, zero/absent handling and ordered fork writes. Reserved
ACL conversion, source-resolved formatting and deferred replacement decisions are covered by the
[ACL interpretation increment](appledouble-native-acl.md). Serialized quarantine
envelope conversion, filesystem-xattr import and ordered/source-overridden decisions are
covered by the [quarantine codec](appledouble-native-quarantine.md). ACL creation
inheritance and replacement over inherited destinations are qualified through
[the portable inheritance policy](appledouble-acl-inheritance.md). Source identity
queries can be [captured and replayed](appledouble-acl-identities.md) portably;
live acquisition adapters remain transport work. [Full security records and
owner-preserving replacement requests](appledouble-filesec.md) have native byte
conversion and restrictive-flag application comparisons. The shared
[ACL restoration protocol](appledouble-acl-restoration.md) now propagates write
errors and qualifies source-cache reset/retry against real APFS and FAT outcomes.
[Darwin attribute records](appledouble-acl-attributes.md) preserve separate UUID
ownership, but native attribute/copyfile differences in empty ACL flags and
restrictive-flag errors rule out substituting attribute writes.
[Extended chmod requests](appledouble-acl-chmod.md) qualify the matching native
operation for those measured cases; the production call boundary remains open.
Non-owner authorization, production native/carrier adapters and full restoration
ordering remain outstanding. ACL application integration,
remaining [quarantine application contexts](appledouble-quarantine-application.md),
size policy and shared transport remain
outstanding, in that order. The allocation guard's stricter alias policy is
documented explicitly rather than counted as native parity.

## 1. Relocate without changing format behavior

- Move the existing codec, safety regressions and archived native fixture into
  APFS, preserving the public API and MIT attribution.
- Require the fixture instead of silently skipping it. Add boundary coverage,
  fuzzing and three-OS evidence, with codec unit coverage above 95% independently
  of acceptance tests or other packages.
- Open an APFS relocation PR and a package-project compatibility PR. Keep the
  old import path usable through aliases and forwarding functions. Core tests
  belong in APFS; package integration and compatibility tests stay in the consumer.
- The consumer initially used the immutable APFS relocation commit and now uses
  published v0.13.0. Continue updating draft PR #72 to the subsequent qualified
  release; never use an invented tag or local replacement in a submitted PR.
- Maintainers merge the PRs. Keep package PR #72 draft until the outstanding APFS
  work is complete, and notify the maintainer when its downstream validation is
  ready. Do not resume codesign implementation during the migration.

## 2. Establish and fix actual native codec behavior

The known limits are listed in `pkg/appledouble/README.md`. They are investigation
items, not assumptions that every limit must be relaxed or that every
normalization is a bug.

1. Pin Apple's XNU AppleDouble/xattr and copyfile sources. Extract complete relevant
   functions and data structures with Clang AST evidence for both Mac architectures.
   SDK/native tools remain research/test dependencies only.
2. Build a native producer/consumer harness around macOS packing and unpacking.
   Retain raw AppleDouble bytes, attribute names and values before/after, exit
   statuses, errno/diagnostics, host/tool identity and fixture hashes.
3. Probe header/table/value size boundaries independently; name byte lengths and
   Unicode; empty versus absent values; FinderInfo lengths/zero values; resource
   fork sizes; ordering, padding and alignment; unknown/duplicate/overlapping
   records; malformed lengths and integer overflow. Never count fixture-creation
   failures as successful native comparisons.
4. Test both directions: decode native-produced data, and have the native consumer
   read Go-produced data. Distinguish byte equality from semantic equality where
   native output contains variable or reserved fields.
5. Fix measured differences in the APFS codec, keeping compatibility adapters
   functional. Reject ambiguous or unsafe input explicitly. Do not introduce
   host-specific codec implementations or use a native process in production.
6. Retain all reproductions in portable unit tests, require **over 95% codec unit
   coverage on Linux, macOS and Windows**, run fuzz/race checks and rerun package
   build/extract/native acceptance against the corrected shared codec.

## 3. Resolve shared host metadata transport

After codec behavior is established, implement preservation in `pkg/hostmeta`
and consume it from APFS/HFS+ extraction and directory packing. The earlier
uncommitted transport experiment is not part of the relocation or a delivered API.

- Preserve original logical attribute names; avoid an ad-hoc codesign-only Linux
  prefix convention. Native namespaces and carrier files are storage details.
- Preserve file, directory, root and link metadata. Handle real and degraded links
  explicitly; never attach link metadata to the target accidentally.
- Cover native write refusal/normalization, empty values, case-sensitive names,
  large forks and extended attributes, and native/carrier conflicts. Attribute
  read failure must not become a successful absence check.
- Define ownership of ordinary files whose names resemble metadata carriers.
  Prevent overwrites, accidental exclusion of content, orphaned metadata and
  unsafe symlink/path traversal. Document concurrent-mutation guarantees honestly.
- Prove APFS and HFS+ image -> extracted tree -> rebuilt image equality for logical
  names and bytes on all three operating systems. Export foreign-host results
  for independent Mac validation. No Windows/Linux unsupported stubs or skipped
  feature tests constitute completion.
- Report actual preservation and any failures in both SDK errors and CLI results;
  no successful extraction/pack should conceal metadata loss.

## 4. Release before codesign resumes

Only after native codec parity fixes, >95% codec unit coverage, shared transport
regressions and required three-OS checks pass should a new APFS version be cut
through the existing release process. Review and merge remain maintainer actions.
Update package tooling to that released version and verify module/artifact
provenance. Only then may codesign resume, using the released shared APIs rather
than duplicating the codec or host transport.

Relocation coverage alone is not permission to release or resume codesign.
