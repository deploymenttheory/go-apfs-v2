# AppleDouble ownership, native parity and release gates

The current implementation work follows the
[consolidated completion plan](appledouble-completion-plan.md) and its
[completion matrix](appledouble-completion-matrix.md). The numbered increments
below retain migration rationale and evidence references; they are not a new
sequence of small PRs or separate compatibility modes.

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
operation for those measured cases. [Optional-property arguments](appledouble-acl-chmod-properties.md)
add omission/removal forms and qualify the distinct Darwin ownership sentinel.
[Image permission preservation](appledouble-image-modes.md) now retains explicit
zero modes and special bits across both writers, readers and captured entry
conversion, with native mode and image-hash qualification. This removes a write
integration prerequisite. [Deferred image ACL restoration](appledouble-image-acl-restoration.md)
now connects the shared execution policy to both image writers and qualifies
real output against native writes. Ordinary security-copy image integration and
the native host call boundary remain open.
[Controlled owner/non-owner image tests](appledouble-acl-nonowner.md) qualify
ordinary-user APFS/HFSX authorization and fix missing HFS security catalog flags.
[Ordinary ACL copy policy](appledouble-acl-copy.md) selects explicit source and
inherited destination entries, separately from creation and deferred replacement.
Privileged/sandbox contexts, production native/carrier adapters and full restoration
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

The ordinary security-copy executor is now available as `hostmeta.CopySecurity`.
It separates native sequence completion from write-failure diagnostics and keeps
source-cache changes explicit. Native host adapters and lifecycle integration
remain required; see [security-copy execution](appledouble-security-copy.md).
This increment does not unblock package PR72 or the final release gate.

APFS/HFS+ image security source capture and APFS root metadata writing are
available, with [root layout qualification](appledouble-root-metadata.md).
These close the measured root-loss gap but do not close the integration gate.

Ordinary security copying is now connected to both image writer trees; see
[image security-copy integration](appledouble-image-security-copy.md) for selected
properties, native refusals, qualification and the remaining ordered lifecycle.

The same executor and image writers support [lazy volume-policy acquisition](appledouble-security-copy-volume.md),
including native query order and retained lookup errors. Providers bind runtime
mount state to the copy endpoints; native host/carrier binding and complete
restoration ordering still gate release.

[Source acquisition and image bindings](appledouble-security-source.md) connect
both image readers to both writers through the shared descriptor-style capture
coordinator. Native fallback read errors stay visible, and all 16 source/target
filesystem combinations reproduce the manually captured path. Live host providers
and full restoration sequencing still gate release; this does not ready PR72.

Independent image timestamp storage and acquisition now support all three OSes.
Both image writers/readers retain separate birth/modification/change/access
fields; snapshot rebuilding retains root and child times. See
[image timestamps](appledouble-image-times.md). Live host timestamp acquisition
and the complete restoration lifecycle remain outstanding. The portable
[stat stage](appledouble-stat-copy.md) now executes ordered timestamp, ownership,
mode and BSD-flag restoration with native-qualified retries and retained errors;
live host bindings and integration with xattrs, deferred ACLs and cleanup remain.

[Image BSD flags](appledouble-image-flags.md) now support ordinary inode flags
in both readers/writers and snapshot rebuilding on all three OSes. Native HFS
catalog normalization and tracked document-ID allocation are qualified across
four images. IDs identify the new volume; original document identity, general
FinderInfo restoration and special object semantics remain separate work. The
stat binding is implemented below; the complete provider lifecycle still gates
release and package PR72's dependency update.

[Ordered image stat staging](appledouble-image-stat.md) now binds the shared
executor to both writer trees, with explicit destination times, alias agreement
and publication only after all staged operations succeed. Native model requests
and 580 mounted-image observations qualify the stored output on all three OSes.
Live authorization/timestamp effects, source/host bindings and the complete
restoration lifecycle remain open; this does not ready package PR72.

The [inner copy coordinator](appledouble-copy-pipeline.md) now owns route
precedence, ordinary quarantine/xattrs/data/security/stat ordering, callback
termination and pack/data failure cleanup. Pack/unpack remain explicit provider
boundaries; unpack's deferred ACL runs before its final stat. Native controlled
observations and real image-API composition replay on all three OSes. Held host
providers, unpack internals and the outer creation/permission-restoration/close
lifecycle remain outstanding. All five roadmap gates remain open.

[Ordinary unpack xattr restoration](appledouble-xattr-restoration.md) now connects
its callback/intent/error policy to both image writer trees. The HFS binding uses
the existing catalog resource-fork field; aliases agree before updates and Finish
cancellation does not roll back successful publication. This closes the ordinary
record execution component, not full unpack ordering or host/carrier transport.
All five completion gates and the package PR72 release hold remain open.

Validated unpack execution now composes destination-xattr cleanup, ordered ATTR
records, dedicated FinderInfo/resource-fork slots, deferred ACL and final stat.
The portable executor retains ignored and overwritten failures and works through
existing image APIs on all three OSes. Complete pinned Apple functions qualify
1,907 controlled cases and 96 live scenarios per reviewed host profile, including 192 verified removals and
89 read-back-verified writes. Production held/carrier providers and the outer
lifecycle remain open; input decoding deliberately completes before destination
mutation. See [unpack restoration](appledouble-unpack-restoration.md). This
component does not open the package release gate or resume codesign.

Held destination enumeration now uses `hostmeta.ListXattrNames` on Linux, macOS
and Windows. It preserves native name order and descriptor identity, bounds
allocation and rejects partial results. This closes the native listing
prerequisite, not the full unpack binding or foreign-carrier preservation gate.
See [held-file listing](appledouble-held-xattr-list.md). Package PR72 remains
draft on released v0.13.0; codesign remains paused.

Held native assignment is available on all three OSes through
[`hostmeta.SetXattr`](appledouble-held-xattr-write.md), with native error and
normalization behavior, bounded Windows records and independent Mac readback.
This completes the assignment primitive, not provider/carrier integration. All
five roadmap gates remain open; package PR72 remains draft until qualification
and a published APFS release.
