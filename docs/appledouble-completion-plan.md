# AppleDouble completion plan

Complete the existing AppleDouble roadmap in one integrated implementation phase.
The result must preserve Darwin logical metadata through APFS/HFS+ extraction and
repacking on Linux, macOS and Windows, with independently qualified native behavior.
Production remains pure Go. C, Clang, Apple SDKs and native commands are research
and acceptance-test dependencies only.

This document describes required work, not completed support. The
[completion matrix](appledouble-completion-matrix.md) records the current gates.
Neither high coverage nor successful component tests closes an unfinished gate.
Package PR72 stays draft until a qualified APFS release is published and adopted;
codesign remains paused until that downstream qualification succeeds.

## 1. Establish the behavioral contract and prerequisites

Audit every existing roadmap assertion against code, native fixtures and tests.
Retain working components rather than implementing a second codec or policy engine.
For every remaining requirement, record its production entry point, prerequisite,
source citation, native scenario, portable regression and completion criterion.

Use operation-specific options and capability checks. Do not introduce a global
compatibility mode that silently changes unrelated operations. Encoding a valid
metadata container, reproducing a native pack operation, restoring through a
live host and preserving metadata through a foreign host have different inputs
and observable effects. Make those distinctions explicit at their entry points.

Required contracts include:

- Ordered records and native namespaces, including duplicates, hidden metadata,
  FinderInfo normalization and dedicated resource-fork slots.
- Native sequential errors and partial effects, separately from existing
  prevalidated snapshot restoration. Existing callers retain their contract.
- Source identity and policy capture, ownership/ACL authorization, destination
  state and timestamp inputs. Foreign hosts must never invent Darwin process or
  account state from their own local policy.
- Native packing limits versus metadata-preserving transport. An explicitly
  requested native operation may reproduce observed loss; preservation must
  never report unqualified success after discarding metadata. Retain diagnostics
  describing every failed, ignored, normalized or partially applied operation.
- Resource ownership, bounded memory, streaming, cancellation, short reads/writes,
  cleanup, close failure and ordering of permission restoration.

The strict native primitives are prerequisites, not the transport itself. Windows
EAs remove empty values, compare names case-insensitively and have smaller size
limits; Linux namespaces and filesystem limits differ from Darwin. The shared
carrier must preserve metadata these native stores cannot represent, including
empty attributes, raw names, security records and large resource forks.

## 2. Consolidate source research and native capture

Continue using `testdata/appledouble/native` for reviewed C probes and committed
portable observations, with Go qualification programs under `scripts`. Do not
replace those independent observations with mocks or self-generated expectations.

Inventory pinned Apple copyfile, xattr policy, ACL/filesec, quarantine and relevant
XNU implementation sources. Resolve every citation to a commit and SHA-256.
Inventory the host SDK headers and available C implementations; installed headers
are not the implementation, and an open-source release is not proof that a newer
host executes identical code. Record that distinction explicitly.

Extract whole relevant functions and declarations, retain original function bytes,
and validate Clang ASTs/layouts for arm 64 and x 86_64. Where private dependencies
require controlled shims, record each shim and the boundary it replaces. Keep
controlled source execution distinct from calls into the live host's libSystem.
Retain commands, compiler/SDK/OS/build/architecture, source hashes, ASTs, fixture
hashes, return codes, errno, callback trace and actual post-operation state.

Batch experiments for these unresolved groups:

1. Large ordinary values above 16 MiB; aggregate/table/wire/address-space limits;
   fork sizes, offset writes, shrinking and empty assignment; aliasing and
   overlapping/truncated records; allocation failures and interrupted streaming.
2. Complete destination cleanup/list visibility/order, hidden security and
   compression records, refusal/normalization and readback after each write.
3. Source capture and destination authorization under owner, nonowner, elevated
   and sandbox contexts, including inherited ACLs and temporary permission changes.
4. Quarantine process-label absence and presence for each supported profile,
   raw-agent/source capture, protected destinations, links and failures after
   earlier successful records.
5. Outer creation/open/truncate/permission/close ordering, cancellation and retained
   errors after partial mutation, with files/directories/roots/links/hardlinks.

Run real APFS, case-sensitive APFS, HFS+ and HFSX scenarios where applicable.
A missing prerequisite is a failing qualification gate, not a skipped feature.
Cross-architecture AST compilation does not count as execution on that architecture.
Version-specific behavior remains explicit in existing profile APIs and fixtures.

## 3. Implement the complete production path

Integrate the existing copy, unpack, security, quarantine, xattr and stat executors
through production held providers. Preserve handle identity after rename/pathname
replacement and operate on the intended link or target. Read back normalization
and retain native failures according to the measured operation ordering.

Implement bounded streaming interfaces for large ordinary values and resource
forks, with overflow-safe 64-bit arithmetic and explicit wire-format boundaries.
Keep the current in-memory codec API compatible. Process native sequential reads
through a separate, documented entry point where partial effects are required;
do not quietly change prevalidated snapshot semantics. Test native resource-fork
non-truncation independently from complete logical-fork replacement in transport.

Implement shared filesystem capture/restoration and a portable metadata carrier.
Its ownership and conflict policy must be explicit: companion matching, roots,
case collisions, existing user files, stale sidecars, malformed/unknown records,
symlink/reparse escape and hardlink aliases all need deterministic outcomes.
Never overwrite a conflicting user file or silently select one disagreeing
metadata source. Preserve logical metadata when the destination's native store
cannot represent it. Keep image storage, host storage and archive construction
in their existing owners; downstream package tooling consumes these APIs.

Complete the outer lifecycle: source acquisition, destination creation and inherited
metadata, data/fork transfer, cleanup and record restoration, deferred ACL, final
stat, temporary permission restoration and close. Cancellation and errors retain
both primary and subsequent cleanup failures. Do not imply transactionality when
the native operation leaves partial changes. Publish image-tree alias updates
consistently with the existing staging contracts.

## 4. Qualify complete journeys and all existing checks

Keep every existing CI gate. Add complete scenario manifests and test:

- Native Mac image → extract on each OS → inspect carrier/native state → modify or
  leave unchanged → repack → independently mount/read on Mac and run fsck.
- All 16 supported source/destination filesystem combinations, including roots,
  explicit zero modes, set-ID/sticky flags, hardlink aliases and snapshots.
- Empty/raw/case-conflicting names, FinderInfo, hidden compression/security,
  large forks/aggregates, ACL ownership/inheritance, quarantine and independent
  birth/modification/change/access timestamps.
- Real permission errors, malformed late input, missing carrier, collision/escape,
  short reads/writes, cancellation, ENOSPC, cleanup/readback/close failures and
  old-path decoys. Assert actual final state and error trace, not just return codes.

Portable codec, every changed provider and each new subsystem must exceed 95%
statement coverage on each supported OS. Retain file-level gates so new code is
not concealed by mature code's coverage. Retain all current 33 fuzz targets and add
streaming/carrier/lifecycle targets, overflow tests and corpus replay. Retain race,
Linux 386, CGO=0 six-target builds, three-GOOS lint, vet and vulnerability checks.

Retain all native C/AST qualification, hdiutil and fsck comparisons and all four
pinned vendor DMGs: Firefox 150, Zed 0.196.5, Charles 5.2.1 and BBEdit 16.0.3.
Mac-only oracle execution does not remove Linux/Windows functionality: both must
execute the complete logical operation, replay the corpus and submit output for
independent Mac inspection. Normalize only legitimately nondeterministic fields
under a documented rule, never unexplained mismatches.

The Go evidence auditor checks the required 20 portable report directories against
the exact checkout revision and source hashes, raw coverage and JSONL transcript.
Native semantic comparison remains the responsibility of each native harness.
Extend the auditor inventory for every new gate and add end-to-end artifact
manifests linking foreign-host outputs to their Mac readback. Missing evidence,
unexpected skip, wrong revision, stale hashes or coverage denominator omissions
must fail qualification.

For efficiency, run independent jobs in parallel with isolated mounts and process
fixtures. Cache pinned downloads and build inputs, not test conclusions. Duplicate
feature-branch push/PR runs may be consolidated only while retaining the complete
PR matrix, main postmerge checks and scheduled fuzzing. Do not remove gates or
shorten native coverage to make the loop faster.

## 5. Documentation, review and release

Publish current-state documentation explaining what the package does, why it is
needed and when to use each API. Include examples, streaming lifetime/error rules,
carrier location/conflicts/path safety, native constraints, platform capability
mapping and reproducible qualification instructions. Keep historical research in
its investigation documents; keep the README roadmap and completion matrix current.

Use one integration branch cut from current main and coherent reviewable commits.
Open a conventional-title draft PR and retain draft status until all required CI
and evidence audits pass. The maintainer reviews and merges. No automated merge
or unilateral release is authorized. Any subsequent phase starts from then-current
main rather than continuing an already-merged branch.

After all implementation gates close and the maintainer merges, follow the existing
release-please/GoReleaser process. Adopt only the published qualified APFS version
in existing package draft PR72, add all downstream changes there, rerun package
unit/native/three-OS validation and notify the maintainer when its hold is lifted.
Do not resume codesign before this sequence completes.
