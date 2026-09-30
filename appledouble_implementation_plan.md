# Complete AppleDouble support with macOS-compatible operations and portable storage

## 1\. Objective and corrected architecture

Complete all outstanding AppleDouble roadmap work in one coordinated research, implementation and qualification phase, then return to codesign after APFS release and downstream adoption.

Use one integration branch cut from the latest APFS `main`, with reviewable commits and one draft completion PR. Internal technical stages do not require separate merges.

**There will be no global “preserve everything” versus “mimic macOS” mode.** Responsibilities are separated by operation:

| Layer | Contract |
|---|---|
| AppleDouble codec | Represent and validate supported metadata without silently introducing native operation-specific data loss |
| macOS-compatible operations | Reproduce the selected macOS profile’s packing, unpacking, normalization, ordering, errors and partial effects |
| Portable transport | Carry logical Darwin metadata across Linux, Windows and macOS without substituting host filesystem limitations for Darwin semantics |
| Native host adapters | Perform actual host operations and retain their errors, capabilities and side effects |
| Metadata carrier | Store metadata and identities that the destination host cannot represent directly |

A caller selects the operation it needs through the API, rather than selecting a global behavioral mode.

Examples:

- `Encode` continues to encode a valid value; it does not empty that value because native `copyfile` packing has a size-related behavior.
- A specifically named macOS-compatible packing operation reproduces that measured native behavior and reports the resulting normalization or loss.
- Existing prevalidated restoration retains its contract.
- A separately named sequential native-compatible restoration operation reproduces late-read failures and partial mutations.
- Linux and Windows use the carrier to represent Darwin state, including present-empty attributes and resource forks. Carrier use is an implementation mechanism, not an alternative compatibility mode.

Production remains pure Go with `CGO_ENABLED=0`. Linux and Windows require no macOS libraries, tools or helper processes. No feature may be replaced with an unsupported stub, empty-success result or skipped platform acceptance case.

The qualification baseline includes the existing macOS 26 and 27 profiles. Every roadmap requirement must have an explicit implementation and evidence-backed result. Unexplained differences remain blockers.

## 2\. Technical stages within the consolidated phase

### A. Establish the complete requirements and dependency matrix

Audit current code, production consumers, documentation and fixtures. Replace historical “remaining work” lists with one authoritative matrix.

Each requirement records its implementation, outstanding prerequisites, native sources, supported profiles, portable tests, integrated acceptance cases and completion evidence.

The matrix must include these confirmed gaps:

| Prerequisite | Required work |
|---|---|
| Production integration | Replace legacy best-effort metadata use in extraction and packing with the complete transport |
| Native host access | Complete source capture, option-bearing and positioned Darwin operations, security/context acquisition and descriptor lifecycle |
| Image semantics | Implement qualified namespace visibility, FinderInfo normalization, resource-fork behavior and hidden metadata handling |
| Large values | Remove whole-value assumptions across codec, host capture, carrier and image writers through appropriate streaming interfaces |
| Sequential compatibility | Implement native read/mutation ordering and late-failure behavior separately from snapshot restoration |
| Portable representation | Preserve attributes, forks, security, names, links and inode metadata that host filesystems cannot represent |
| Full qualification | Prove integrated workflows and remaining authorization/quarantine contexts |

Include special flags, tracked document identity, root metadata, allocation policy, cleanup and close-error precedence explicitly.

Use multiple agents to validate source interpretation, transport design and qualification independently. The lead owns shared contracts and integration; agents cross-review conclusions before requirements are closed.

### B. Complete native research using the existing capture process

Continue extending `testdata/appledouble/native` and the existing Go scripts. Do not replace the native corpus with models generated solely from the Go implementation.

Inventory Apple C sources already cached on the host and installed SDK headers. Verify provenance and hashes before reuse. Fetch missing implementation sources from pinned official repositories.

Research covers:

- Complete `copyfile_pack`, resource-fork packing, unpack helpers and relevant outer copy/open/close paths.
- XNU xattr, vnode, attribute-list and authorization behavior.
- HFS+ xattr, fork, link and catalog behavior.
- Libc filesec, ACL translation, extended chmod and stat interfaces.
- Quarantine process, source and destination state, including remaining macOS 27 contexts.

Retain complete extracted functions, source notices, upstream commits, hashes, generated headers, compiler arguments, record layouts and arm64/x86\_64 ASTs.

Use the existing pinned [Apple copyfile implementation](<https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c>) and related pinned XNU, HFS and Libc sources. Supplement research with [Netatalk](<https://github.com/Netatalk/netatalk/tree/main/libatalk/adouble>), [Samba](<https://github.com/samba-team/samba/blob/master/source3/modules/vfs_fruit.c>) and [libarchive](<https://github.com/libarchive/libarchive/blob/master/libarchive/archive_read_disk_entry_from_file.c>). Differences in those implementations generate test cases; Apple evidence determines compatibility.

Resolve these subjects together:

- Ordinary versus hidden attribute visibility and ordering.
- FinderInfo validation and normalization.
- Resource-fork positioned writes, empty assignments, non-truncation, directory exceptions and timestamp effects.
- Values around and above 16 MiB, native fork limits, aggregate/wire boundaries and allocation order.
- Overlapping records, late malformed input, short I/O and partial mutations.
- Creation inheritance, owner/non-owner/root/sandbox authorization and temporary permissions.
- Quarantine absence, raw-agent capture, effective flags, protected destinations and capture races.
- Cancellation, permission restoration, synchronization, close failures and error precedence.

Keep four evidence classes distinct: source analysis, unchanged Apple functions with controlled providers, live native execution, and independently mounted image observations.

AST validation is not execution qualification. Controlled quarantine/ACL/stat providers are not proof of complete native restoration. Private APFS behavior requires live observation.

### C. Implement streaming and low-level prerequisites

Add a sized `io.ReaderAt`\-based value abstraction in `appledouble`. Reuse it from host metadata and image adapters without introducing an import cycle.

Implement:

- Indexed record/value-span access.
- Streaming encoding to `io.Writer`.
- A separately named sequential native-compatible restoration entry point.
- Lazy attribute and resource-fork inputs in both image writers and readers.
- Explicit resource budgets, checked offsets and bounded scratch storage.
- Defined source lifetime, cancellation, exact-length reads and close-error handling.

Preserve existing in-memory APIs and their documented guards. Overlapping records must not multiply retained allocations unnecessarily.

Ordinary native attributes generally require a complete value in one operation. Repeated chunk writes must not be used as an incorrect streaming substitute.

For portable transport, stream large values into the carrier or image when native representation is unsuitable. For an explicitly requested native-equivalent operation, report a configured execution-budget refusal distinctly from native errno or native success.

Resource-fork positioned I/O is a separate qualified operation. Carrier blobs can retain values beyond AppleDouble wire capacity without producing invalid AppleDouble data.

Complete Darwin bindings through supported `x/sys` wrappers where available. Use isolated Darwin-only [`purego v0.11.1`](<https://github.com/ebitengine/purego/tree/v0.11.1>) bindings for required signatures unavailable through those wrappers.

Verify ABI layouts, options, positions, pointer lifetime, empty buffers and errno independently. Pin the OS thread through calls and errno capture. Remove deprecated raw-syscall dependencies from the production preservation path.

Native libraries supply low-level host operations only. Production must not delegate copyfile or metadata-policy algorithms to Apple implementations.

### D. Implement portable metadata transport and carrier storage

Add a transport layer depending on `appledouble`, `hostdata` and existing fidelity reporting. It must not import concrete image writers or host-walking code. Concrete image packages implement shared endpoint interfaces.

Use the agreed separate, caller-selected metadata root. It contains:

- A versioned manifest associating logical objects with materialized paths.
- AppleDouble payloads for interoperable metadata.
- Streamed blobs for large values and forks.
- Metadata AppleDouble cannot fully encode, including original names, logical link identities, ownership, four timestamps, modes, BSD flags and captured security/policy context.
- Baselines and generations for detecting conflicting native/carrier changes.

Carrier rules are fixed:

- Never consume arbitrary `._*` files by filename alone.
- Reject identical or overlapping payload and metadata roots, including aliases.
- Hold roots open and prevent traversal, symlink and reparse-point escapes.
- Preserve names and values without case folding or lossy conversion.
- Record filename remapping and unavailable native link representations so repacking reconstructs the logical tree.
- Validate manifest versions, associations, lengths and blob hashes.
- Accept matching representations; report conflicting changes rather than choosing an implicit winner.
- Publish blobs before manifest references.
- Keep interrupted publication detectably incomplete.
- Remove only staging artifacts owned by the operation.

Carrier storage does not alter macOS operation semantics. It represents the logical state produced or consumed by the requested operation.

### E. Complete production providers and lifecycle execution

Reuse existing policy and execution components, including source capture, security copying, ACL restoration, stat restoration, copy routing and unpack ordering.

Implement production held-host, image and carrier providers for:

1. Source acquisition and explicit identity, process and volume context.
2. Destination opening/creation, inheritance and stable identity.
3. Temporary permission changes required by the qualified operation.
4. Native two-stage namespace query/read behavior.
5. Ordered cleanup with retained failures and appropriate readback.
6. Ordinary records and dedicated FinderInfo/resource-fork handling.
7. Quarantine evaluation using actual destination state at each record.
8. Deferred ACL application and final stat restoration.
9. Permission restoration, synchronization, close and failure cleanup.

Qualify callback behavior, cancellation, primary/secondary error precedence and actual partial destination state.

Implement shared target-filesystem semantics for image providers. Existing map assignment must not substitute for non-truncating native fork writes or FinderInfo normalization. Keep hidden compression/security capture separate from ordinary cleanup visibility.

On Linux and Windows, retain Darwin ACLs, quarantine state and other metadata in the carrier and evaluate applicable policies through the portable implementation. Host-kernel enforcement remains distinct and accurately reported.

Permission denials must not become fictitious successful native writes.

### F. Connect SDK and CLI consumers

Replace legacy best-effort metadata paths in extraction and host walking with the completed transport.

Public interface changes:

- Add streaming codec/value APIs without changing existing byte-oriented contracts.
- Add explicitly named macOS-compatible packing and sequential unpacking operations.
- Keep the existing prevalidated restoration operation.
- Add endpoint-based capture, transfer and restoration APIs with explicit target profile/context where required.
- Add structured results separating native return codes, completed work, native/carrier representation, normalization, conflicts, unknown capture and actual loss.
- Do not add a global preservation/native-mode enum.

CLI behavior:

- Existing metadata flags retain their selected categories and request complete transport of those categories.
- Add a caller-selected metadata-directory option and resource-budget controls.
- Require a carrier during read-only preflight when requested metadata cannot otherwise be retained.
- Do not choose an implicit metadata location.
- Consume carrier state during repacking only when explicitly supplied.
- Expose macOS-equivalent pack/unpack behavior through operation-specific commands or options, with their contracts documented.
- Report unexpected loss, conflict or incomplete capture as nonzero incomplete transport.
- For explicitly requested native-equivalent operations, retain native return semantics while exposing additional diagnostics.

Carrier-preserved metadata is not “dropped” and must not increment loss counters.

## 3\. Testing, native evidence and CI

Retain the current harness and quality gates:

| Layer | Required qualification |
|---|---|
| Builds | Six `CGO_ENABLED=0` builds: Linux/macOS/Windows × amd64/arm64 |
| Static checks | Three-GOOS golangci-lint, gofmt, vet and govulncheck |
| Coverage | Strictly above 95% for the codec and each new/changed functional component on each applicable OS |
| Runtime checks | Existing race checks, Linux 386 regressions, full unit and acceptance suites |
| Fuzzing | All 33 existing targets plus streaming, carrier and sequential-execution targets |
| Native macOS | Existing C oracles, source extraction, Clang ASTs, live metadata comparisons, `hdiutil` and filesystem checks |
| Commercial images | Firefox, Zed, Charles and BBEdit on every OS |
| Evidence | Exact revision, source/fixture hashes, tools, host profiles, observations, diagnostics and coverage denominators |

Add integrated scenarios:

- Native Mac source image → extraction on each OS → modification → repacking on each OS → independent macOS mount/readback.
- APFS, case-sensitive APFS, HFS+ and HFSX, including existing source/destination format combinations.
- Files, directories, roots, snapshots, symlinks, dangling links and hard-link aliases.
- Unicode, case collisions, Windows-unrepresentable names and legitimate `._` files.
- Empty attributes, FinderInfo, hidden compression/security state and large resource forks.
- Fork prefix overwrite, empty overwrite, directory exceptions and timestamps.
- ACL inheritance/replacement/removal, identities, ownership, flags and quarantine contexts.
- Carrier conflicts, corruption, missing blobs, interrupted publication and path redirection.
- Short reads/writes, allocation refusal, ENOSPC, permission denial, cancellation and late malformed input.
- Concurrent rename/replacement, permission-restoration failures and close errors.
- Bounded-memory transfer and synthetic near-wire-limit inputs.

Every successful native write requires independent readback. Failure cases verify unchanged or partially changed destination state. Fixture/setup failures fail qualification.

Linux and Windows must execute real host/carrier workflows and replay native behavioral cases. Compilation or replay alone does not establish production support.

Promote artifact auditing into a committed Go verifier. It rejects missing platforms/cases, unexpected skips, stale evidence, source-hash mismatches, missing coverage files, unreviewed profiles and behavioral disagreements.

Improve orchestration without removing checks:

- Run the complete matrix on PR revisions and `main` after merge.
- Eliminate duplicate feature-branch push/PR runs.
- Parallelize independent suites with isolated native resources.
- Cancel only superseded revisions.
- Cache pinned inputs and builds, never stale test results.

## 4\. Documentation and completion criteria

Maintain one current implementation matrix and update documentation alongside implementation.

Document:

- The distinction between codec representation, macOS-compatible operations and portable storage.
- SDK and CLI workflows for capture, restoration, carriers, streaming and repacking.
- Existing prevalidated restoration versus explicit sequential native compatibility.
- Platform representation and enforcement behavior.
- Source provenance and reproducible native capture.
- Budgets, conflicts, cancellation, partial effects and error reporting.
- Migration implications of complete transport replacing best-effort behavior.

The AppleDouble README should explain what it is, why it is needed, when it is used, current capabilities and remaining requirements. Historical investigations remain evidence links; stale outstanding-work statements point to the authoritative matrix.

Completion requires:

- Every existing implementation roadmap requirement has production code and passing qualification.
- No unresolved logical preservation gap remains in the selected Linux/Windows workflows.
- Explicit native-equivalent operations match supported macOS profiles, including measured limitations and partial effects.
- All required CI and artifact audits pass at the final revision.
- Coverage remains above the required threshold per component/platform.
- Documentation describes implemented behavior without uncompleted implementation placeholders.

A constraint is closed only when its behavior is tested and the portable representation is implemented as fully as that constraint permits. An unexplained mismatch cannot be reclassified as a constraint to declare completion.

## 5\. PR, release and return to codesign

1. Cut the integration branch from the latest APFS `main`.
2. Open one draft completion PR with coherent research, prerequisite, transport, integration, testing and documentation commits.
3. Keep it draft until all mandatory CI and evidence audits succeed. Then mark it ready; the user merges.
4. Release through the existing release-please and GoReleaser process. The user merges the release PR.
5. After publication, update existing package draft PR72 to the qualified APFS version. Add required consumer changes there, retain compatibility aliases and rerun full cross-platform and native package qualification.
6. Notify the user when PR72’s hold is satisfied. The user merges it.
7. Resume codesign on a fresh branch from its latest `main` only after qualified APFS adoption and downstream validation.

Research, implementation and qualification proceed continuously within this phase. Individual helpers do not restart the small-PR merge loop.