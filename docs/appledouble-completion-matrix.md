# AppleDouble completion matrix

This matrix is the completion checklist for the [integrated plan](appledouble-completion-plan.md).
It distinguishes existing components from completed end-to-end functionality.
No row is complete solely because its component coverage exceeds 95%.

The defined implementation and qualification scope completed in [PR182](https://github.com/deploymenttheory/go-apfs-v2/pull/182), merged on 30 September 2026. Its final revision passed all 62 checks, including the 23-report per-OS coverage audit, all 37 fuzz targets, native authorization/sandbox cases and independent large-fork readback. [CI evidence](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/36769165547) remains the baseline for that claim.

The current phase is the requested [hostdata package refactor](hostdata-packages.md). Every gate must pass again for that refactor before release. The qualified native-version/context boundaries and explicit format/resource constraints below remain in force; this table does not claim unseen future macOS behavior.

| Requirement | Existing foundation | Qualification evidence and retained constraints | Status |
| --- | --- | --- | --- |
| Binary codec | Borrowed streaming values, sequential partial mutation, native packing and retained source/AST fixtures | Final revision CI/fuzz/race and integrated lifecycle qualification | Qualified in PR182 |
| Held native attributes | Strict list/read/assignment/removal, held metadata providers and native readback | Final three-OS provider and outer lifecycle qualification | Qualified in PR182 |
| Resource forks | Bounded APFS/HFS fork writers/readers, native non-truncation, large/empty carrier values; real 4 GiB + 17 byte image/carrier/native harness | Final three-OS large-value jobs and independent Mac readback of both foreign image artifacts; documented whole-buffer sequential limit | Qualified in PR182 |
| Compressed storage | Types 1, 3/4,7/8,9/10,11/12,13/14; native compression bounds and independent inline forks | Final codec/transport CI; external generation-store/provider references require their separate content source | Qualified in PR182 |
| ACL and security | Conversion, captured identities, inheritance, image bindings; 579-case temporary-permission oracle and explicitly scoped portable replay | Final live root/nonowner supervisor and signed native/Go App Sandbox jobs; retain C-only allocator boundaries | Qualified in PR182 |
| Quarantine | macOS 26/27 conversion/application profiles, raw process/source capture, destination corpus and integrated object/path providers | Final process-context, protection, destination normalization and ordered write/failure native gates | Qualified in PR182 |
| Stat restoration | Image time/mode/flags storage and ordered policy executor | Live host binding, side effects, temporary permission restoration and close failures | Qualified in PR182 |
| Shared metadata transport | Production carrier, required preservation preflight, host baseline reconciliation, collision/path safety, roots/links/hardlinks and contained native projection/readback | Final cross-platform lifecycle, CLI preservation and independent image acceptance | Qualified in PR182 |
| Complete lifecycle | Production held-object and path APIs; 8 live held-owner combinations; 552 native path scenarios; temporary permission and close-failure traces | Final 23-report audit and complete native CI; actual authorization, protection and version-specific host observations | Qualified in PR182 |
| End-to-end filesystem qualification | 16 streaming extract/repack pairs with native mounted metadata/content comparison, 14 native compression cases and 80 FinderInfo cases | Final Linux/Windows image artifacts independently mounted on Mac; edited-payload/refusal lifecycle qualification | Qualified in PR182 |
| Evidence integrity | Source-hashed coverage and retained native artifacts | Integrated journey manifests and comprehensive required-case inventory | Qualified in PR182 |
| Documentation | Detailed investigations and package roadmap | Current architecture, usage, carrier/streaming contracts and final capability matrix | Qualified in PR182 |
| Release and consumers | Release-please/GoReleaser and package draft PR72 on v0.13.0 | All gates closed, maintainer merge, published release, downstream adoption/qualification | Awaiting refactor qualification, release and downstream adoption |

## Evidence inventory

The required 23 portable qualification reports remain required on each supported
OS. `go run scripts/audit-appledouble-evidence.go` validates their revision, source
hashes, test transcripts and raw coverage counts against the checkout. It rejects
skips, failures, missing package completion, stale hashes, incomplete file counts
and coverage at or below 95%. The auditor itself has portable unit tests.

This audit does not establish native semantics, validate unpublished future gates
or replace C/AST/hdiutil/fsck and vendor acceptance scripts. Those retain their own
scenario and output checks. New integration work must add its coverage and evidence
to the inventory before its row can close. Downloaded cross-host evidence must be
checked against the exact source bytes used by that host; newline conversion is
not a reason to silently accept a different source hash.

`path-lifecycle-coverage` is the new report; the preceding 22 remain required.
Object facade, intent and sandbox files are selected individually by the existing
metadata transport coverage gate. Temporary permission replay accounts for all
579 source traces: 22 direct preparation and 492 direct reset comparisons,
28 C-only construction faults, 36 C-only temporary-template faults, and one
outer reset with no destination. C allocation/property APIs do not exist inside
the Go slice transformation. Those 64 fault cases retain native assertions and
compare Go with the matching native transformation without that C-only fault;
they are not presented as equivalent injected Go failures. The native gate still
executes every case. Empty ACL omission in native file readback is explicit;
present-empty ACLs remain distinct during logical preparation.

The live owner matrix now compares packed metadata as well as bytes, including
unconditional inner PACK stat and the outer mode reset. The 16-case real
root/nonowner supervisor requires `sudo -n` and validates actual process
credentials without creating accounts. Nonowner PACK and writable (0666) UNPACK
retain independently generated data/fork write times when explicit timestamp
restoration is unauthorized; read-only (0400) UNPACK retains its exact original
timestamp. For the two measured write contexts, each
observed mtime must lie within its own recorded invocation interval. Raw times
and bounds are retained, and all other metadata and output bytes remain exact.
Signed sandbox qualification requires an
explicit disposable GitHub-hosted Mac runner: two generated container namespaces
expire when the VM is destroyed, while temporary app-bundle cleanup is checked
before success is reported. Local prerequisite failure is not a passing result.
These jobs and the final audit passed in PR182 and remain mandatory for the package refactor.

## Large-value boundary

The direct sequential native-style unpack API allocates the incoming resource
fork before its native stat/read/write effects. Its explicit active-memory budget
includes simultaneous input and owned write buffers. The default 64 MiB budget
therefore cannot accept every fork that fits the wire's 32-bit size. Budget refusal
is an ordered, documented library diagnostic, not an invented Darwin errno or
a claim that macOS cannot store the fork. The logical destination owns newly
written bytes; untouched old suffixes remain borrowed. This facade does not claim
bounded-memory full-fork restoration.

Lossless large-value transport uses borrowed streaming codec/carrier/image APIs.
AppleDouble cannot encode a resource-fork length above 4,294,967,295 bytes; the
carrier and APFS/HFS image APIs preserve the larger value and explicitly omit the
unrepresentable optional AppleDouble view. The dedicated real-byte harness uses
4 GiB + 17 bytes, full hashes, a memory ceiling and independent native reads.
Its three-OS and foreign-image jobs passed in PR182 and remain required for every change. No Linux
or Windows feature is removed because native local xattrs have smaller limits.

## Exit rules

- Every implementation row has public production behavior, portable regression
  tests and reviewed native evidence or a precisely scoped native constraint.
- Linux and Windows complete each logical feature through native storage or the
  shared carrier. Unsupported native storage alone cannot close a row or justify
  silently losing metadata.
- Required coverage exceeds 95% independently on each OS and relevant new files;
  all existing fuzz/race/lint/build/native/vendor gates pass for the final revision.
- Native behavior is claimed only for the measured versions/contexts; uncertainty
  remains visible as an open requirement instead of a fabricated success.
- Package PR72 stays draft and codesign stays paused until the qualified APFS release
  and downstream adoption satisfy the final row.
