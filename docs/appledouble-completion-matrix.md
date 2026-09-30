# AppleDouble completion matrix

This matrix is the completion checklist for the [integrated plan](appledouble-completion-plan.md).
It distinguishes existing components from completed end-to-end functionality.
No row is complete solely because its component coverage exceeds 95%.

| Requirement | Existing foundation | Required closing evidence | Status |
| --- | --- | --- | --- |
| Binary codec | Borrowed streaming values, sequential partial mutation, native packing and retained source/AST fixtures | Final revision CI/fuzz/race and integrated lifecycle qualification | Open |
| Held native attributes | Strict list/read/assignment/removal, held metadata providers and native readback | Final three-OS provider and outer lifecycle qualification | Open |
| Resource forks | Bounded APFS/HFS fork writers/readers, native non-truncation, large/empty carrier values | Final three-OS native image artifact qualification and lifecycle limits | Open |
| Compressed storage | Types 1, 3/4,7/8,9/10,11/12,13/14; native compression bounds and independent inline forks | Final codec/transport CI; external generation-store/provider references require their separate content source | Open |
| ACL and security | Conversion, captured identities, creation inheritance, copy/update policy, image bindings | Live authorization/source capture and outer lifecycle, nonowner/privileged/sandbox qualification | Open |
| Quarantine | macOS 26/27 conversion/application profiles and destination corpus | Remaining process contexts, raw source/agent capture, protection and ordered write/failure integration | Open |
| Stat restoration | Image time/mode/flags storage and ordered policy executor | Live host binding, side effects, temporary permission restoration and close failures | Open |
| Shared metadata transport | Production carrier, host baseline reconciliation, collision/path safety, roots/links/hardlinks and explicit native projection/readback | Final cross-platform CI and remaining complete lifecycle composition | Open |
| Complete lifecycle | Copy routing and prevalidated unpack executor | Create/open/transfer/restore/close with cancellation and partial-error trace | Open |
| End-to-end filesystem qualification | 16 streaming extract/repack pairs with native mounted metadata/content comparison, 14 native compression cases and 80 FinderInfo cases | Final Linux/Windows image artifacts independently mounted on Mac; edited-payload/refusal lifecycle qualification | Open |
| Evidence integrity | Source-hashed coverage and retained native artifacts | Integrated journey manifests and comprehensive required-case inventory | Open |
| Documentation | Detailed investigations and package roadmap | Current architecture, usage, carrier/streaming contracts and final capability matrix | Open |
| Release and consumers | Release-please/GoReleaser and package draft PR72 on v0.13.0 | All gates closed, maintainer merge, published release, downstream adoption/qualification | Blocked by preceding rows |

## Evidence inventory

The required 22 portable qualification reports remain required on each supported
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
