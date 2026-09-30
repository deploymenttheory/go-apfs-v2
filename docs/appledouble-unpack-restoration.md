# AppleDouble unpack restoration

`hostmeta.RestoreAppleDouble` executes a validated metadata snapshot through
caller-supplied held destination operations. It supplies the missing ordering
between the codec and the existing ordinary xattr, quarantine, ACL and stat
components. Production code is pure Go and available on Linux, macOS and Windows.

Use it when a sidecar has been captured and the destination/provider identity is
already established. It does not find a companion file, open paths, authorize a
write, create a file, inherit permissions or close handles.

## Sequence and ownership

The executor calls `appledouble.Decode` before any destination operation. The
codec owns the returned records and preserves their wire order. It then:

1. Probes the destination's visible xattr-list size, reads that list once, and
   attempts removal of every listed name in order. Removal ignores source intent
   filtering: a stale `#N` destination attribute is still selected for removal.
2. Walks records in wire order. Ordinary records use `RestoreXattr`; each
   quarantine record invokes its own provider call, including empty records.
   Nonempty ACL records replace the deferred candidate; empty ones do not erase it.
3. Handles a nonzero dedicated FinderInfo slot using its own callback rules.
4. Captures destination type/times for a nonempty dedicated resource fork,
   applies its separate callback/write rules, and restores modification/access
   times after success when final stat copying is not selected.
5. Applies only the last nonempty ACL record, then optionally runs final stat.

Special names in ordinary ATTR records still use ordinary record rules. A
zero-filled FinderInfo slot and a zero-length resource-fork slot perform no
writes. FinderInfo's invisible bit is forwarded to the final stat provider only
following a successful slot write and non-cancelling Finish callback.

The source bytes are decoded before callbacks. Writes receive owned values.
The caller/provider must exclude concurrent mutation of the destination; there
is no rollback. In particular, Finish cancellation leaves an applied write in
place and stops later operations.

## Callback and failure rules

| Operation | Start Skip | Write failure | Finish Quit |
| --- | --- | --- | --- |
| Ordinary ATTR | Still writes | Existing `RestoreXattr` rules: callback Continue/Skip/unknown can suppress; exact root-installed EPERM exception | Stops after the applied write |
| Dedicated FinderInfo | Skips slot | Stops even if Error returns Continue/Skip; Error Quit reports cancellation | Stops before invisible-bit propagation |
| Dedicated resource fork | Skips slot after type/time capture | Only Error Continue suppresses; Skip/Quit/unknown keep failure but later ACL/stat still run | Stops before time restoration and ACL/stat |

All Start Quit responses stop immediately. Dedicated slots preserve the current
progress counter; ordinary records reset/update it only when a callback exists.

A failed resource-fork write is also suppressed for a directory when the value
exactly matches Apple's complete 286-byte empty-fork marker. No Error or Finish
callback follows that suppressed write. Other failed writes on directories do
not receive that exception.

Cleanup has its own native rules. Initial list-query EPERM and ENOTSUP continue;
other query errors exit with return code zero. A failed list read and failed
removals are ignored. Refusing the name-buffer allocation exits early instead;
providers distinguish that case with `ErrUnpackListAllocation`. Allocation or
budget diagnostics must never be disguised as a successful empty list.

Quarantine stops on any nonzero provider code. Deferred ACL stops immediately
only on `-1`; other codes can be replaced by final stat. A resource-fork failure
can also be overwritten by a successful later ACL/stat call. The Go error
reflects the final nonzero code, while `UnpackResult.Failures` retains operation
diagnostics even when the final code is zero. `ReachedEnd` distinguishes an early
zero-code exit from traversing the entire sequence. Neither is proof that every
piece of metadata was preserved.

## Provider contract

`UnpackBackend` represents one stable destination. Providers own:

- Visible namespace listing with its actual filesystem semantics, bounded name
  allocation, list framing and concurrent-change diagnostics. Raw security and
  compression storage must not become deletable merely because they exist in an
  image xattr map. The executor neither sorts nor retries the list.
- Exact-name removal, including failures and partial effects.
- Logical xattr writes and special normalization, using the ordinary executor's
  EPERM classification only where the captured Darwin error was actually EPERM.
- Type/time capture and ordered modification/access restoration for fork writes.
- Quarantine conversion and application at each record's position, using actual
  post-cleanup destination state and an explicitly captured target profile/process.
- Deferred ACL parsing/application, with ownership and authorization kept intact.
- Final stat staging, including the passed Finder-invisible decision.

Existing `File.QuarantineUpdates`, `Quarantine.PlanApplication`, `File.ACLUpdate`,
`RestoreACL` and `CopyStat` remain the shared implementations. An unpack delegate
for `RunCopyPipeline` can return the executor's code and error through
`CopyStageResult`; it must also retain the detailed unpack failures for its caller.

The image composition test supplies a provider for a deliberately known fixture
namespace and uses the actual APFS/HFS+ xattr, ACL and stat APIs. This is not a
new general-purpose image or host transport provider. The remaining production
provider work includes hidden metadata, held identity and authorization.

## Evidence and coverage

The native oracle extracts the complete unchanged `copyfile_unpack`,
`copyfile_unpack_xattr`, endian helpers and intent-policy helpers from Apple's
pinned [copyfile source](https://github.com/apple-oss-distributions/copyfile/tree/9f91eb6ced021952278816cdc76ad68da8631ccb).
It retains both arm64 and x86_64 Clang ASTs and the exact generated headers.
The Finder-invisible private state bit is symbolic in the helper; its ABI value
is not asserted. Quarantine, ACL and final-stat providers have controlled return
codes so ordering and masking can be tested independently of their existing
native qualification suites.

Pinned source hashes:

- `copyfile.c`: `19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`
- `xattr_flags.c`: `991a340ad26bf9086f9fcbca8eafb0dee4c2ab38e41d152c60fa218e5d4226dc`
- `xattr_flags.h`: `0fd2d35d0ae3efba30d30b8c470dae4bc42972455c6d8d5246fec44732f43d49`

Each reviewed host profile covers **1,907 controlled cases and 96 live file/directory
scenarios**. Live scenarios use real list/remove/set/get/stat/time operations:
**192 stale-attribute removals** are checked for absence and **89 successful
writes** are independently read back. Callback cancellation, refusal and skipping
mean not every scenario performs a write. Source data is always a valid captured
snapshot; this corpus does not qualify corrupt-source partial mutations.

Two complete profiles retain the native traces from macOS 27 and CI macOS 26.6.2.
The former includes host-added `com.apple.provenance` in the initial destination
namespace; the latter does not. Both preserve the exact list and removal events.
Native verification must match one complete profile, including every event and
return value; it does not filter or reorder observations. Any unreviewed host
variation fails qualification.

Every OS replays both complete profiles (the same 1,907 controlled inputs plus
192 captured live observations across the two hosts), exercises provider-contract/input failures,
checks source ownership and requires more than 95% coverage of the new production
file. Current focused coverage is **125/125 statements (100%)**, with **4,018
passing test records** and no focused skips. Four APFS/APFS-sensitive/HFSX/HFS+ images prove explicit and coordinated
stage execution produce identical bytes, with hard-link aliases and APFS
snapshots. Actual readers verify the retained metadata. These new images are not
claimed as independent mounted-image metadata observations.

Run `go run scripts/verify-unpack-restore-coverage.go` on any supported OS. Run
`go run scripts/verify-unpack-restore.go` as an ordinary macOS user to recapture
native evidence and compare it with the reviewed archive. `-capture` records an
unapproved candidate only. CI archives reports, transcripts, source hashes and
native artifacts; Clang is qualification-only, never a production dependency.

## Remaining work

Production held/carrier providers, full quarantine/process authorization,
creation inheritance and outer permission/close cleanup remain open. Snapshot
validation intentionally precedes cleanup: it does not reproduce native partial
destruction followed by a late malformed/truncated source read. Header/value/fork
allocation failures and sequential processing versus the codec's cumulative
allocation guard remain in the size/streaming phase. No silent metadata-loss
success should cross the consumer boundary: inspect the full result and recapture
preserved state when transport qualification requires it.

All five [AppleDouble completion gates](../pkg/appledouble/README.md#roadmap)
remain open. Package PR72 stays draft on its released APFS dependency; codesign
resumes only after the qualified APFS release and downstream adoption.
