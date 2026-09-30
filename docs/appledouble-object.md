# AppleDouble object operations

`hostmeta.PackAppleDoubleObject` and `UnpackAppleDoubleObject` connect the native
packing and sequential unpacking policies to held metadata providers. They
include source security acquisition, temporary destination permissions, source
quarantine precedence, intent filtering, ACL handling, optional stat restoration
and final permission reset. Detailed results retain failures that native control
flow ignores; a successful native return code is not proof of lossless copying.

Successful native packing always invokes its final stat stage. The pack
`Stat` option controls the outer descriptor lifecycle's permission reset; it
does not disable that inner stat copy. These two stages must remain distinct.

`NewHostAppleDoubleObject` captures a held macOS file's metadata, source account
resolver, quarantine process context and actual App Sandbox selector. It does
not own the file. Keep the descriptor open and exclude concurrent mutation until
the operation ends. Public construction always uses the native providers; a
private composition helper makes acquisition order and failures testable on all
three platforms. No production compiler, shell or copyfile subprocess is used.

`NewCapturedAppleDoubleObject` supplies the same policy on Linux, Windows and
macOS from explicit `MetadataState`, borrowed attribute Values, an identity
snapshot and captured process/mount policy. Account mappings belong to the
source. Captured policy does not confer native authorization on another host.
`LogicalSnapshot` returns the updated logical state for an image or carrier.
Native objects require actual native readback instead.

## Captured filesystem mutation effects

An attribute removal or replacement can return success while the native
filesystem retains or recreates the same attribute. A before/after namespace alone cannot establish
whether removal was refused, succeeded, or had an intermediate effect. Explicit
provider observations are needed to reproduce these effects on another OS.

`CapturedAppleDoubleObject.Removals` accepts object-scoped
`CapturedXattrRemoval` observations. `Writes` accepts `CapturedXattrWrite`,
which also binds exact incoming bytes for a position-zero, flags-zero native
assignment. Both use `CapturedXattrMutation`: exact before/after presence and bytes,
attribute name, and returned Darwin errno. There are no built-in protected-name
exceptions. Callers must capture these operations under the applicable source
filesystem, permissions, ACL, descriptor access and process context. Unlisted
names use ordinary logical storage effects; that default does not claim to reproduce
uncaptured kernel mutation policy.

Construction rejects duplicate names and inconsistent absence/value records,
then clones the observation bytes. Each operation checks its full before-value;
assignment also checks the exact input bytes.
A stale observation returns `ErrXattrMutationUncaptured` without changing storage.
A state-changing observation therefore cannot be applied a second time unless
its before-state has been restored. A success that leaves its before-value
unchanged can be repeated. Observed errors retain their original number as
`CapturedDarwinErrno`, distinct from the receiving system's `syscall.Errno`.

Removal observations apply only to attribute removal. An all-zero FinderInfo
write and a named-fork open with truncation have separate storage effects and
do not consult removal observations. The Darwin fork operation opens and closes
the actual held named fork; captured objects perform its logical effect on all
three operating systems.

## Allocation and ownership

The native-compatible unpack executor allocates a complete incoming resource
fork before its destination stat and data-read stages. It does not stream fork
writes. The default object options provide 64 MiB of active workspace;
`MaxActiveBytes` also accounts for simultaneous input and owned write buffers,
header and deferred records. A fork's wire size alone is therefore not its
workspace requirement. Insufficient budgets return explicit errors in native
operation order, potentially after earlier metadata changes.

For each allocation, the check is
`size <= (MaxActiveBytes - headerBytes - deferredACLBytes) / 2`, in addition
to the configured single-value, aggregate-value and machine address-space limits.
The default 64 MiB budget thus admits less than a 32 MiB incoming fork once
header and deferred ACL storage are counted. Callers may raise the budgets; this
is an allocation contract, not a Darwin filesystem fork-size restriction.

Workspace limits do not bound all destination-owned metadata accumulated across
records or operations. Logical writes own their input bytes, so closing an
unpacked input does not invalidate the bytes just written. A shorter resource
fork write preserves the old suffix without reading or materializing it.
Repeated prefix writes coalesce their owned prefix into one buffer instead of
retaining obsolete overlays; old snapshots retain their previous Values.
Coalescing may copy the existing owned prefix even when the new write is shorter.
The untouched original suffix is still borrowed and must remain readable until
its current snapshots have been persisted or discarded.

For large lossless preservation, use the borrowed streaming AppleDouble codec,
metadata carrier and APFS/HFS image readers/writers. Those APIs preserve values
without imposing native pack's ordinary-attribute loss policy or its complete
fork allocation. Selecting an API is a semantic choice: native-compatible
packing deliberately preserves copyfile's observed omissions and errors.

## Qualification

The retained public-path corpus contains 552 context-bound native observations,
including complete ordered raw namespaces, source ACLs, sandbox state and source
wire bytes. The portable PACK replay compares 92 completed outputs against
captured native byte hashes and lengths, plus 20 callback-cancellation sequences.
The remaining 133
PACK observations cover outer acquisition/destination IO, and 307 records concern
UNPACK; those categories are checked explicitly rather than silently omitted.
Live path qualification separately compares installed C and Go on identical
complete inputs. Native provenance attributes remain in both comparisons.

`go run scripts/verify-xattr-remove-effects-native.go` independently records
removal and replacement return values and immediate readback in 228 explicit
native contexts. The matrix covers regular files, directories, held symlinks and
dangling symlinks, modes, absent/read/temporary-owner ACLs and descriptor access.
Acquisition failures are recorded explicitly. Both architecture ASTs and full
observer/header hashes are retained. Current C observations and the retained
fixture are replayed through the public captured-object constructor on every OS.

Forty retained UNPACK cases now compare the complete final namespace and callbacks.
Each uses a matching mutation-provider observation: owner, mode, ACL, filesystem,
device, mount flags, descriptor access, sandbox and process identifiers all agree.
The temporary permission stage uses the separately qualified `PreparePathSecurity`
policy. Only the inode differs between the independently created probe objects.
The remaining 13 destination-creation and 254 outer-acquisition/replacement/error
records retain their explicit classification and live native path qualification.
No metadata names are removed from either comparison. Unit tests additionally
exercise defensive ownership, stale and wrong-input refusals, partial effects
with errors, repeated observations and distinct operation identity.

`TestAppleDoubleObject*` covers provider failure ordering, source identity
resolution, ACL conversion/restoration, intent filtering, quarantine precedence,
callback error codes, source-cache lifetime, destination mode reset, owned writes
and snapshot lifetime. Native tests use real held descriptors and retain original
permission/syscall errors. Every object implementation file is measured separately
against the greater-than-95-percent gate on its applicable platforms.

`go run scripts/verify-appledouble-object-native.go` builds an independent C
`fcopyfile` caller and metadata observer against the installed SDK. Eight cases
combine ACL, stat and resource-fork choices. Packed bytes must match exactly;
C independently compares final modes, BSD flags, xattrs and external ACLs for
native and Go unpacked destinations, including stale-attribute removal and
resource-fork write results. Both architecture ASTs, source hashes, host
and SDK identity and controlled fixture hashes are retained. Fixture contexts
retain necessary numeric IDs and raw ACL principals for exact reproduction;
account names and directory-service records are not collected.

This first live matrix establishes owner-context composition. Nonowner and
privileged authorization require a disposable fixture supervisor with actual
privilege; a host without noninteractive privilege cannot establish those cases.
A sandbox qualification must observe a genuinely sandboxed process selector,
not infer it from a synthetic policy flag. Existing controlled source traces and
captured quarantine process fixtures remain part of the portable qualification;
they do not substitute for these outstanding live authorization scenarios.

The live owner oracle also compares each packed file's mode, mtime, flags,
xattrs and ACL before unpacking. This independently catches the distinction
between always copying stat inside PACK and the optional outer permission reset.

`go run scripts/verify-appledouble-object-authorization.go` requires
noninteractive `sudo -n` and qualifies sixteen additional combinations of actual
root versus the existing `nobody` identity, PACK versus UNPACK, destination modes
0400 versus 0666, and stat selection. Its root supervisor creates only disposable
fixtures. Children receive held descriptors before dropping privileges, clear
supplementary groups, and assert their real and effective UID. Native C and Go
results, failure errno, output bytes and independent C metadata readback must
agree. For the independently observed nonowner PACK case whose final stat cannot
restore source time, each write-generated mtime must fall within its own measured
invocation interval. Actual timestamps and bounds remain in evidence; other
metadata and all output bytes still compare exactly. Cases where stat copies
source time retain exact timestamp comparisons. Missing privilege is a failing prerequisite, never a skipped test. No
account is created or changed. This supervisor is implemented; actual privileged
execution remains a CI qualification requirement on hosts without passwordless
sudo.

`go run scripts/verify-xattr-intent.go -ephemeral-runner` retains the complete
SHA-pinned Apple xattr policy sources and both architecture ASTs. It compares
4,384 controlled cases across both sandbox selectors and 2,192 actual unsandboxed
calls. It additionally creates two ad-hoc signed application bundles and requires
both the native C and pure Go helper to observe App Sandbox as active for another
2,192 policy comparisons. Merely signing a bare executable or supplying a
controlled selector does not establish this native authorization context.

The signed-app gate requires a disposable GitHub-hosted macOS runner, verified
through both the explicit flag and runner environment before creating fixtures.
macOS container-manager metadata cannot be removed through ordinary unlink even
by its owner. The gate therefore assigns its two uniquely named synthetic
containers to the runner VM's destruction lifecycle, records that prerequisite,
and checks removal of its temporary app bundles. It refuses developer-host
execution instead of silently leaving persistent containers or skipping sandbox
cases. Signing inputs, retained sources and observer hashes are artifacts; no
personal account mappings or process labels are published.

`verify-appledouble-object-sandbox.go` extends the actual sandbox predicate check
to full native/Go operations: eight ACL/stat/fork combinations each qualify PACK
and UNPACK, including quarantine, and two cases exercise actual denied source
acquisition. Its temporary entitlement scopes file access to the disposable
fixture directory; denied fixtures remain outside that grant. Packed bytes,
independent C metadata, native return codes and the actual sandbox selector must
agree. The same explicit GitHub-hosted VM prerequisite and container lifetime
apply. This harness is implemented; execution in the disposable CI sandbox is
required before the authorization row can close.
