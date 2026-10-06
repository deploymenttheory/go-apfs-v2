# Foreign recompression authority

A metadata carrier retains Darwin mode, ownership, flags and ACL bytes. These
values do not grant access to storage on the receiving machine. Recompression
checks the explicitly supplied foreign identity against that metadata, while
normal host permissions continue to govern access to carrier and payload files.

`recompression.Authority` supplies the effective UID, complete numeric group
membership, user UUID and recorded UUID membership outcomes. A missing UUID
observation fails when an ACL decision needs it. A recorded lookup failure is
separate: the source kernel treats unresolved permit and deny entries differently.
No Linux or Windows account is substituted for a Darwin principal.

The evaluator covers the regular-file operations used by this recompression
provider. It evaluates ordered ACL entries and residual POSIX permissions, named
resource-fork access, immutable/append flags, read-only mounts, attribute writes,
mode changes and explicit timestamp restoration. Owner security rights are
resolved before ACL evaluation; ownership grants residual timestamp rights only
after an ACL has had the opportunity to deny them. Requested set-ID mode bits
receive their own ownership/group checks.

A writable descriptor retains its admitted data-write capability. A later mode
or ACL change does not turn `ftruncate` into a new pathname authorization check.
The independent native probe also retains the difference between immutable and
append flags set after acquisition. The carrier operation itself requires callers
to exclude unrelated metadata and data mutations throughout its lifetime.

Resource-fork authorization uses the explicit macOS target. The existing complete
recompression profiles demonstrate a macOS 15 versus 26/27 difference for denying
read access to extended attributes. A resource-fork creation also checks write
access to the base file. These are operation checks rather than a single initial
permission boolean.

This identity model does not claim to reproduce sandbox profiles, process
entitlements that override discretionary access, remote authorization servers or
other uncaptured process policy. Preserving those metadata bytes is not evidence
that those policies have been evaluated. Broader process-context qualification
remains necessary before a general native-authorization parity claim.

## Evidence

The full Apple source bodies and their original license headers are retained in
[`recompression-access-source`](../testdata/appledouble/native/recompression-access-source).
Its `sources.json` identifies exact raw URLs and SHA-256 hashes for XNU
`xnu-11417.140.69`. Portable tests verify all four bodies:

- `kern_authorization.c`: ordered `kauth_acl_evaluate` and generic rights.
- `kern_credential.c`: well-known UUID recognition and membership lookup behavior.
- `vfs_subr.c`: owner/group decisions, residual POSIX permissions, immutable
  checks, named-stream rights translation and attribute-change authorization.
- `vfs_syscalls.c`: admitted descriptor truncation, explicit timestamp error
  translation and the flag-change call path.

These are source evidence, not execution of a compiled XNU kernel. The two
architecture ASTs in each native capture describe the probe and SDK declarations;
they must not be described as execution or compilation of the kernel policy body.

`recompression-access.c` independently executes 168 file operations. It retains
actual credentials, requested raw filesec bytes, readable ACL bytes and any ACL
observation error. Generic rights use the raw filesec interface because the
public ACL permission-mask setter rejects them. No denied observation is replaced
with a fabricated successful read. Every retained access outcome is compared with
the production Go evaluator.

`recompression-open.c` separately installs the exact valid type 15/16 LZ4 storage
from the existing native corpus and calls `open(O_RDWR)` directly. It retains
compression attributes, resource-fork bytes, flags and size before opening, after
opening and after closing, together with the logical bytes and actual open/read
errors. A framework codec failure is never substituted for a kernel open result.

Capture on each supported host using:

```sh
go run scripts/capture-recompression-access.go -out artifacts/recompression-access/native.json.gz
APFS_RECOMPRESSION_ACCESS_CAPTURE="$PWD/artifacts/recompression-access/native.json.gz" go test ./pkg/recompression -run '^TestRecompressionAccess'
```

The artifact path supplied to the test must be absolute when invoking `go test`
from the repository root, because the test process runs in its package directory.
Use `-check` once the genuine host-profile baseline is retained; it independently
recaptures and compares every operation and complete compressed-open observation.
Both arm64 and x86_64 AST files and source/SDK hashes remain in the artifact set.

The new standalone corpus currently retains macOS 27 observations. Fresh macOS
15 and 26 captures are required before declaring this additional corpus qualified
on all three releases. The earlier mandatory 990 recompression observations and
540 resource-fork opening observations continue to apply without removal.
