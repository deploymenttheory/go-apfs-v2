# ACL authorization on SDK-written APFS and HFS+ images

An ACL must both survive image creation and take effect when macOS mounts the
image. The HFS+ writer now sets `HFSHasSecurityMask` (`0x0008`) alongside
`HFSHasAttributesMask` when a catalog node stores `com.apple.system.Security`.
Previously the bytes were present but macOS could ignore them during access
checks. This fixes both ignored grants and ignored denials. It applies to HFS+
and HFSX images created on Linux, macOS and Windows.

The flag follows the stored attribute's exact name and presence, including an
empty value; it does not parse or rewrite security bytes. Files, directories,
roots and symlinks receive the appropriate catalog flags. Hard-link names do not
claim attributes belonging to their shared indirect inode; that inode gets the
flags. Ordinary attributes and differently cased names retain their prior flags.
Images containing security attributes intentionally change catalog bytes. Images
without them follow the same serialization as before.

## Native proof

The required native harness builds disposable APFS and HFSX images using this
SDK, then mounts them with ownership enforcement. An ordinary non-root process
compares unchanged Apple copyfile ACL restoration against Go `RestoreACL` and
`DarwinChmodRequest` consumed by libSystem's extended chmod operation. Native
helper processes are test-only: the production writer and request/execution
policies remain pure Go, with no macOS dependency.

The 1,152 pairs cover both filesystems, files/directories, owner/non-owner,
primary-group member/nonmember, read-only/world-writable POSIX modes, nine
starting ACL profiles and four replacements. Foreign UID/GID 60000 are checked
against the actor and supplementary groups. Each helper verifies actual numeric
ownership, filesystem type, writable mounting and ownership enforcement before
running. No privileged account changes or injected authorization errors are used.

Profiles include absent and empty ACLs, everyone write-security grant/denial,
read-security denial, allow-before-deny and deny-before-allow, inheritance-only
permission and an unrelated UUID. Replacements are absent, malformed, empty and
nonempty. In each filesystem the measured outcomes are:

| Outcome | Pairs |
| --- | ---: |
| No-op, with no capture or write | 288 |
| Successful write | 160 |
| Write refused with `EPERM` | 96 |
| Capture refused with `EACCES`, no write | 32 |

Owner implicit authority permits security writes despite the tested explicit
write denial. A non-owner needs the applicable write-security grant; POSIX write
bits or primary-group membership alone do not confer that authority. Ordering
and inheritance-only flags affect whether the tested grant applies. Explicit
read-security denial stops capture for owners and non-owners, while no-op
updates do not attempt that capture.

Native and Go paths must agree on return code, errno, operation counts, request
results, full security/attribute observations, numeric ownership, mode, flags
and held-object identity. After detaching, SDK readers compare complete attribute
maps and file contents for both paths. Failed/no-op writes must preserve the
original security bytes even where the mounted process cannot read them.

Apple's pinned [HFS vnode source](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/hfs_vnops.c)
uses the security catalog bit to decide whether ACL lookup is needed; its
[xattr source](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/hfs_xattr.c)
sets/clears that bit with the security attribute. Both full files and SHA-256
hashes are retained. The harness also retains the unchanged pinned copyfile
functions, arm64/x86_64 Clang ASTs, command transcripts, native seed exports,
raw requests/responses, image hashes and post-run images. The HFS kernel files
are source evidence; native mounted-volume tests supply execution evidence.

Run `CGO_ENABLED=0 go run scripts/verify-appledouble-filesec.go` on a Mac.
`-capture` records unapproved observations; normal qualification compares them
against required `acl-nonowner.json.gz`, normalizing only numeric host account
IDs. All preceding security, restoration, attribute and chmod matrices remain
mandatory. Portable tests replay the corpus without skips on all three OSes.
The focused gate independently requires over 95% coverage for each restoration,
attribute, chmod-request and HFS catalog-flag implementation file. HFS+/HFSX
image tests check root/file/directory/symlink/hard-link flags and unchanged data.

## Remaining work

These are controlled ordinary-user authorization contexts, not a general Darwin
authorization evaluator. Privileged processes, sandbox restrictions, live
identity acquisition and full restoration ordering remain unqualified. Native
mounting here uses HFSX; portable catalog round-trips cover HFS+ and HFSX. Native
hard-link/symlink/root authorization is outside this matrix.

Production call/capture adapters and foreign metadata carriers still need
integration. The [five roadmap gates](../pkg/appledouble/README.md#roadmap) remain
open. Package PR #72 stays draft; codesign remains paused until the completed
integration is qualified, APFS is released and downstream adoption is verified.
