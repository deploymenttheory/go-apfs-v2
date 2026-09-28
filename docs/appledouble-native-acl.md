# Portable AppleDouble ACL interpretation

`pkg/appledouble.ParseACLText` interprets the serialized `com.apple.acl.text`
record on Linux, macOS and Windows without cgo or a host account database.
`ACL.MarshalBinary` produces the portable, big-endian representation returned
by Darwin's `acl_copy_ext`. This increment supplies a policy primitive; it does
not yet apply ACLs during APFS/HFS+ extraction or packing.

## Independent source and native evidence

The investigation uses Apple's [Libc acl_translate.c at
71bbe350ab79eef58113991d817ccc6165061a64](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/posix1e/acl_translate.c).
Its SHA-256 is
`929b16ba8d52527c1bb4812ed7ed25f3e43f315516898d1bd777a10ca690e4c2`.
The native fixture was recorded on macOS 27.0 (26A428) with an independent C
helper calling public libSystem ACL functions. Neither the helper nor Apple's
source is linked into the SDK.

`testdata/appledouble/native/acl.json` retains 59 input cases, native acceptance,
diagnostics, exact `acl_copy_ext` bytes, canonical native text and input hashes.
Portable unit tests compare against those independent bytes on all three OSes.
The cases cover headers and numeric prefixes, allow/deny, all 14 permission
names, all five entry flags, ACL-wide flags, malformed fields and UUIDs, ignored
fields, NUL/blank-line termination and the 128/129-entry boundary.

Run from the repository root on a Mac:

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble-acl.go
```

The CI oracle downloads and verifies the pinned source, extracts the **complete
unchanged `acl_from_text` function and token tables**, and records Clang ASTs
for arm64 and x86_64. Public SDK includes provide declarations; this is syntax
analysis, not compilation of all Libc. It also records helper ASTs, SDK structure
layouts/static assertions, host/SDK/compiler identity and every subprocess result.
The helper source hash must match the fixture provenance.

Every parser case is rerun through current libSystem and Go. Both must agree
with the archived acceptance and exact binary output. Expected native parser
refusals require exit status 1 and the parser diagnostic; setup failures fail CI.
For both a file and a directory, the oracle additionally:

1. Sets a native ACL with an explicit principal UUID, packs it with `copyfile`,
   and compares Go's interpretation with `acl_get_file`/`acl_copy_ext`.
2. Encodes the original ACL text into a Go AppleDouble sidecar, has native
   `copyfile` unpack it, and compares the actual destination ACL bytes.

Artifacts under `artifacts/appledouble-acl` retain inputs, raw sidecars, native
and Go external bytes, native canonical text, source, ASTs and a pass/fail report.
All filesystem mutations are confined to fresh harness-owned test paths.

## Parsing and identity contract

The native dialect deliberately accepts some unusual input. This parser follows
those observations instead of imposing a stricter authoring grammar:

- Header versions use a C-style numeric prefix; trailing fields can be ignored.
- NUL terminates input and an empty entry line ends entry parsing.
- Explicit UUIDs take precedence over names and numeric IDs. Invalid UUID text
  becomes the zero UUID in the observed native parser.
- Empty comma tokens terminate flag/permission lists. An empty action token
  before a comma can yield an inert entry, retained in external bytes.
- At most 128 entries are accepted. Order and duplicate entries are preserved.

Name/ID-only entries require an `ACLResolver` supplied by the caller. The request
specifies user/group and either a name or a numeric UID/GID. Resolution must use
**source identity information**, not the account database of the Windows/Linux
machine processing the image. No resolver returns `ErrACLResolver`; it never
silently discards an entry. Explicit UUID records need no resolver.

A source lookup with no matching account returns a zero UUID and nil error,
matching native parsing. Directory-service failures return an error, propagated
to the caller. Names take precedence over numeric IDs; UID/GID parsing retains
native numeric-prefix and 32-bit conversion behavior. Resolver tests exercise
this callback contract; they do not claim equivalence between different hosts'
account databases.

The external binary is a 44-byte `kauth_filesec` header followed by 24 bytes per
entry. Owner/group UUID header fields are zero, as in `acl_copy_ext`; the API
represents an ACL, not ownership or an entire filesystem security policy. This
is the portable big-endian export, not `acl_copy_ext_native` or a claim that an
APFS on-disk security record has the same representation.

`Decode`, `Encode` and `Xattrs` continue to preserve raw serialized ACL records.
Parsing is explicit: invalid ACL policy text does not invalidate an otherwise
readable AppleDouble container. Applying deferred/duplicate ACL records, native
inheritance, ownership/file flags and destination policy remains separate work.
Canonical ACL text formatting and external-binary import are not yet supplied.

## Quarantine finding and remaining gate

Initial native research shows that a packed quarantine record contains `q/`,
then quarantine text, then NUL. Plain xattr text alone was not restored by the
native unpacker. With a valid native envelope, unpacking refreshed the timestamp
and agent fields; setting an initial `0001` flag produced `0081` on the observed
host. These are preliminary observations, not a complete quarantine API or a
portable fixture qualification claim. The next policy increment must retain
independent envelope and runtime-context fixtures before implementing this.

Remaining work includes ACL application/formatting and source identity transport,
quarantine normalization, remaining size/allocation policy and shared host metadata
transport. Package PR #72 remains draft and codesign remains paused. This parser
increment alone does not satisfy the APFS release gate.
