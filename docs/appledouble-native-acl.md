# Portable AppleDouble ACL interpretation

`pkg/appledouble.ParseACLText` interprets the serialized `com.apple.acl.text`
record on Linux, macOS and Windows without cgo or a host account database.
`ACL.MarshalBinary` produces the portable, big-endian representation returned
by Darwin's `acl_copy_ext`; `ParseACLBinary` imports it. `MarshalText` and
`FormatText` provide native-style canonical formatting. This increment supplies a policy primitive; it does
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
readable AppleDouble container. Deferred/duplicate record selection is available through `File.ACLUpdate`;
executing the result, native inheritance, ownership/file flags and destination
write-failure policy remain separate work.
Canonical text formatting and external-binary import are described below.

## Quarantine finding and remaining gate

The [quarantine codec and native investigation](appledouble-native-quarantine.md)
now cover serialized envelope parsing and canonical output. Independent
application observations distinguish fresh-file and directory behavior; runtime
normalization remains separate policy work.

Remaining work includes ACL application and source identity transport,
quarantine normalization, remaining size/allocation policy and shared host metadata
transport. Package PR #72 remains draft and codesign remains paused. This parser
increment alone does not satisfy the APFS release gate.

## Binary import and canonical text

Use `ParseACLBinary` to read a portable `acl_copy_ext` blob, and `MarshalBinary`
to export it again. The importer checks the magic, maximum 128-entry count and
available bytes before accessing entries. Native `acl_copy_int` has no length
argument; the Go API explicitly rejects truncated buffers with `ErrACLBinary`.
The native test helper refuses to submit truncated buffers for unsafe reads.
Those truncation checks are Go safety tests, not native acceptance comparisons.

Owner/group UUID header fields and trailing bytes are ignored by native import.
Export consequently zeroes the owner/group fields and emits just the ACL extent.
Entry order, unknown rights/flags and all entry kinds are retained in the model
and binary export. Parsed principals do not alias the caller's input bytes.

`MarshalText` emits native token order, uppercase UUIDs, a final newline and no
NUL terminator. Like native `acl_to_text`, it omits entry kinds other than allow
and deny, omits unknown bits, and omits the permission colon when there are no
known permissions. Binary → text → binary is therefore not generally lossless.
Retain binary/model data when those omitted details matter. Native AppleDouble
packing appends a NUL to the text; the filesystem oracle verifies that payload
including its terminator.

`FormatText` accepts an `ACLPrincipalResolver` for source UUID-to-account lookups.
A match supplies `ACLPrincipal{Group, Name, ID}`. Without a match, native syntax is
`user:UUID:::` even when the original text used `group`. `MarshalText` uses that
unknown-account form for every principal; it never queries the receiving host.
The resolver's names are source data, emitted verbatim up to a C-string NUL.
Numeric IDs use native signed 32-bit decimal formatting. Callback failures are
surfaced to the caller rather than silently treated as an unknown account; a
caller wanting fallback must explicitly return `found=false, err=nil`.

The new `acl-external.json` fixture contains 34 independent macOS observations:
31 accepted and three rejected. It covers every entry kind, known/unknown global
and entry flags, rights ordering, ignored owner/group fields, trailing bytes,
invalid magic and 0/128/129/0xffffffff counts. Accepted records retain exact
native binary re-export and canonical text. The existing 59 text cases now also
compare native canonical text, including omitted inert entries.

The required native harness replays these fixtures and adds two identity cases:
source `root` and `wheel` are resolved by the independent native helper, then
Go formats their actual UUIDs using explicit source account details. The test
does not assume a fixed UUID or make host lookups part of production code. File
and directory checks now import the actual native external bytes, format them
in Go, compare the native-packed ACL payload, and verify native application of
the Go-produced sidecar.

For Clang analysis, the harness downloads `aclvar.h` from the same pinned Libc
revision (SHA-256
`74711afda9818508af93ec472db57243ed45b13908a22e2bff35af9d6a8f7fd7`).
The additional translation unit retains the complete unchanged `acl_copy_int`,
`acl_to_text`, `acl_from_text`, token tables and formatting/lookup helper functions,
with the pinned private declarations and public SDK includes. It records arm64
and x86_64 ASTs for that unit and the independent external-import helper. These
are syntax-analysis artifacts; live comparisons still call the host libSystem.
Source licenses remain in the retained files.

`FuzzACLBinary` checks bounded import and stable binary/text canonicalization.
The portable unit suite exercises fixture agreement, every truncation of a
single-entry blob, input ownership and source resolver success/failure paths.

## Deferred replacement decisions

`File.ACLUpdate(resolve)` interprets the ordered ACL records for a consumer that
will apply metadata. Its `ACLUpdate` result separates three outcomes:

| Result | Consumer action |
| --- | --- |
| `ACL == nil`, `Invalid == false` | Preserve the existing ACL; there was no nonempty ACL record. |
| `ACL == nil`, `Invalid == true` | Preserve the existing ACL; native unpack ignores the selected malformed text. Report or reject this explicitly if the consumer requires stricter validation. |
| `ACL != nil` | Replace the existing ACL after restoring other metadata. A valid zero-entry ACL requests clearing entries. |

`RecordIndex` identifies the selected `File.Attrs` entry, or -1 if none was
selected. Only the last nonempty `com.apple.acl.text` record is parsed. An empty
record cannot undo an earlier nonempty record. Invalid later text prevents an
earlier valid ACL from being applied; there is no fallback. Earlier principal
names are never resolved. Missing source resolution and callback failures return
errors, including callback errors that wrap `ErrACLText`; consumers must not
mistake operational failure for an ignored malformed record.

This is a pure-Go decision API on all three OSes, with no destination mutation.
It does not merge entries with an existing ACL. It also does not translate a
macOS ACL into a Linux or Windows ACL, model every destination's inheritance or
file flags, or claim success applying permissions. Those responsibilities remain
with shared metadata transport. `Xattrs` retains its raw serialized-map behavior;
consumers needing ACL policy must use the ordered-record API explicitly.

The native fixture `acl-update.json` captures 21 cases on each of a file and a
directory, both starting with a known existing ACL. The independent helper sets
and reads that baseline, native copyfile unpacks a raw sidecar, and the helper
reads the actual destination ACL afterward. Cases include absence, empty/NUL-only
records, malformed text, clearing, allow/deny replacement, duplicates, trailing
NUL data, inert entries, zero UUIDs and global inherit flags. All 42 native
unpacks succeeded; malformed text was ignored, while valid replacements matched
the portable binary representation. Clearing a zero-flag, zero-entry ACL made
native `acl_get_file` report ENOENT. Inert entries remained in the binary ACL
although native text formatting omitted them.

Portable tests replay the raw sidecars and compare the decision's resulting ACL
with those independent before/after bytes. The native CI harness recreates each
baseline and requires the same live outcome. Expected missing-ACL readback is
accepted only for the corresponding fixture, with exit status 1, ENOENT and a
successful stat of the destination. Missing files, setup failures and unexpected
read errors fail the check. The report retains the selected record, invalid-text
flag, native equality and policy equality; raw sidecars and readbacks remain in
the ACL artifact.

The source for this decision is the pinned copyfile revision documented in the
size investigation: `copyfile_unpack` defers the last nonempty record until after
other metadata, and `copyfile_unpack_acl` ignores a failed text parse. The full
source and hash are retained in the ACL artifact. Existing AST evidence covers
Libc parsing/conversion and copyfile wire structures; this increment does not
claim to compile copyfile's private filesystem implementation. Native runtime
probes establish the observed destination behavior.
