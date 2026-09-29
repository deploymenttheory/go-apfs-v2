# ACL policy for ordinary file copies

`appledouble.CopyACL(source, destination)` prepares the ACL for the ordinary
`COPYFILE_ACL` stage. It keeps explicit source entries, followed by inherited
destination entries, preserving their order, UUIDs and entry bits. It discards
source inherited entries, destination explicit entries and global ACL flags.
Use it when planning security for a copied filesystem object whose source and
destination ACLs have already been captured.

This policy runs in pure Go on Linux, macOS and Windows. It does not read host
accounts, apply permissions, call macOS or translate Darwin ACLs into Windows or
Linux authorization rules.

## Choosing the operation

| Operation | API | Effect |
| --- | --- | --- |
| Create a new object beneath a parent | `InheritACL` | Derives eligible inherited entries, adjusting propagation flags |
| Copy an existing object's ACL | `CopyACL` | Explicit source entries, then already-inherited destination entries |
| Restore a valid AppleDouble ACL record | `ACLUpdate.FileSecurity` / `hostmeta.RestoreACL` | Replaces the destination ACL, retaining captured ownership |

These operations are not interchangeable. In particular, an AppleDouble
replacement after a copy must not retain the merged inherited entries.

## Input, output and errors

A nil input means confirmed absence, not a failed read. Both inputs nil return
nil. If either input is present, an empty result remains a present ACL with zero
global flags; a filesystem may subsequently normalize it to absence. The result
owns its storage, and neither input is changed or retained.

Each input must contain at most 128 entries. The result limit counts only entries
that survive selection: two 128-entry inputs can be valid if enough entries are
discarded. This differs from creation inheritance's allocation rule. Exceeding
an input or result limit returns a nil result and `ErrACLCopy`; no partial ACL is
returned. Apple's native merge reports `ENOMEM` for an oversized selected result.
The portable error describes the policy limit rather than pretending a local
allocation or filesystem operation occurred.

Retained entries keep unknown bits and entry kinds, including duplicate entries.
Use binary serialization to preserve these details: ACL text formatting emits
only the known text representation. Global flags, including `no_inherit`, are
discarded by this copy stage rather than suppressing the destination merge.

## Native qualification

The oracle pins Apple's [copyfile source](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c)
at SHA-256 `19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`.
It retains the complete, unchanged `copyfile_security` function, its POSIX-clear
and volume-feature helpers, and the relevant original flag definitions.

Two independent measurements are required:

- **256 policy cases:** real libSystem ACL and filesec operations run through
  the unchanged function. Destination capture supplies the explicit input ACL;
  the final chmod boundary records the selected request rather than writing a
  file. There are 235 successes and 21 native `ENOMEM` refusals. Failed selection
  performs no write and retains the source cache; successful selection updates
  that cache. Binary fixture inputs preserve unknown bits and entry kinds.
- **288 real file/directory copies:** public `fcopyfile(COPYFILE_ACL)` copies
  actual APFS objects (the helper verifies the filesystem type). There are 270 successes and 18 `ENOMEM` refusals.
  The Go policy is compared with the observed destination ACL using the actual
  captured inputs. Source metadata, destination ownership/mode/flags, object
  identity and distinct source/destination payloads are checked. Directory
  payloads use child sentinel files. Refused copies retain the original ACL.

The matrix includes absent/empty ACLs, global flags, grants/denials, explicit and
inherited entries, propagation flags, unknown bits, mixed ordering and
64/127/128-entry boundaries. The model qualifies request selection independently
of filesystem normalization; the actual copies qualify its measured application.
The capture boundary does not simulate authorization or claim to test native
write failures.

Run `CGO_ENABLED=0 go run scripts/verify-appledouble-acl-copy.go` on macOS.
`-capture` records unapproved observations. Normal qualification checks policy
results and requires the archived `acl-copy.json.gz` corpus, normalizing only
host account IDs. Reports retain the pinned full source, unchanged extracted
functions, helper hash, arm64/x86_64 Clang ASTs, raw binary inputs, command output,
actual copy objects and host/revision details.

All three OS jobs replay the required corpus without skips. The AppleDouble
coverage gate additionally enforces over 95% independently for `acl_copy.go`.
Unit tests check invalid input bounds, nil/empty distinctions, ownership of result
storage and later AppleDouble replacement; `FuzzCopyACL` checks bounds, wire
round-trips, input immutability and discarded-entry behavior.

## Remaining work

This provides selection policy, not a complete `COPYFILE_SECURITY` backend. It
does not copy numeric/UUID ownership, implement copyfile's fallback writes or
coordinate source-cache mutation, stat changes and final AppleDouble restoration.
Production capture/write adapters, live source identities, privileged/sandbox
contexts and full restoration ordering remain open. So do the other
[roadmap gates](../pkg/appledouble/README.md#roadmap). Package PR #72 stays draft,
and codesign remains paused until APFS qualification, release and downstream adoption.
