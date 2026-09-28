# Source identities for portable ACL restoration

An AppleDouble ACL may name an account or carry a UID/GID instead of an explicit
UUID. That identity belongs to the source system. Looking up the same name or
number on a receiving Linux, Windows or different Mac can change who the ACL
refers to. Native-style text formatting also needs source UUID-to-account results.

`NewACLIdentityCapture` records those source queries while existing ACL APIs run.
`Snapshot` produces data that can travel with the source metadata, and `Resolvers`
replays it without account services, native libraries or subprocesses. All three
operations are pure Go on Linux, macOS and Windows.

Use this when an exporter has access to source identity information and an
offline importer needs to reproduce the ACL. Explicit UUID input needs no forward
lookup. If account labels are not needed when formatting, `ACL.MarshalText`
already emits UUID-only text without a reverse lookup.

## Capture, transport and replay

```go
capture := appledouble.NewACLIdentityCapture(sourceResolve, sourceLookup)
update, err := file.ACLUpdate(capture.Resolve)
if err != nil {
    return err
}
if update.ACL != nil {
    _, err = update.ACL.FormatText(capture.Lookup)
    if err != nil {
        return err
    }
}

// Store alongside this source image's metadata, not inside an invented
// AppleDouble attribute. Standard JSON preserves Name byte slices as base64.
encoded, err := json.Marshal(capture.Snapshot())
if err != nil {
    return err
}

var snapshot appledouble.ACLIdentitySnapshot
if err := json.Unmarshal(encoded, &snapshot); err != nil {
    return err
}
resolve, lookup, err := snapshot.Resolvers()
if err != nil {
    return err
}
restored, err := file.ACLUpdate(resolve)
if err != nil {
    return err
}
if restored.ACL != nil {
    _, err = restored.ACL.FormatText(lookup)
}
return err
```

The supplied callbacks must read the source's account information or an explicit
source mapping. The recorder does not supply a live directory-service adapter.
Such acquisition belongs to shared filesystem transport and is still outstanding.
An APFS/HFS+ image alone need not contain every external directory-service record.

## Lookup semantics

- Capture retains the first successful result per exact query. Name and numeric
  requests, users and groups, and aliases remain distinct. Repeated queries reuse
  their result within that capture epoch.
- Forward zero UUID means a source lookup confirmed no account. Reverse
  `found=false` means the UUID had no source account details. Both are recorded.
- An unrecorded query returns `ErrACLIdentityUncaptured`. It must not silently
  become a zero UUID or an unknown-principal formatting fallback.
- Source errors propagate and are not cached. Retrying can succeed; an error
  wrapping `ErrACLText` remains an operational error in `File.ACLUpdate`.
- Forward and reverse observations are independent. Reversing a name-to-UUID
  map cannot establish canonical account names, aliases or group classification.
- Version 1 snapshots reject duplicate query keys, duplicate UUID lookup records,
  ambiguous name/ID requests and account data attached to a negative reverse
  result. ID zero is a valid numeric request, distinct from an absent ID.
- Name byte slices preserve arbitrary source bytes through JSON. Formatting
  still applies the existing native C-string termination rules.
- Capture is sequential. Returned snapshots own their slices and ID pointers;
  validated replay callbacks also own their data and support concurrent reads.

Associate each snapshot with its source and capture epoch. The format is a partial
query record, not a universal account database or an AppleDouble wire extension.
Apply the application's size limits when reading externally supplied JSON before
validating it with `Resolvers`.

## Native verification

The required ACL CI oracle now performs 25 real source capture/replay cases and
50 file/directory AppleDouble restorations on each Mac host. It calls public
account/membership functions through a test-only C observer, independently of
native `acl_from_text`, `acl_to_text` and `copyfile` comparisons. Cases cover names,
IDs, UID/GID zero, current source user/group, absent accounts, numeric-prefix and
overflow parsing, explicit-UUID precedence, duplicate queries and ignored earlier
AppleDouble records.

Each live result must match native external ACL bytes and canonical text, survive
JSON transport and restore to those same native bytes. Portable unit tests replay
the archived source snapshot on every OS. Live CI uses the runner's actual source
accounts; it never assumes that the runner and archived Mac share account names,
UIDs or UUIDs. Operational lookup failures fail the oracle rather than becoming
successful absence cases.

The existing pinned [Libc source](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/posix1e/acl_translate.c)
and complete parser/formatter/`uuid_to_name` Clang analysis remain required.
The new observer has arm64/x86_64 ASTs and account/UUID width assertions. Artifacts
retain raw input, observer output, native parse/readback bytes, transported
snapshots, helper hashes and host identity. `FuzzACLIdentitySnapshot` checks
validation and replay; unit tests also cover errors, mutation isolation and
concurrent replay.

This provides source-query capture and portable replay. Live acquisition adapters,
restoration ordering, ownership, restrictive flags, write failures and shared
filesystem carriers remain unfinished. Package PR #72 stays draft and codesign
remains paused until the complete AppleDouble release gate is satisfied.
