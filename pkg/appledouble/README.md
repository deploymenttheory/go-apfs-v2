# AppleDouble

AppleDouble stores macOS file metadata in a separate file, usually named
`._<filename>`. For example, `._Report.pdf` can carry the Finder information,
resource fork and extended attributes belonging to `Report.pdf`.

`pkg/appledouble` reads and writes those metadata bytes in pure Go. It also
interprets serialized macOS ACLs (access control lists) and quarantine envelopes.
The same implementation
works on Linux, macOS and Windows without cgo, macOS commands or access to a host
account database.

## Why this package exists

Copying a file's main contents is not always enough to preserve the file.
Resource forks can contain additional content; Finder information affects how
macOS presents a file; extended attributes can carry application and security
metadata. Archives and filesystems may need a separate place to store it.

AppleDouble provides that container. This package gives image tools, package
builders and metadata-preservation tools a shared way to interpret it, so each
consumer does not need to implement its own binary codec or require a Mac just
to process the bytes.

## When to use it

| Situation | Use this package to |
| --- | --- |
| Reading an archive or package payload containing `._` files | Decode the sidecar and inspect the metadata belonging to its companion file. |
| Building a package or archive that carries macOS metadata | Encode captured metadata into an AppleDouble sidecar. |
| Preserving metadata across filesystems or operating systems | Encode and decode the metadata container used by the surrounding transport layer. |
| Inspecting a serialized `com.apple.acl.text` record | Convert between ACL text, structured entries and portable external binary bytes. |
| Inspecting a serialized `com.apple.quarantine` record | Parse its envelope or construct canonical serialized quarantine bytes. |

The package operates on bytes. Filesystem reads/writes, choosing where to store a
sidecar, resolving filename conflicts and applying permissions belong to the
surrounding metadata layer. Shared filesystem operations live in `pkg/hostmeta`;
full AppleDouble transport integration is on the roadmap below.

## What it provides

- **Sidecar encoding and decoding:** `File`, `Attr`, `FromXattrs`, `Encode` and
  `Decode` carry FinderInfo, resource forks and extended-attribute records.
- **Logical metadata:** `Xattrs` resolves ordinary duplicate attributes and the
  implemented FinderInfo/resource-fork write semantics. `File.Attrs` retains
  ordered records for consumers that need to inspect them directly.
- **Naming helpers:** `IsSidecarName`, `SidecarName` and `OwnerName` work with
  sidecar path names. The caller is responsible for establishing which files
  actually belong together.
- **ACL conversion:** `ParseACLText` and `ParseACLBinary` produce an `ACL`.
  `MarshalBinary` exports portable `acl_copy_ext` bytes; `MarshalText` formats
  canonical text using UUIDs. `FormatText` accepts a source UUID-to-account resolver
  when names and IDs are needed. Name/UID/GID-only text input requires an
  `ACLResolver` using source identity information.
- **ACL update decisions:** `File.ACLUpdate` selects the last nonempty ACL record
  and reports whether to preserve or replace the destination ACL. Malformed text
  is explicitly marked as ignored; a valid zero-entry ACL requests clearing.
- **Quarantine conversion:** `ParseQuarantine` reads the serialized `q/` envelope;
  `Quarantine.MarshalBinary` writes canonical bytes. These APIs handle escaping,
  field limits and native parsing quirks without applying destination policy.
  The default targets macOS 27. The `WithProfile` variants explicitly select
  macOS 26 or 27 behavior on any supported operating system.
- **Quarantine application planning:** `Quarantine.PlanApplication` computes exact
  destination bytes, preservation decisions and specific errors for qualified
  effective process contexts, including explicitly confirmed process-label absence
  for the macOS 26 target profile. It requires explicit process/destination state and
  an injected timestamp; it never reads the Go host's policy. See
  [application planning](../../docs/appledouble-quarantine-application.md) for
  supported contexts and the remaining transport work.
- **Filesystem quarantine import:** `ParseQuarantineXattr` and its `WithProfile`
  variant interpret a captured filesystem xattr, including its separate stored
  size limit. The caller supplies the bytes and handles filesystem read errors.
- **Quarantine update decisions:** `File.QuarantineUpdates` preserves record order
  and reports ignored malformed records. Optional resolved source quarantine
  state overrides each matching record, including empty records.

Always check encoding and decoding errors. FinderInfo must contain exactly 32
bytes. `Sniff` is a format hint; `Decode` performs validation. Canonical encoding
can change padding or layout while preserving logical metadata.

ACL and quarantine parsing are explicit. The raw codec preserves ACL and
quarantine payloads;
executing ACL update decisions or restoring quarantine state is a
separate operation. Binary ACL conversion retains unknown bits and entry kinds;
text formatting follows macOS by emitting only known bits and allow/deny entries.
Use the binary representation when those additional details must be preserved.

## Example

```go
import "github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"

func encodeMetadata(attrs map[string][]byte) ([]byte, error) {
    return appledouble.FromXattrs(attrs).Encode()
}

func decodeMetadata(sidecar []byte) (map[string][]byte, error) {
    metadata, err := appledouble.Decode(sidecar)
    if err != nil {
        return nil, err
    }
    return metadata.Xattrs(), nil
}
```

The caller supplies or consumes the metadata map and handles filesystem access.
Use `File.Attrs` instead of the map when duplicate record order matters.

## Roadmap

The remaining work is ordered around completing metadata policy before integrating
filesystem transport:

1. **Complete ACL application and transport.** Integrate deferred replacement
   decisions with source identity transport, inheritance, ownership, file flags
   and destination write-failure handling.
2. **Complete quarantine context and transport qualification.** Extend the
   [controlled runtime evidence](../../docs/appledouble-quarantine-runtime.md) and
   application planner to unresolved process contexts (including absence on macOS
   27), production raw-agent capture and destination kinds. Integrate ordered plans with destination cleanup,
   source-state capture and write-failure handling. Raw existing values, including
   malformed metadata, are handled by `ExistingXattr`; see
   [destination-state policy](../../docs/appledouble-quarantine-existing.md).
3. **Resolve large-value and allocation behavior.** Qualify oversized attributes,
   aggregates and resource forks. Resolve the difference between native packing
   of values above 16 MiB and the codec's preservation behavior, and between
   native sequential handling and the decoder's cumulative alias-allocation guard.
4. **Integrate shared filesystem transport.** Preserve metadata for files,
   directories, roots and links through `pkg/hostmeta`. Handle native write refusal,
   normalization, carrier conflicts and path safety without losing metadata on
   Linux, macOS or Windows. Prove APFS/HFS+ extract-and-repack preservation.
5. **Qualify consumers and release.** Require native macOS comparisons, more than
   95% codec unit coverage on all three operating systems, and downstream package
   validation before adopting the completed APIs in codesign.

For implementation detail, see the [migration and implementation plan](../../docs/appledouble-migration.md).
The native investigations document [sizes](../../docs/appledouble-native-sizes.md),
[names](../../docs/appledouble-native-names.md),
[records](../../docs/appledouble-native-records.md),
[FinderInfo/resource forks](../../docs/appledouble-native-special.md),
[ACLs](../../docs/appledouble-native-acl.md) and
[quarantine](../../docs/appledouble-native-quarantine.md).
