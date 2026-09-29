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
- **Complete security records:** `FileSecurity` preserves owner/group UUIDs, ACLs
  and opaque bytes in disk and Darwin memory byte orders. `ACLUpdate.FileSecurity`
  prepares a replacement using captured destination ownership. See
  [security records and native write refusals](../../docs/appledouble-filesec.md).
- **ACL creation inheritance:** `InheritACL` computes a new file or directory's
  ACL from captured parent and initial ACLs, including propagation flags and
  allocation limits. It runs on every supported OS without applying host
  permissions. A subsequent valid AppleDouble ACL update replaces this result;
  see [creation and restoration](../../docs/appledouble-acl-inheritance.md).
- **ACL copy policy:** `CopyACL` keeps explicit source entries followed by
  inherited destination entries, preserving entry order and bits while dropping
  global flags. It is distinct from creation inheritance and AppleDouble
  replacement. See [ordinary ACL copies](../../docs/appledouble-acl-copy.md).
- **Source identity capture and replay:** `NewACLIdentityCapture` records the
  source callbacks used during parsing and formatting. Its serializable snapshot
  supplies immutable resolvers on any supported OS, preserving confirmed absence
  and rejecting uncaptured queries. See [source identities](../../docs/appledouble-acl-identities.md).
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

**Five completion gates remain open: four implementation areas and final
qualification/release.** Work is currently in ACL application. The codec and
many policy components are implemented; end-to-end filesystem preservation is
not complete. Code coverage measures the implemented code, not the percentage
of this roadmap delivered. These phases are not estimates of remaining PR count.

| Phase | Current state | Completion gate |
| --- | --- | --- |
| 1. ACL application | Policy, requests and controlled owner/non-owner cases qualified; production integration open | Source acquisition, authorization, actual writes and restoration ordering qualified together |
| 2. Quarantine | Conversion and much of application policy implemented; context/integration gaps open | Remaining process contexts and ordered restoration qualify against native behavior |
| 3. Large values and allocation | Known native differences remain | Oversized values, aggregates, forks and allocation policy have explicit, tested behavior |
| 4. Shared filesystem transport | Host metadata primitives available; preservation integration outstanding | APFS/HFS+ extract-and-repack preserves logical metadata on all three OSes |
| 5. Consumers and release | Component CI and downstream checks exist; final gate blocked by phases 1–4 | Qualified APFS release adopted by package tooling before codesign resumes |

1. **ACL application and transport.** Implemented: deferred replacement,
   creation inheritance, [ordinary copy selection](../../docs/appledouble-acl-copy.md),
   captured identity replay, full security records,
   [write/retry execution](../../docs/appledouble-acl-restoration.md),
   [attribute records](../../docs/appledouble-acl-attributes.md) and
   [extended chmod request preparation](../../docs/appledouble-acl-chmod.md),
   including [optional properties and removal](../../docs/appledouble-acl-chmod-properties.md),
   plus [ordinary security execution and fallbacks](../../docs/appledouble-security-copy.md).
   Native extended chmod comparisons resolve the measured attribute/copyfile
   refusal and empty-ACL flag differences for the qualified owner-operated cases.
   **Remaining:** production call/capture adapters, live source acquisition,
   privileged/sandbox authorization contexts and full restoration ordering.
   [Owner/non-owner image tests](../../docs/appledouble-acl-nonowner.md) qualify
   ordinary-user APFS/HFSX grants and denials and fix HFS security catalog flags.
   The request builder is not a completed native backend; foreign metadata carriers are integrated
   in phase 4.
2. **Quarantine context and transport qualification.** Implemented: serialized
   and filesystem conversion, ordered updates, application planning, raw
   destination-state handling and file/directory/symlink destination policy.
   **Remaining:** unresolved process contexts (including absence on macOS 27),
   production raw-agent capture, destination protection, source-state capture,
   cleanup and write-failure integration. See [runtime evidence](../../docs/appledouble-quarantine-runtime.md),
   [application planning](../../docs/appledouble-quarantine-application.md) and
   [destination state](../../docs/appledouble-quarantine-existing.md).
3. **Large-value and allocation behavior.** Basic native size boundaries have
   tests. **Remaining:** values above 16 MiB, aggregate and resource-fork limits,
   the native packing versus lossless-codec difference, and native sequential
   handling versus the decoder's cumulative alias-allocation guard. Each
   difference needs a qualified policy, not an implicit metadata-loss success.
4. **Shared filesystem transport.** Strict native xattr primitives are available
   in `pkg/hostmeta`. **Remaining:** integrated preservation for files,
   directories, roots and links; native write refusal/normalization; empty values,
   logical names and large forks; carrier conflicts and path safety. Prove
   logical name/value preservation through APFS/HFS+ extraction and repacking on
   Linux, macOS and Windows, with independent Mac validation of foreign-host output.
5. **Consumers and release.** Component native comparisons, greater than 95%
   codec unit coverage and downstream package tests are ongoing gates.
   **Remaining:** qualify the completed integration, release APFS through the
   repository release process, update draft package PR #72 to that published
   version and rerun downstream validation. Keep PR #72 draft until then.
   Resume codesign only after the qualified APFS release and downstream adoption.

For implementation detail, see the [migration and implementation plan](../../docs/appledouble-migration.md).
The native investigations document [sizes](../../docs/appledouble-native-sizes.md),
[names](../../docs/appledouble-native-names.md),
[records](../../docs/appledouble-native-records.md),
[FinderInfo/resource forks](../../docs/appledouble-native-special.md),
[ACLs](../../docs/appledouble-native-acl.md) and
[quarantine](../../docs/appledouble-native-quarantine.md).
