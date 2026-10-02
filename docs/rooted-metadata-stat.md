# Rooted metadata discovery

`hostdata.StatMetadata(root, name)` observes an entry without requesting access to
its data fork or extended-attribute values. Use it when deciding whether an object
can be discovered before selecting a data or metadata operation. A data-read
denial must not be mistaken for an undiscoverable file.

The immediate consumer is codesign bundle discovery: macOS can select Info.plist
when an executable's metadata cannot be discovered, but a denied read on a selected
executable must fail without removing the plist's signature. Go's Windows rooted
stat currently opens with generic read access, which includes FILE_READ_DATA and
FILE_READ_EA. Using that operation as a metadata-only authorization check conflates
these cases.

The API runs on Linux, macOS and Windows. Unix uses rooted `Lstat`. Windows reuses
the existing relative NT metadata opener with `SYNCHRONIZE | READ_CONTROL |
FILE_READ_ATTRIBUTES`. It does not request data or EA read access. Its parent is
held through `os.Root`, its final component is opened without following a reparse
point, and an escaping intermediate link is rejected. It returns the entry's own
identity, including for dangling or external final symlinks. It never reads data,
changes ACLs, enables backup privilege or shells out in production.

Permission results still follow the actual host filesystem. On NTFS,
[listing the parent also grants child-attribute visibility](https://devblogs.microsoft.com/oldnewthing/20150428-00/?p=44994).
A deny-READ_ATTRIBUTES ACE alone therefore does not prove that discovery is
inaccessible. The acceptance test denies parent listing as well, checks that the
metadata query actually fails with permission denied, then restores access and
requires the query to succeed. This does not claim Linux, Darwin and Windows ACLs
are interchangeable.

The returned `os.FileInfo` is an observation, not an authorization token for a
later write. Consumers must acquire a contained handle and verify identity before
mutation. The existing `OpenMetadataFile` and `OpenMetadataFileRead` now use this
metadata-only observation for their before/after identity checks. Windows can
acquire a metadata handle when file-data reads are denied; the read-only opener
still requires EA reads because that is part of its broader metadata contract.

## Qualification

The existing `go run scripts/verify-held-metadata.go` gate includes every new
production file and its hashes. It continues to require coverage above 95% per
file, the complete existing test count, and no skipped tests. New tests cover:

- Files, directories, internal/final/external/dangling symlinks, inode identity and
  no-follow behavior; escaping intermediate links and invalid names.
- Missing and closed-root error identity.
- Effective denied file-data reads on all three hosts, with successful metadata
  discovery and unchanged contents afterward.
- Effective denied metadata discovery and recovery on all three hosts.
- Windows metadata-handle acquisition despite data-read denial, and discovery
  despite denied EA reads while the broader metadata opener remains denied.

Native macOS and Windows permission tests use temporary fixtures and host ACL tools
only in tests. The normal CI platform matrix, native capture/replay, image and
large-resource-fork harnesses, race/fuzz and existing quality gates remain in place.
There is no reduced Windows feature profile or local consumer metadata codec.
