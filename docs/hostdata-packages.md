# Filesystem metadata package structure

`pkg/hostdata` separates metadata operations by responsibility while keeping the
complete path/held-object lifecycle in one coordinating package. Applications
can use the small operation they need without importing lifecycle implementation
details. The namespace is project terminology; it is not a claimed Apple C API.

## Import migration

This is a breaking Go import change from `pkg/hostmeta`. The CLI flags, output,
AppleDouble format, carrier format and filesystem image formats are unchanged.
There is no second compatibility implementation or metadata policy switch.

| Previous symbol | New package and symbol |
| --- | --- |
| `hostmeta.CopyAppleDoublePath`, held object and restoration APIs | `hostdata`, same symbol names |
| `hostmeta.ACLMetadata`, `RestoreACL`, Darwin ACL/chmod records and identity capture | `hostdata/acl`, same symbol names |
| `hostmeta.CopyAccessTime`, `RecordReadAccess` and their errors | `hostdata/accesstime`, same symbol names |
| `hostmeta.CaptureAppSandbox` | `hostdata/sandbox.CaptureAppSandbox` |
| `hostmeta.PreserveXattrForIntent` and intent types/constants | `hostdata/xattrintent`, same symbol names |
| `hostmeta.Flags` | `hostdata/bsdflags.Flags` |
| `hostmeta.AvailableSpace` | `hostdata/diskspace.AvailableSpace` |

For example:

```go
import (
    "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
    "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/accesstime"
    "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// Complete operations retain descriptor ownership and partial-error contracts.
result, err := hostdata.CopyAppleDoublePath(ctx, source, destination, options)

// Individual operations use their owning package.
err = accesstime.CopyAccessTime(sourceFile, targetFile)
aclResult, err := acl.RestoreACL(update, backend)
```

The example shows independent calls; callers must handle each result/error before
performing their next operation. `acl.ACLMetadata.CloneForRestore` exposes the
existing owned-copy step to lifecycle callers. It requires validated non-nil
security and ACL records, as the original internal operation did.

## Dependency boundaries

The coordinating package depends on the focused packages; none imports it back.
The ACL package depends on `appledouble` for its wire and policy models. Native
platform files retain their build constraints and libSystem/Windows/Linux calls.
The common Windows FILETIME conversion and held timestamp setters are shared in
`internal/hosttime`, rather than duplicated between access-time and other setters.
Test-only held-file construction is shared in `internal/testutil/heldfixture`.

Linux and Windows retain the full captured metadata/lifecycle behavior and their
native filesystem adapters. A package move grants no Darwin permission semantics
to a foreign host. Unsupported *native* observations remain explicit, while
logical preservation continues through the image/carrier APIs.

## Refactor qualification

The refactor must retain all 23 portable evidence reports, their greater-than-95%
per-file gates, all 37 fuzz targets, native C/Clang/AST comparisons, real
authorization/sandbox tests, full 4 GiB + 17 byte transfers, independent macOS
readback of foreign images and all four vendor DMGs. Source inventories include
the new subdirectories and shared helpers. Split files keep every previously
selected coverage statement in the inventory; moving tests cannot remove them
from a runner or denominator.

Follow `CONTRIBUTING.md` and compare the merged-main and refactored CLI outputs
with SHA-256: APFS and HFS+ plain and case-sensitive volumes, APFS snapshots and
nested trees containing hard links, symlinks, xattrs, ACLs and a resource fork.
Both binaries receive the same fixed source-date epoch, UUID and volume name.
Any difference is a refactor failure requiring explanation and correction.

The refactor PR stays draft until the complete CI set passes. The maintainer
merges it and the subsequent release. Package PR72 adopts only that published
qualified version, including these import changes, before codesign work resumes.
