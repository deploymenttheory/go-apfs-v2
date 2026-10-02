# Typed Darwin wrappers

`internal/darwinabi` supplies the macOS host operations that the pinned
`golang.org/x/sys/unix` v0.48.0 does not expose with the required signatures.
It replaced the `purego` dependency in v0.15.0 without removing host features.
The additional basic entry-type query requires its own passing qualification
and published release before downstream adoption.

The extension follows x/sys's fixed libSystem import and Go runtime call pattern.
There are 28 typed functions, generated for amd64 and arm64. There is no public
function-pointer dispatch, runtime symbol lookup, generic FFI, CGo production
code, helper process, or numbered Darwin syscall. The production code still
calls macOS libraries for macOS host observations, just as x/sys does. It is not
an implementation of the macOS kernel in Go.

| Boundary | Operations retained |
| --- | --- |
| libSystem | Basic entry-type queries, option-aware xattr reads/listing, filesec properties, held/path metadata, extended ACL writes, held creation time, flag compare-and-swap, protected open, quarantine MAC entry point, account/group/UUID lookup |
| libquarantine | Allocate/capture/free the process record used to independently confirm absent quarantine state |
| libxpc | Query the current process's App Sandbox state |

Policy, AppleDouble/resource-fork codecs, serialization, image operations,
transport, ordering, cancellation and cleanup remain Go implementations. Linux
and Windows keep their existing portable logical metadata and host adapters.
A foreign host cannot observe a live Darwin process; callers continue to use
captured context there. No new unsupported platform path is introduced.

## ABI and error handling

The Go runtime captures errno before returning to Go. There is no second call
that could read a different thread's errno after a scheduling event. Signed
32-bit status codes, full-width `ssize_t` results, pointer returns, direct POSIX
error codes and the one-byte C boolean are handled separately. Intel statx
imports retain the `$INODE64` suffix.

`Passwd` and `Group` match the measured SDK layouts. Clang checks 20 public
function signatures and the relevant layouts on both architectures. The private
interfaces continue to be qualified by the existing independent native C
observers, SDK/source research and signed process-context CI. Their signatures
are not represented as public SDK guarantees. A missing imported symbol is a
link/load failure, rather than a recoverable runtime lookup failure.

## Qualification

Run from the repository root:

```sh
go run scripts/generate-darwin-wrappers.go -check
go run scripts/audit-native-bindings.go -check
# macOS host required for live qualification:
go run scripts/verify-darwin-wrappers.go
go run scripts/verify-quarantine-capture-native.go
```

The dependency audit checks production graphs for all six Linux/Darwin/Windows
amd64/arm64 targets, tagged source imports and the module requirement. It rejects
CGo/purego imports and generic native dispatch in repository Go sources. Native
compiler directives are confined to the typed extension and the test-only
quarantine observer. Generated output must reproduce exactly.

The wrapper gate requires more than 95% statement coverage, at least 1,150
passing records and no skipped selected tests. It retains the coverage profile,
JSON test events, source hashes, SDK path and both Clang ASTs, and links both
Darwin architectures with CGo disabled. Existing held metadata, path lifecycle,
metadata transport, scheduling-stress, large-fork, authorization, signed sandbox,
foreign-image, commercial-DMG, fuzz and portable evidence gates remain required.
Direct invalid-descriptor tests cover held read/write errors independently of
filesystem state. Protected-open tests call the typed entry point even when the
higher-level API selects ordinary open; existing and missing paths must match
an independent C observer, with descriptor identity and payload checked on
success. The coverage artifact includes a per-function report to diagnose runner
differences without changing thresholds.

The wide native xattr result test writes the final byte and closes the resource
fork before querying its length, so the assertion does not depend on an
unmaterialized truncated fork.

The quarantine C observer still runs in the same process as Go with CGo disabled.
Its unchanged C source is compiled by the research driver; a retained Go overlay
provides its concrete dylib path to two fixed test-only imports. That library
and overlay are test artifacts, never production dependencies.

## Maintenance and provenance

Regenerate with `go run scripts/generate-darwin-wrappers.go`. Additions require
specific typed signatures, native evidence and the same coverage/CI gates.
Prefer an upstream x/sys wrapper when one becomes available.

The runtime call/import pattern is adapted from
[x/sys v0.48.0](https://github.com/golang/sys/tree/v0.48.0/unix), especially
`syscall_darwin_libSystem.go`, `zsyscall_darwin_arm64.go` and its assembly
trampolines. The Go Authors' BSD license is retained in
[`internal/darwinabi/LICENSE.go-authors`](../internal/darwinabi/LICENSE.go-authors).
Runtime entry points are declared in Go's
[`runtime/sys_darwin.go`](https://go.dev/src/runtime/sys_darwin.go).
These internal entry points require requalification when changing Go versions.

After maintainer merge and publication, downstream projects must pin the released
module and rerun their full checks. Local replacement testing proves a candidate,
not a published dependency. Codesign currently uses v0.16.0; the new
[rooted entry-type query](rooted-entry-type.md) must be released before adoption.
