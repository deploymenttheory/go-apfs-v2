# Native AppleDouble attribute names

The decoder previously accepted names native macOS rejected, and interpreted
`a NUL z NUL` as a name containing an embedded NUL rather than native name `a`.
It now requires a declared name field of 2–128 bytes, terminal NUL, a nonempty
logical prefix and valid UTF-8 in that prefix. The encoder also rejects invalid
UTF-8. Limits count bytes, including the wire terminator, rather than characters.

The first NUL ends the logical name. Later bytes in the declared name field are
padding, even if nonzero or invalid UTF-8. Record advancement still uses the full
declared length. This preserves the existing padded-name safety regression and
matches native unpacking. Canonical re-encoding removes padding; this is semantic
equivalence, not a claim that malformed/padded wire bytes remain identical.

## Evidence and reproduction

`testdata/appledouble/native/names.json` contains fourteen raw synthetic sidecars
and **independent native** observations from macOS 27.0 (26A428), not expectations
derived from Go decoding. Names and values are byte arrays encoded as base64 so
JSON cannot replace invalid UTF-8. The fixture records the C helper hash, Apple
source revision and native diagnostics. Every accepted case was read back through
native getxattr, and every rejection was an unpack failure with EINVAL.

| Cases | Native outcome |
| --- | --- |
| ASCII, zero-padded, embedded NUL, invalid padding after NUL | Accept; use the prefix before the first NUL |
| 127-byte ASCII, 126-byte Unicode, 127-byte Unicode | Accept; exact name/value readback |
| Empty logical name, absent terminator, declared length 0 or 1 | Reject |
| 128-byte logical name, invalid UTF-8, truncated UTF-8 | Reject |

The codec unit suite replays all fourteen on Linux, macOS, Windows and Linux/386.
The native harness replays them against the current host; accepted cases are then
re-encoded by Go, unpacked natively into fresh files, and read back again. Rejected
cases require the expected error rather than counting a crash, setup error or
missing tool as a rejection. Reports distinguish expected failures explicitly.

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble.go
CGO_ENABLED=0 go run scripts/verify-appledouble-native.go # native oracle on macOS
```

The existing pinned copyfile source and Clang AST/layout derivation remain in the
native evidence artifact. The source's `copyfile_unpack` checks the declared name
length and terminal NUL; native filesystem application establishes UTF-8 behavior.
The AST scope remains complete wire structures and public helper calls, not every
private Apple implementation function. See [size research](appledouble-native-sizes.md)
for source revision, hashes and compiler provenance.

The decoder's candidate-header and attribute-record bounds now use subtraction
instead of potentially overflowing additions. Boundary tests exercise MaxInt
without allocating multi-gigabyte files. The alias-amplification fixture now uses
valid terminated names so it still reaches the allocation-budget check.

This increment does not settle duplicate records, overlapping regions, special
attribute normalization, oversized native packing policy or filesystem transport.
Package PR #72 remains draft and codesign remains paused until those phases are
complete, released and validated downstream.
