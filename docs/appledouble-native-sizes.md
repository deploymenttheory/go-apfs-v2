# Native AppleDouble sizes and empty values

This increment fixes two measured encoder differences. A single 300 KiB ordinary
attribute could be packed by macOS and decoded by Go, but Go could not re-encode
it because values incorrectly counted against the entry-table limit. Empty
attributes were preserved semantically but used a different wire offset.

The encoder now bounds the header/table independently of values, uses the native
65,554-byte table buffer limit (largest aligned table: 65,552), and encodes empty
attribute offsets as zero. `MaxHeader` increases from 65,536 to 65,554 and its
documentation now states exactly what it bounds. `ErrTooLarge` keeps its sentinel
identity; its message describes header, wire and address-space bounds. Ordinary
values and forks remain subject to uint32 wire fields and the host's address
space. Allocation cannot wrap; memory availability can still limit very large
valid encodings. This is an in-memory codec, not a streaming API.

## Independent evidence

Pinned Apple source:
[`copyfile.c` at 9f91eb6ced021952278816cdc76ad68da8631ccb](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c).
SHA-256: `19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`.
The full pack/unpack functions are retained in the downloaded research artifact.
Clang AST and record-layout extraction covers the complete wire structures and
the native helper for arm64 and x86_64; it does **not** claim to compile or analyze
every implementation function in Apple's private build environment. Static
assertions verify header size, data-start/name field offsets and the table limit.

Run from the repository root on macOS:

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble-native.go
```

The Go harness builds a small C oracle against the host's public libSystem
`copyfile`, `setxattr` and `getxattr` APIs. It verifies setup by reading values back,
packs natively, decodes and re-encodes in Go, requires byte equality, unpacks the
Go output natively, and compares the restored bytes. Any setup or comparison
failure fails the run. There are no skipped cases. Production has no CGo/native
process dependency.

Observed locally on macOS 27.0 (26A428), arm64, SDK 27.0, Apple Clang 21.0.0:

| Case | Native pack → Go exact bytes → native unpack |
| --- | --- |
| 0, 1, 65,535, 65,536, 65,537 bytes | Passed; empty remains present |
| 300 KiB, 1 MiB, 16 MiB | Passed |
| 65,552-byte table, 468 unique empty attributes | Go → native unpack; every attribute read back |

Raw native/Go sidecars, expected/restored values, commands, failures, compiler/host
identity, ASTs and hashes remain in `artifacts/appledouble-native/` and the CI
artifact. The final table case is a native consumer test, not a native producer
byte-equality claim. Native execution is on the host architecture; the other
architecture receives compile/AST validation only.

`testdata/appledouble/native/large.ad.gz` retains the complete native 300 KiB
observation, including host provenance. Uncompressed length: 307,395 bytes;
SHA-256: `cf9147dc250d8f01a14faf0bd40c5b2f4b09b2cf168d0ffcc265fc05399cd204`.
Every OS must decode it, verify its value and reproduce its exact bytes. Coverage
is measured from portable unit tests only, independently of the Mac harness.
Linux also runs the codec on 386 to exercise address-space rejection.
That check exposed an existing decoder bug: a declared section size of
`0xffffffff` became a negative `int` on 386 and bypassed an upper-bound-only
check. The initial correction rejected negative converted sizes. Subsequent
[native record research](appledouble-native-records.md) established that copyfile
ignores this summary field entirely. The decoder now does the same without an int
conversion, while retaining overflow-safe bounds on every actual read.

## Remaining work

An exploratory native probe accepted a 16 MiB + 1 value on the source filesystem
but packed it as a present attribute with an empty value. That is an observed native packing-policy limitation,
not a successful preservation comparison and not behavior this byte codec silently
emulates. Oversized-value policy, aggregates near wire limits and very large forks
need further native investigation. The portable unit suite already checks multiple
16 MiB values plus a fork; that is not a native aggregate-parity claim.

Name validation and malformed/overlapping record increments are documented
separately. Special attribute normalization, remaining size policy and shared
host transport remain on the migration plan. These increments do not authorize
resuming codesign.
