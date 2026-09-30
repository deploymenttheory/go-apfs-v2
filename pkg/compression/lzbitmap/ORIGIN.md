# Shared LZBITMAP codec

This package moves the existing pure-Go implementation from
`deploymenttheory/go-macos-pkg/pkg/lzbitmap` at commit
`a91762f6c9bfe36b18451e3dca92762f7a5fd59a` into shared filesystem compression
ownership. That implementation translates Ernesto A. Fernandez's MIT-licensed
[libzbitmap](https://github.com/eafer/libzbitmap), copyright 2022 Corellium LLC.
The complete upstream MIT notice is retained in LICENSE. Reference commit:
`574abeae25b25c3319b9b6a9225cc7464e08ae88`.

The original native `aa` compressed/plain fixture pair and encoder/decoder tests
travel with the code. Additional bounded decoding and malformed input tests
qualify its use for decmpfs chunks. Existing package consumers remain on their
released dependency until this APFS phase is qualified and released. Draft
macos-pkg PR72 must then replace its old package with thin compatibility wrappers
and move its pbzx imports here; there must not be two independent codec forks.

The history search uses Go's optimized `bytes.IndexByte` in place of the original
scalar first-byte scan. It visits the same candidates in the same order. Golden
encoder hashes captured before this change cover random and repeated data,
transitions between them, long history references and chunk tails. Native Apple
fixtures and decoder round trips remain independent format checks. This is a
production optimization on every platform; coverage builds retain the ordinary
20-second performance limit and the complete 8 MiB workload.
