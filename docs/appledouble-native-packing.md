# Explicit native AppleDouble packing

`hostdata.PackAppleDouble` provides native-compatible packing through held source
and destination providers. Use it when copyfile's callback sequence, size policy
and partial output effects matter. `appledouble.StreamFile.EncodeTo` remains the
lossless canonical encoding operation; its behavior is unchanged.

`PackBackend` supplies captured ACL presence, native names, target intent policy,
separate size/read operations, serialized ACL/quarantine, positioned writes and
the final stat operation. The provider owns stable endpoint identity, actual
permission checks and process capture. These source/provider effects are not
replaced by a call to native `copyfile` in production.

`PackOptions` makes the choice explicit, including captured quarantine/ACL state,
callback, intent, initial progress, workload/output budgets and active allocation
budget. All three operating systems execute the same policy. No global mode or
host-OS inference selects loss behavior.

## Behavior callers must handle

- Ordinary Start callbacks occur while building the complete name table, before
  value reads. Progress Skip cannot remove a record already laid out. The native
  FinderInfo Progress callback and resource-fork Finish callback expose an empty
  current name; the Go notice retains that detail.
- Attribute data and the resource fork are written before the header. Errors can
  leave partial positioned output; this operation neither truncates an existing
  suffix nor removes the destination.
- An ordinary value above 16 MiB leaves a present empty record under the native
  packing policy. Resource-fork packing has a separate `INT_MAX` limit. These are
  packing policies, not codec storage limits.
- Native fork output failure can be ignored. A later successful fork can replace
  an earlier ordinary write/allocation error code. The fork Error callback can
  suppress some failures, including a size refusal. Final stat runs only after
  a zero packing code.
- The pinned source's captured-but-unlisted quarantine path overwrites the saved
  name-buffer position without adding a header record. The explicit compatibility
  operation preserves that measured behavior and reports the missing record.
  Lossless transport should carry the captured quarantine independently.

Inspect `PackResult.Failures` and `PackResult.Losses`, not just `Code` or
`HeaderWritten`. Failures retain actual operation diagnostics; losses identify
known value-loss behavior even when native returns success. Limits distinguish
caller allocation/output refusal from native size policy. `ErrPackAllocation`
joins `appledouble.ErrStreamBudget` for explicit allocation limits.

Some C failure paths use unspecified lengths or would pass a negative read length
through unsigned allocation/write arguments. The Go operation returns
`ErrPackUnsafe` with the underlying error rather than reproducing undefined memory
access. The compatibility contract covers defined measured outcomes, not native
memory corruption or process crashes.

## Evidence and testing

The native script extracts complete unchanged `copyfile_pack`,
`copyfile_pack_rsrcfork` and `sort_xattrname_list` from
[pinned Apple copyfile source](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c).
Its SHA-256 is
`19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`.
Generated source retains Apple's license. Controlled metadata providers isolate
packing order and callback/error effects; they are explicitly not a claim that
every source acquisition or authorization path has been bound.

The 417 native cases compare every event, return code, progress value and complete
output SHA-256. They cover callback combinations, empty and 16 MiB boundaries,
fork size refusal, ACL/quarantine source selection, intent filtering, read shrinkage,
list/query failures, short/error writes and final stat outcomes. Portable tests
replay these observations on Linux, macOS and Windows, alongside allocation,
overflow, malformed-provider and cancellation tests.

Three additional public libSystem tests seed and independently read back native
attributes, then call the actual host `copyfile`: 16 MiB ordinary values are
preserved, 16 MiB + 1 ordinary values become present empty records, and a
16 MiB + 1 resource fork is preserved. Full source/readback/packed bytes and hashes
remain in the artifact. These measure the host's actual filesystem and library;
the controlled extraction and live calls remain separate evidence classes.

Run `go run scripts/verify-appledouble-pack-coverage.go` on every supported OS.
It rejects skipped tests and requires above 95% coverage in each production file.
Run `go run scripts/verify-appledouble-pack.go` on an ordinary macOS account to
qualify native behavior. The script retains source, generated headers, both Mac
architecture ASTs, compiler/SDK/host identity, all commands, complete outputs and
reports. `-capture` records unapproved evidence and never reports qualification.
