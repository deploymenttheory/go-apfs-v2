# Existing quarantine state during application

`QuarantineApplicationContext.ExistingXattr` supplies the exact prepared
`com.apple.quarantine` value to the pure-Go application planner. Use it when
restoring metadata onto an existing file or applying successive quarantine
records. It works identically on Linux, macOS and Windows; it does not read a
filesystem or load native libraries.

A valid serialized record does not imply that an existing destination attribute
is valid. Native application can replace malformed bytes, preserve them exactly,
or use their numeric header even when full `libquarantine` import rejects them.
Calling `ParseQuarantineXattr` first and treating an error as absence loses these
outcomes.

## Supplying destination state

```go
ctx := appledouble.QuarantineApplicationContext{
    Profile: appledouble.QuarantineMacOS27,
    Process: &appledouble.QuarantineProcess{Flags: 0x202, Agent: "Browser"},
    ExistingXattr: []byte("ffff;0"),
    Timestamp: 1700000000,
}
source := &appledouble.Quarantine{Flags: 0x218, Identifier: "ID"}
plan, err := source.PlanApplication(ctx)
// plan.Value: 0086;6553f100;Browser;ID
```

`ExistingXattr == nil` with `Existing == nil` confirms absence. A non-nil empty
slice represents a present zero-byte attribute. Read failures are neither state:
resolve them in transport before calling the planner. Supply only one of
`ExistingXattr` and the existing `Existing` model; contradictory representations
return `ErrQuarantine`.

The planner does not retain or change the input bytes. A preservation decision
has `Write == false` and `Value == nil`; keep the original bytes, even if empty,
malformed, noncanonical or oversized for library import. Writes carry owned,
exact filesystem bytes. A later record must see the actual resulting state.

## Application rules

For qualified sandbox process contexts, native policy scans the existing
attribute's flags and timestamp with hexadecimal widths four and eight. It
requires both numeric assignments and the separator between them. It does not
require valid agent/identifier fields, the library flag mask or the library's
382-byte import limit. The scan stops at the first NUL. Zero existing flags
remain zero.

The kernel skips only space, tab and line feed before each number. The library
importer also skips carriage return, vertical tab and form feed. This distinction
matches Apple's [pinned XNU scanner](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libkern/stdio/scanf.c#L71)
and is measured with every possible byte in both header positions. The Go codec
and planner share the numeric scanner with explicit whitespace selection.

A usable header contributes existing bits `0x6`. An unusable header contributes
none, but does not automatically fail application: ordinary replacement and the
source-preserving fallback can still succeed. If subsequent process flag policy
requires preservation through the sandbox path, a malformed header returns
`ErrQuarantineExisting` (native code/errno 22). Confirmed absence instead returns
`ErrQuarantineMissing` (native code -1, errno 93). Neither error requests a write.
Other qualified process contexts do not need to interpret the existing value.
Source validation, process qualification and the source application size limit
retain their existing precedence.

## Native qualification

The `-existing` runtime matrix measures 6,672 cases per host profile, with
inherited and explicitly requested process contexts, files and directories,
absent/empty/malformed values, signs and numeric widths, embedded NULs,
non-UTF-8 bytes, field overflow, values through 4,096 stored bytes, long leading
whitespace and all 256 byte values in both numeric header positions.

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble-quarantine-runtime.go -existing
```

The native helper changes only its own short-lived process and disposable
files. It captures effective raw process state and exact prepared/applied xattrs.
A dedicated observer retains full-library import failures as code/errno evidence;
it never substitutes an empty model. Successful imports are independently
compared with Go serialization. Native application results and bytes are compared
with the planner, allowing only current timestamps bounded by each operation.
Clang ASTs for arm64/x86_64, SDK exports, helper hashes, inputs and outputs are
retained. All portable tests replay the committed native corpora without skips.

Destination kinds beyond regular files/directories, production capture, actual
write refusals, cleanup/callback integration and process contexts outside the
qualified range remain separate transport work. These observations do not
resolve the general large-value/allocation or APFS/HFS+ preservation gates.
