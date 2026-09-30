# Inner copy routing and stage order

`hostdata.RunCopyPipeline` coordinates operations on an already held source and
destination. Use it to compose metadata/data providers without duplicating
Apple's route selection, failure exits and cleanup policy. It is pure Go and
runs the same implementation on Linux, macOS and Windows.

This is the inner `copyfile_internal` coordinator. Providers still implement the
selected operations. It does not open paths, create destinations, authorize
writes, acquire source/quarantine state or close handles.

## Routes

Both endpoints must be ready before any operation, even with no flags selected.
The backend must be non-nil. Route precedence and ordering are:

| Selection | Operations |
| --- | --- |
| Pack | Pack only; takes precedence over every other selection |
| Unpack without Pack | Unpack only; the provider owns the entire unpack route |
| Ordinary copy | Captured quarantine, xattrs, data, security, stat, in that order |

Ordinary stages run only when selected, except captured quarantine: it is applied
even when no ordinary stage flags are set. Run-in-place prepares quarantine first,
only when captured quarantine exists. Either `Data` or `SparseData` selects one
data call; the provider implements sparse policy. Either `ACL` or `Stat` selects
security. Thus a stat-only request still runs **security then stat**.

AppleDouble unpack has its own internal order. After its attributes, quarantine,
FinderInfo and resource-fork handling, it applies the **deferred ACL before the
final stat stage**. The coordinator delegates that whole route; it does not add
ordinary security/stat calls after unpack. This corrects the earlier image-stat
documentation's suggestion that deferred ACL replacement should follow stat.

## Provider contract

```go
result, err := hostdata.RunCopyPipeline(hostdata.CopyPipelineOptions{
    SourceReady: true,      // Set only after successful source acquisition.
    DestinationReady: true, // A held destination, not merely an existing path.
    Xattrs: true,
    Data: true,
    ACL: true,
    Stat: true,
}, boundBackend)
if err != nil {
    return err // Partial effects may already exist; inspect result.Steps too.
}
// Completed describes control flow. Inspect all stage/provider diagnostics
// before reporting successful metadata preservation.
```

Bind the same selection options into the backend: `Run(stage)` receives the stage
identity, not a second copy of the options. Existing image `CopySecurity` and
`CopyStat` APIs can supply those stages. Their detailed results still matter:
`CopyStat.Applied`, for example, must be checked before a provider reports that
image metadata was published. The composition test exercises both real writer
APIs; it is not a complete production image/host transport adapter.

A stage result keeps `Code` separate from `Err`. Negative ordinary codes stop the
sequence; zero and positive codes continue. Each later selected stage replaces
the prior return code. A negative unpack result becomes `-1`; other stage codes
are retained. A negative code without an error receives a descriptive Go error.
Providers must return a negative code for a fatal ordinary-stage error. Internal
failures deliberately ignored by a stage may accompany a nonnegative code and
remain visible in `Steps`.

Only a failed **pack or data** stage requests destination removal, and only when
`HasDestinationPath` is true. Descriptor-only callers leave it false. The backend
owns safe removal of the bound pathname and must prevent path replacement/link
races. Removal failure is retained without replacing the primary stage error.
There is no removal for failed unpack, xattrs, security, stat or quarantine, and
there is no rollback of preceding stages.

`CopyPipelineQuarantine` owns captured state and profile conversion. Its
`AllowRunInPlace` operation preserves existing flags while adding the provider's
`QTN_FLAG_DO_NOT_TRANSLOCATE`; `Apply` uses the held destination. A nonzero
preparation code terminates with `os.ErrInvalid`. A nonzero application code is
retained but ignored unless `OnQuarantineError` returns `CopyPipelineQuit`.
Continue, Skip and unknown callback values all continue, matching the native
coordinator. The callback receives `com.apple.quarantine` and the operation's
result, with no shared mutable xattr-name state left behind.

On callback quit, a negative quarantine code maps to `errors.ErrUnsupported` and
a positive code to `CopyQuarantineError`. The original provider error is also
retained. Positive codes are not converted through the running OS's errno table.
Ambient errno and the outer copyfile state error cache are outside this API.
Callers must exclude concurrent mutation; callback panics are not recovered.

## Qualification

`go run scripts/verify-copy-pipeline.go` downloads and verifies pinned
[Apple copyfile source](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c),
extracts the **complete unchanged `copyfile_internal` function**, retains its
license, compiles it with Clang and records arm64/x86_64 ASTs. The source SHA256 is
`19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c`.

The native helper supplies controlled stage responses and compares **2,316
observations** with Go: every flag combination, missing endpoints, route
precedence, independent negative/positive stage returns, cleanup eligibility and
failure, quarantine preparation/application failures and callback decisions.
The helper checks callback arguments and cleared state, plus run-in-place
get/OR/set ordering. Its quarantine flag is a **symbolic test constant**, not a
claim about libquarantine's private ABI. Provider flag conversion and live
quarantine authorization remain separate qualification.

This oracle establishes the coordinator's control flow. It does not claim that
mocked stage responses are live filesystem effects. Existing security/stat and
mounted-image qualification continues to cover the constituent implementations.
A separate composition test executes the real image writer APIs through both
explicit ordering and the coordinator. APFS, case-sensitive APFS, HFSX and HFS+
produce identical image hashes between those routes; both APFS cases include a
snapshot. Different security/stat modes detect reversed ordering.

`go run scripts/verify-copy-pipeline-coverage.go` runs the corpus and composition
tests on all three OSes with CGO disabled, rejects skipped focused tests and
requires **above 95% coverage in the production file**. Current coverage is
**48/48 statements (100%)**, with **2,326 passing test records**. CI retains the
coverage profile, test log, revision and source hashes. Native CI separately
recaptures the oracle and compares it with the reviewed corpus.

## Remaining integration

Held native/foreign providers, unpack internals, creation inheritance and the
outer temporary-permission/restoration/close lifecycle remain outstanding.
Quarantine contexts, large values/allocation and shared filesystem transport
also remain open. These are the same five completion gates in the
[AppleDouble roadmap](../pkg/appledouble/README.md#roadmap).

Package PR72 remains draft on APFS v0.13.0. The qualified APFS release and its
downstream adoption must complete before codesign resumes.
