# CI command reporting

CI uses a shared Go runner for repository test, verification, capture and build
commands. Its purpose is to show which operation is running, whether tests are
advancing, and where execution stopped, while retaining the original evidence.
The same reporting contract applies to filename comparison, lookup, carrier
recompression, metadata transport, package tests and native acceptance.

## Reading a run

Each workflow workload starts with `CI PREPARE` and has a suite identity,
explicit deadline, raw stdout/stderr files and a start manifest. Each subprocess
reports `START`, `LAUNCHED`, periodic `ACTIVITY`, cancellation and `FINISH`.
Monitoring begins before process startup so a slow launch is visible too.

`ACTIVITY` means the monitor is alive. It does **not** claim the child made
progress. Go test JSON supplies observed test/package progress, failures, skips
and summaries separately. Native probes with per-operation records retain those
records. A command without operation-level output can only report its elapsed
activity and final result; the runner does not invent percentages or completed
cases.

The console is a diagnostic view. Existing JSONL, native JSON, binary payloads,
Clang ASTs, SDK headers and source maps remain the qualification evidence. The
runner does not insert reporting text into a child's machine-readable stdout or
combined-output result. Routine test events may be coalesced in the diagnostic
view; original streams remain complete in the artifacts.

## Components

- `internal/testutil/cirunner` owns subprocess lifecycle reporting, bounded
  asynchronous console/journal delivery, Go JSON progress and file forwarding.
- `scripts/ci-run.go` is the workflow entry point. It owns raw stream files,
  workload deadlines and start/finish manifests.
- `.github/actions/setup-ci-runner` builds that entry point for the actual host,
  including when a job supplies another `GOOS`/`GOARCH` for cross compilation.
- `scripts/audit-ci-reporting.go` checks repository test/harness source and
  workflow commands for reporting bypasses. Its report inventories external
  actions separately; their own processes remain managed by those actions.
- `scripts/verify-ci-reporting.go` qualifies the shared runner and provenance
  helpers with statement coverage above 95% per production file and package.

The CI runner is internal test infrastructure, not a production dependency.
Existing test inventories, assertions, expected error codes, source validation,
platform matrices and coverage requirements remain in force.

## Adding a command

After checkout and `actions/setup-go`, use the local setup action, then:

```yaml
- uses: ./.github/actions/setup-ci-runner
- run: apfs-ci-runner --suite example/verify --timeout 10m -- go test -json ./pkg/example
```

Upload `artifacts/ci-observability/` with `if: always()` and
`if-no-files-found: error`, with a unique artifact name for each matrix cell.
Also retain the suite's existing evidence directories. Set a job/step deadline
that leaves time for command cancellation, cleanup and artifact upload.

Inside Go tests and scripts, use `cirunner.CommandContext` with the operation's
context. Preserve existing independent, bounded cleanup contexts when the
operation may already be cancelled. `Command` retains background-context
semantics for existing call sites; a workflow deadline still bounds the parent
workload. Do not pass a nil context. Keep test-specific mount ownership,
case validation and domain evidence in the suite that understands them.

## Failure and cleanup

Console delivery is independent of raw-file writes. A blocked or broken console
must not prevent the child from recording evidence. Queue overflow, journal
errors and incomplete final drainage are reporting failures in CI:
`APFS_CI_STRICT_REPORTING=1`. They do not replace the original subprocess error.
Partial raw output and start manifests remain available after failures. A
successful qualification requires successful existing assertions as well as
complete reporting; a heartbeat, upload or zero exit from a producer alone is
not acceptance.

Cancellation is logged independently of waiting for process exit. A kernel
operation can delay termination even after a deadline; the outer CI timeout
remains the final boundary. No in-process runner can guarantee a final manifest
or artifact upload after its host is killed or becomes unresponsive. Absence of
that evidence is incomplete execution, never a pass. Image probes keep live
mounts outside uploaded directories so artifact collection does not traverse a
stalled mounted filesystem.

## Native provenance

Native captures bind the shared runner, workflow entry point, setup action and
capture-provenance implementation, including platform-specific source files.
Changing these inputs invalidates current-source fixture qualification just as
changing a capture script does. Regenerate on the real required macOS version,
retain complete C/Clang/SDK evidence, review native outcomes and then promote
the genuine archive bytes. Never update hashes inside old observations.

Dependent captures must consume the reviewed new prerequisite archives: for
example, recompression access binds the macOS 27 LZ4 capture. Historical
experimental records retain their original sources and observations; they are
not relabelled as current qualification.

## Verification scope

The reporting matrix runs on Linux, Windows 2022/2025 and macOS 15/26/27. It
checks byte preservation, nonzero exits, failed launches, cancellation,
blocked/failed writers, inherited descriptors, JSON progress, concurrent
reporting, source inventories and audit rejection paths. Linux also runs the
race detector. Existing native and portable acceptance matrices remain
separate mandatory gates.

The audit is a static guard, not a proof of arbitrary generated shell or Go
programs. New launch mechanisms or external actions require review. Shell
housekeeping, setup and external actions retain their own Actions logs; they
are not falsely counted as instrumented subprocesses.

For a harness-wide source change, the capture-only workflow collects each
current-source fixture on its required macOS profile. Dispatch
`compression-native.yml` with `capture_phase=base` on the working branch, review
and promote the genuine prerequisite outputs, then dispatch with
`capture_phase=dependent`. The normal `full` selection and all pull-request runs
keep the existing qualification jobs. Capture jobs assert the actual host
version and unchanged tracked files before and after execution. These jobs
write artifact destinations only; they neither rewrite retained baselines nor
satisfy the normal acceptance gates.

Promote a capture as a complete fixture set. Compression-state observations bind
both `compression-state-APFS.dmg` and `compression-state-HFS+.dmg`; large-compression
observations bind all 42 retained resource-fork sidecars. Verify the recorded
hashes against the freshly produced bytes, then replay the existing consuming
acceptance gate in an isolated checkout before promotion. A codec-only replay
does not qualify image consumers. For compression state, run
`go run scripts/verify-compression-state.go`, which requires all 480 image/carrier
cases and the existing per-file coverage threshold. Commit matching observations
and required sidecars together; never repair a mismatch by changing recorded
hashes or reducing the inventory.

Evidence uploads explicitly include hidden files: the bound setup action lives
under `.github`, and omitting it would leave an incomplete source archive. The
workflow audit rejects owned evidence uploads without this setting. For a
focused regeneration, `capture_recipe` accepts an exact recipe from the chosen
capture phase. Invalid recipe/phase combinations fail; this optional selection
only affects supplemental capture jobs, never the normal qualification matrix.

## Native filename receiver references

The native filename matrix separates image production from receiving-kernel
lookup. Each cell first retains a source-bound preparation checkpoint without
mounting the image. A separate C reference probe (`name-receiver.c`) then captures
both spelling results for every case. Its TSV completion record is emitted only
after closing the file and directory descriptors. A fresh `name-readback.c`
process remounts the same immutable image and independently replays all cases.

The reference includes actual receiver build, producer/image/manifest identity,
current source hashes, SDK headers, both Clang ASTs, compiled probe identity,
raw results and attach/detach evidence. Successful lookups must match the exact
stored inode and empty-file content. Failed lookups must have no inode/content
and an unperformed read. Neither creation admission nor the producer's lookup
errno supplies receiver expectations. Preparation, capture and replay are
separate stages; the aggregate requires successful capture and replay transcripts
and verifies the nested reference evidence again. Missing or partial references
fail instead of falling back to producer results.

A receiver whose APFS line is below 2600 (macOS 15) does not mount an APFS image
formatted by line 2600 or newer (macOS 26 and later): that mount deadlocks the
receiving kernel. The reference stage reads both lines with the portable reader,
from the producer image and from the same-filesystem image the receiver's own
kernel wrote in this run, and writes `<producer>-<filesystem>-forward-incompatible.json`
instead of mounting. The replay stage and the aggregate matrix re-derive the
record from the same images and reject a cell that carries both the record and
mount evidence, or claims observations for a volume it did not mount.

`APFS_NAME_OUTPUT_ROOT` selects a fresh artifact parent for local investigation;
the default remains `artifacts`. Existing output directories are rejected. Run
`TestCaptureNativeNameReceiver` before `TestNativeCrossVersionNameImages` with
the same explicit producer/receiver/filesystem selection and producer inputs.

The aggregate job initializes reporting before testing upstream job results, so
a cancelled dependency produces a retained command failure instead of preventing
the diagnostics directory from being created. This does not convert cancellation
into success. Native kernel or runner nontermination can still prevent later
uploads; the preparation checkpoint survives independently of those later steps.
