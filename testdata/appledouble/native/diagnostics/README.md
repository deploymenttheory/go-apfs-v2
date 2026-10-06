# Native capture diagnostics

`compression-operation-macos15-read-open.json.gz` is the unchanged raw artifact
from PR #206, Actions run `37375989087`, macOS 15 job `111984810918`, at revision
`788875ee3e348e867c3eab9330c5ba012445e2d6`. It retains all 330 cases, both Clang
AST hashes and the original source provenance. It is historical diagnostic
evidence, not a current-source acceptance baseline.

Case 261 (`HFS+/multi-block/default/default/pread-short`) reports
`observer_open_access_changed: false`; the retained profile at that revision
reports `true`. The normalized compression trace, metadata restoration,
compressed bytes and logical readback agree. That boolean measured a new
read-only open after compression, which can invoke native validation and mutate
access time. It did not establish a deterministic compression contract.

Current capture profiles use a descriptor retained from fixture setup and
require an exact held/path metadata match before permissions are relaxed or
compressed data is opened for readback. See
[compression operation qualification](../../../../docs/compression-operation.md)
for the native source references and the complete assertions. The historical
artifact is intentionally preserved without changing its source hashes.
