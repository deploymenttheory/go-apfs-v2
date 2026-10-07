# Historical receiver lookup regression

These files are unchanged excerpts from the `mini-outcome-ascii-a7ce-APFS`
artifact in [native diagnostic run 37456664601](https://github.com/deploymenttheory/go-apfs-v2/actions/runs/37456664601).
The capture source revision is `7e6554ac8f41a62af1f8cffe6950aa06c400e86f`.

The macOS 15.7.9 receiver read a two-case APFS image produced on macOS 26.
ASCII resolved successfully. For `fold-A7CE`, the original spelling returned
`EINVAL` (22), and the alternate spelling returned `ENOENT` (2). The native
process completed both cases, reported successful descriptor cleanup, exited
zero and detached the image. The subsequent assertion against the producer's
successful lookups failed.

This evidence protects the distinction between creation on the producer and
lookup on the receiver. It establishes no general error rule for Unicode 17,
other images, case-sensitive APFS, writable opens or different OS builds.
It remains diagnostic evidence from its original revision: it does not satisfy
any current full-matrix or source-provenance gate. Unit tests retain the original
host and completion identity; current acceptance captures all 3,753 cases afresh.
