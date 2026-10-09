# Unresolved native allocation observations

These are two complete, unedited macOS 27.0.1 (26A434) compression captures from
this branch's native oracle. They retain diagnostic evidence and the content-protected host context that is
absent from the hosted runner. Both were produced with `capture-compression-operation.go
-check`; the strict checker rejected their physical allocation counts.

For `host/multi-block/9/default`, the observations report 368 and 264 allocated
512-byte blocks. For `host/multi-block/9/no`, they report 352 and 384. The complete
data, compression attribute and resource-fork bytes are identical in each pair.
`TestCompressionAllocationObservations` preserves those facts and source hashes in
all-host CI. Portable storage replay additionally checks both captures. Native
held-file recompression uses the matching content-protection context for its
existing byte/metadata assertions; its 22-case requirement remains unchanged.
These checks do not qualify physical allocation equivalence.

Apple documents `st_blocks` as filesystem-dependent physical allocation:
[blocksAllocated](https://developer.apple.com/documentation/system/stat/blocksallocated).
That definition and these captures do not yet explain the timing or allocation
cause. Isolated six-case runs, with and without the native interposer and in both
temporary-directory locations, reported 264 blocks before and after inspection.
The complete native operation comparison still requires exact allocation counts;
no normalization or retry-to-pass policy has been added for this discrepancy.

Before closing the native lifecycle qualification, determine whether allocation
changes during inspection, deferred filesystem work or another captured context,
and implement a native-observed measurement/acceptance contract. Keep failure
states, stored bytes, logical readback and metadata comparisons strict.

## Original module inputs

`capture-go.mod.txt` and `capture-go.sum.txt` contain the exact original module
inputs, verified against the hashes recorded in both unchanged captures. These
allocation counterexamples are immutable historical observations, not the current
operation baseline. Their recorded counts, stored bytes, logical data and oracle
source checks remain required. The active macOS 15/26/27 operation profiles are
recaptured with the current `go.mod` and retain their strict current-source checks.
A Go upgrade must not relabel these earlier physical-allocation observations as a
new capture or discard the counterexample.
