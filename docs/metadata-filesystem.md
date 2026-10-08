# Filesystem-selected metadata

The codesign consumer needs ordinary path operations to see the metadata that
macOS exposes, without asking users to supply AppleDouble flags or a sidecar map.
This behavior belongs in the shared filesystem layer. AppleDouble byte decoding,
copyfile pack/unpack semantics and filesystem-visible attributes are separate
contracts; success in one does not establish another.

## Native evidence and CI

`scripts/capture-metadata-filesystem.go` creates disposable APFS, HFS+, FAT32 and
exFAT volumes with Apple's tools. A Clang-built C oracle queries both held and
no-follow path attributes, records complete name lists, and performs native
attribute operations. Inputs include ordinary files and directories with absent,
valid, truncated, bad-magic, empty, directory-valued and readonly sidecars, plus
native-seeded and conflicting storage controls. Twelve actions cover reading,
plain/fork create/replace/set, empty assignment, removal and zero FinderInfo.
There are 960 required cases, with full input/output carrier bytes and native
results. Permission and link profiles beyond these cases remain outstanding.

The seed comes from native attribute installation and `copyfile` with
`COPYFILE_PACK | COPYFILE_ALL`; its three intended values are validated before
capture. Filesystem seeding itself can have different native outcomes (for
example fork installation on FAT/exFAT); command journals preserve those results,
and every case records the actual values visible before the requested action.
Fixture creation removes host-created provenance sidecars before preparing an
explicit absent or replacement-sidecar state. This does not normalize attributes
out of the operation's observations.

The existing Metadata transport workflow now captures macOS 15, 26 and 27
separately. Each producer must report the requested actual version; a moved runner
alias fails rather than silently substituting a different producer. All three
host operating systems validate every producer's complete corpus. Negative tests
reject missing/duplicate cases, malformed observations and damaged input seeds.
The shared CI reporter retains command boundaries, heartbeat/deadline information,
raw channels and failures. A failed capture saves an explicitly incomplete report.

Both Clang targets also compile four complete pinned XNU attribute dispatch
bodies. Kernel helpers are declaration-only shims; private constants and vnode
layout are symbolic. This is static source evidence, not kernel execution or a
claim that a published source revision matches the installed macOS binary.

**These jobs validate native research evidence, not completed Go filesystem
parity.** Production integration, behavioral replay against the eventual shared
metadata view, current-profile regression comparisons and foreign output native
readback remain required before closing the prerequisite. Native fixtures from
15/26 must be retained from their actual runner captures, never synthesized by
changing a version field in the local 27 capture.

## What the local capture establishes

On macOS 27.0.1 build 26A434, valid packed sidecar attributes are visible on FAT32
and exFAT while the same sidecars remain separate files on APFS and HFS+.
Reading an existing fork and setting a fork have different outcomes on the
AppleDouble-backed volumes. The implementation must use operation-specific
contracts; neither blindly scanning every `._` file nor applying the copyfile
logical-value rules globally is sufficient.

## Cleanup and CI refinement

The completion work includes an audit of native behavior, useful library/transport
contracts, fault injection, obsolete CLI scenarios and duplicate execution.
Codesign's invented AppleDouble routing flags are to be replaced by ordinary
command/filesystem cases. Record old case IDs, the reason for replacement and the
new native requirement/case IDs; do not retain obsolete product semantics merely
to preserve an old test count.

The APFS metadata carrier also serves real extraction/repacking consumers. Its
explicit API tests are valid library tests, not proof that a native codesign CLI
requires configuration. Keep necessary library and corruption/failure tests.

CI timing baseline at release commit f9b546a: the macOS and Windows core jobs
execute for approximately 37 minutes. Windows runs carrier qualification for
about six minutes and then the complete unit suite for about ten minutes;
separate carrier/owned-compression workflows also execute those packages.
Consolidation must retain unique cases and raw per-host coverage, including
stricter per-file gates, while removing duplicate execution. Distinct race modes,
macOS producers and foreign-image readbacks are not interchangeable. Separate
queue time from execution time when evaluating improvements.
