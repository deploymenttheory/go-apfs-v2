// Package acceptance holds the acceptance tests for this repository. It has no
// production code in it — only tests.
//
// A test belongs here if something outside our own code decides whether it
// passed: either the real apfs command, run as a subprocess, or a tool that
// ships with the operating system. A test that only checks our code against
// itself is a unit test and stays in the package it tests.
//
// That distinction matters most for the disk images we write. If we write an
// image and then read it back with our own reader, both halves can share the
// same misunderstanding of the format and the test still passes. Handing the
// image to Apple's fsck_apfs, or to apfsck on Linux, removes that blind spot.
//
// # The three kinds of test here
//
// Command tests build ./cmd/apfs and run it against the small disk images
// committed in testdata/cli, checking what it prints, what it extracts and
// what exit code it returns. They compare file contents against the checksums
// in testdata/cli/manifest.json. Nothing in these tests imports internal/cli,
// so they exercise the command the way a shell script would. They need nothing
// installed:
//
//	go test ./acceptance/
//
// Checker tests write an image with pkg/apfswrite, pkg/hfsplus or pkg/disk and
// then check it with the tools that come with the platform: fsck_apfs,
// hdiutil and diskutil on macOS, apfsck on Linux. Each one skips if its tool
// is missing, so passing these on a machine without them proves nothing — CI
// installs apfsck from source for this reason.
//
// Real-image tests run against a published application DMG rather than a
// fixture. They extract the whole volume, compare every file against the same
// file read through an hdiutil mount, and repack the image to confirm the raw
// filesystem comes back byte for byte. They are skipped unless
// APFS_ACCEPTANCE_DMG points at an image. CI runs them twice, against Firefox
// (HFS+) and Zed (APFS):
//
//	APFS_ACCEPTANCE_DMG=/path/to/Zed.dmg \
//	APFS_ACCEPTANCE_VOLNAME=Zed \
//	APFS_ACCEPTANCE_APP=Zed.app \
//	APFS_ACCEPTANCE_BUNDLE_ID=dev.zed.Zed \
//	APFS_ACCEPTANCE_BINARY=zed \
//	go test -v -run TestAcceptance ./acceptance/
//
// # Environment
//
// The real-image tests read these, defaulting to Firefox:
//
//	APFS_ACCEPTANCE_DMG        path to the image; unset skips these tests
//	APFS_ACCEPTANCE_VOLNAME    expected volume name
//	APFS_ACCEPTANCE_APP        expected .app bundle at the volume root
//	APFS_ACCEPTANCE_BUNDLE_ID  expected CFBundleIdentifier in its Info.plist
//	APFS_ACCEPTANCE_BINARY     expected CFBundleExecutable; empty derives it
//
// # Recorded results
//
// The real-image tests log what they actually saw — file counts, checksums,
// sizes — through attest, which writes to the test output and, in CI, to the
// GitHub Actions step summary. A passing run therefore states the numbers it
// observed rather than only that it passed.
package acceptance
