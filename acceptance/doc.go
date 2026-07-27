// Package acceptance holds the acceptance suite for this repository. It
// contains no production code. What distinguishes a test here from a unit test
// is that it judges the result against something outside the code under test:
// either the real apfs binary run as a subprocess, or a filesystem checker
// that ships with the platform. Tests that verify behaviour purely in memory
// stay in the package they exercise.
//
// # Tiers
//
// The suite has three tiers, all run by CI on Linux, macOS and Windows.
//
// The fixture tier needs nothing but the repository. It builds ./cmd/apfs and
// drives it as a subprocess against the images committed under testdata/cli
// (UDZO, UDBZ, ULFO and a gzipped raw GPT image, plus an HFS+ image), checking
// their contents against testdata/cli/manifest.json and asserting the
// exit-code contract in pkg/exitcode. Nothing in this tier imports
// internal/cli, so it exercises the tool exactly as a pipeline would. Run it
// with:
//
//	go test ./acceptance/
//
// The writer-oracle tier calls pkg/apfswrite, pkg/hfsplus and pkg/disk
// directly and hands the result to a platform checker: fsck_apfs, hdiutil and
// diskutil on macOS, apfsck on Linux. These are the tests that catch on-disk
// format errors a round-trip through our own reader would agree with and
// therefore miss. They skip when the tool is absent, so a green run on a
// machine without them proves less than a green run in CI.
//
// The vendor-image tier runs against a real application DMG and is skipped
// unless APFS_ACCEPTANCE_DMG is set. It extracts the whole volume, verifies
// every file against a checksum of the same file read through an hdiutil
// mount, and repacks the image to prove the raw filesystem round-trips
// bit-for-bit. CI runs it twice, against Firefox (HFS+) and Zed (APFS):
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
// The vendor-image tier reads these, defaulting to Firefox:
//
//	APFS_ACCEPTANCE_DMG        path to the image; unset skips the tier
//	APFS_ACCEPTANCE_VOLNAME    expected volume name
//	APFS_ACCEPTANCE_APP        expected .app bundle at the volume root
//	APFS_ACCEPTANCE_BUNDLE_ID  expected CFBundleIdentifier in its Info.plist
//	APFS_ACCEPTANCE_BINARY     expected CFBundleExecutable; empty derives it
//
// Some tests additionally require platform tools and skip without them:
// hdiutil, fsck_apfs, fsck_hfs and diskutil on macOS.
//
// # Attestations
//
// Tests in the vendor-image tier record what they observed — file counts,
// checksums, sizes — through attest, which writes to the test log and, in CI,
// to the GitHub Actions step summary. The point is that a green run states the
// values it saw rather than only that it passed.
package acceptance
