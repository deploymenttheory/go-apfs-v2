#!/bin/bash
# Derives pkg/hfsplus/normalize_table.go by observing macOS, rather than
# transcribing Apple's exclusion list. Requires macOS. Run from the repository
# root:
#
#   ./scripts/derive-normalization.sh
#
# HFS+ stores names decomposed, but not with plain NFD: some code points are
# deliberately left alone -- the CJK compatibility ideographs at U+F900+ and
# part of U+2000..U+2FFF -- so that a round trip cannot lose them. Others are
# left alone only because their decompositions were added to Unicode after
# Apple froze this behaviour, which no published list would tell you.
#
# The derivation writes one file per decomposing code point, reads the stored
# names back out of the catalog, and asserts that every one is either untouched
# or exactly NFD. Anything else would mean the rule is not "NFD with
# exclusions" and the generated table could not express it, so the script fails
# rather than emitting something that quietly loses those cases.
set -euo pipefail

if [[ "$(uname)" != "Darwin" ]]; then
  echo "error: deriving the normalization table requires macOS" >&2
  exit 1
fi

WORK="$(mktemp -d)"
MOUNT="$WORK/mnt"
trap 'hdiutil detach "$MOUNT" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
mkdir -p "$MOUNT"

echo "==> Creating an HFS+ volume"
hdiutil create -size 200m -fs HFS+ -volname NORM -type UDIF \
  -layout GPTSPUD "$WORK/norm.dmg" >/dev/null
hdiutil attach -mountpoint "$MOUNT" -nobrowse "$WORK/norm.dmg" >/dev/null

echo "==> Probing every decomposing BMP code point"
go run ./scripts/normalize probe "$MOUNT/probe"

sync
hdiutil detach "$MOUNT" >/dev/null

echo "==> Reading the stored names back and deriving the table"
# Written via a temporary file so a failed derivation cannot leave the
# committed table truncated.
go run ./scripts/normalize derive "$WORK/norm.dmg" > "$WORK/normalize_table.go"
gofmt "$WORK/normalize_table.go" > pkg/hfsplus/normalize_table.go

echo "==> Verifying"
go test ./pkg/hfsplus/ -run TestNormalize

echo "==> Done: pkg/hfsplus/normalize_table.go"
