#!/bin/bash
# Derives pkg/hfsplus/casefold_table.go by observing macOS, rather than
# transcribing Apple's table. Requires macOS. Run from the repository root:
#
#   ./scripts/derive-casefold.sh
#
# Why observe rather than transcribe:
#
# A case-insensitive HFS+ volume orders catalog keys by a fold that Apple froze
# around Unicode 3.2. Building the table from current Unicode data gets it
# wrong -- most visibly across the Georgian block, where modern data maps
# U+10A0..U+10C5 to Nuskhuri at U+2D00+ while HFS+ maps them to Mkhedruli at
# U+10D0+, so every Georgian name would sort and resolve incorrectly. U+1E9E
# (added in Unicode 5.1) is a second: modern data folds it to U+00DF, HFS+
# folds it to itself.
#
# How it works:
#
#   1. Create a case-insensitive HFS+ volume with hdiutil.
#   2. Create one file per BMP code point that survives NFD unchanged. Code
#      points that fold alike collide, so only one of each pair is created.
#   3. Detach, then read the catalog B-tree directly. Leaf order is key order,
#      and key order on a case-insensitive volume is fold order.
#   4. Derive a fold value per code unit: characters in ascending runs fold to
#      themselves and anchor the scale; the rest are pinned to the window their
#      position allows, taking Unicode's lowercase when it falls inside it.
#   5. Assert the derived table reproduces the observed order exactly, then
#      emit it.
#
# Step 5 is the acceptance test: a table that cannot reproduce what macOS did
# is rejected rather than written out.
set -euo pipefail

if [[ "$(uname)" != "Darwin" ]]; then
  echo "error: deriving the fold table requires macOS" >&2
  exit 1
fi

WORK="$(mktemp -d)"
MOUNT="$WORK/mnt"
trap 'hdiutil detach "$MOUNT" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
mkdir -p "$MOUNT"

echo "==> Creating a case-insensitive HFS+ volume"
hdiutil create -size 200m -fs HFS+ -volname FOLD -type UDIF \
  -layout GPTSPUD "$WORK/fold.dmg" >/dev/null
hdiutil attach -mountpoint "$MOUNT" -nobrowse "$WORK/fold.dmg" >/dev/null

echo "==> Probing every BMP code point"
go run ./scripts/casefold probe "$MOUNT/probe"

sync
hdiutil detach "$MOUNT" >/dev/null

echo "==> Reading the catalog order and deriving the table"
# Written via a temporary file so a failed derivation cannot leave the
# committed table truncated.
go run ./scripts/casefold derive "$WORK/fold.dmg" > "$WORK/casefold_table.go"
gofmt "$WORK/casefold_table.go" > pkg/hfsplus/casefold_table.go

echo "==> Verifying"
go test ./pkg/hfsplus/ -run TestCaseFold

echo "==> Done: pkg/hfsplus/casefold_table.go"
