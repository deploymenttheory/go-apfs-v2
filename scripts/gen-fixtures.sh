#!/bin/bash
# Generates the committed CLI acceptance-test fixtures in testdata/cli/.
# Requires macOS (hdiutil). Run from the repository root:
#
#   ./scripts/gen-fixtures.sh
#
# Produces:
#   testdata/cli/basic.dmg        UDZO (zlib) compressed DMG
#   testdata/cli/basic-bz2.dmg    UDBZ (bzip2) compressed DMG
#   testdata/cli/basic-lzfse.dmg  ULFO (lzfse) compressed DMG
#   testdata/cli/basic.img.gz     gzipped raw GPT image (tests decompress it)
#   testdata/cli/manifest.json    expected volume contents with sha256 sums
set -euo pipefail

if [[ "$(uname)" != "Darwin" ]]; then
  echo "error: fixture generation requires macOS (hdiutil)" >&2
  exit 1
fi

OUT_DIR="testdata/cli"
VOLNAME="ACCEPT"
WORK="$(mktemp -d)"
MOUNT="$WORK/mnt"
trap 'hdiutil detach "$MOUNT" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

mkdir -p "$OUT_DIR" "$MOUNT"

echo "==> Creating writable APFS image"
hdiutil create -size 8m -fs APFS -volname "$VOLNAME" -type UDIF \
  -layout GPTSPUD "$WORK/rw.dmg" >/dev/null
hdiutil attach -mountpoint "$MOUNT" -nobrowse "$WORK/rw.dmg" >/dev/null

echo "==> Populating volume"
printf 'hello from apfs\n' > "$MOUNT/hello.txt"
mkdir -p "$MOUNT/dir1/nested"
printf 'deep file\n' > "$MOUNT/dir1/nested/deep.txt"
mkdir -p "$MOUNT/ünïcødé"
printf 'unicode name content\n' > "$MOUNT/ünïcødé/файл.txt"
: > "$MOUNT/empty.txt"

# Incompressible data spanning multiple DMG chunks
dd if=/dev/urandom of="$MOUNT/random.bin" bs=1024 count=1536 2>/dev/null

# Executable
printf '#!/bin/sh\necho ok\n' > "$MOUNT/script.sh"
chmod 0755 "$MOUNT/script.sh"

# Relative symlink and a hardlink
ln -s hello.txt "$MOUNT/link-to-hello"
ln "$MOUNT/hello.txt" "$MOUNT/hardlink-to-hello"

# Extended attribute
xattr -w com.example.test "value42" "$MOUNT/hello.txt"

# decmpfs-compressed file (ditto applies HFS/APFS transparent compression)
seq 1 5000 > "$WORK/compressible.txt"
ditto --hfsCompression "$WORK/compressible.txt" "$MOUNT/compressed.txt" || \
  cp "$WORK/compressible.txt" "$MOUNT/compressed.txt"

sync

echo "==> Writing manifest"
python3 - "$MOUNT" "$OUT_DIR/manifest.json" "$VOLNAME" <<'PYEOF'
import hashlib, json, os, sys

mount, out_path, volname = sys.argv[1], sys.argv[2], sys.argv[3]
files = {}
for root, dirs, names in os.walk(mount):
    dirs.sort()
    # Skip APFS housekeeping
    dirs[:] = [d for d in dirs if d not in (".fseventsd", ".Spotlight-V100", ".Trashes")]
    for name in sorted(names):
        if name in (".DS_Store",):
            continue
        full = os.path.join(root, name)
        rel = os.path.relpath(full, mount)
        entry = {}
        if os.path.islink(full):
            entry["type"] = "symlink"
            entry["target"] = os.readlink(full)
        else:
            entry["type"] = "file"
            entry["size"] = os.path.getsize(full)
            h = hashlib.sha256()
            with open(full, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            entry["sha256"] = h.hexdigest()
            entry["mode"] = oct(os.stat(full).st_mode & 0o777)
        files[rel.replace(os.sep, "/")] = entry

with open(out_path, "w") as f:
    json.dump({"volumeName": volname, "files": files}, f, indent=1, sort_keys=True, ensure_ascii=False)
    f.write("\n")
print(f"    {len(files)} entries")
PYEOF

echo "==> Detaching"
hdiutil detach "$MOUNT" >/dev/null

echo "==> Converting to fixture formats"
rm -f "$OUT_DIR/basic.dmg" "$OUT_DIR/basic-bz2.dmg" "$OUT_DIR/basic-lzfse.dmg" "$OUT_DIR/basic.img.gz"
hdiutil convert "$WORK/rw.dmg" -format UDZO -o "$OUT_DIR/basic.dmg" >/dev/null
hdiutil convert "$WORK/rw.dmg" -format UDBZ -o "$OUT_DIR/basic-bz2.dmg" >/dev/null
hdiutil convert "$WORK/rw.dmg" -format ULFO -o "$OUT_DIR/basic-lzfse.dmg" >/dev/null
hdiutil convert "$WORK/rw.dmg" -format UDTO -o "$WORK/basic" >/dev/null
gzip -9 -c "$WORK/basic.cdr" > "$OUT_DIR/basic.img.gz"

echo "==> Done"
ls -la "$OUT_DIR"
