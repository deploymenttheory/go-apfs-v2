#!/bin/bash
# Generates the committed CLI acceptance-test fixtures in testdata/cli/.
# Requires macOS (hdiutil, ditto, xattr). Run from the repository root:
#
#   ./scripts/gen-fixtures.sh          # both file systems
#   ./scripts/gen-fixtures.sh apfs     # only the APFS set
#   ./scripts/gen-fixtures.sh hfs+     # only the HFS+ set
#
# Produces:
#   testdata/cli/basic.dmg          UDZO (zlib) compressed DMG, APFS
#   testdata/cli/basic-bz2.dmg      UDBZ (bzip2) compressed DMG, APFS
#   testdata/cli/basic-lzfse.dmg    ULFO (lzfse) compressed DMG, APFS
#   testdata/cli/basic.img.gz       gzipped raw GPT image (tests decompress it)
#   testdata/cli/manifest.json      expected APFS volume contents
#   testdata/cli/hfs-basic.dmg      UDZO (zlib) compressed DMG, HFS+
#   testdata/cli/hfs-manifest.json  expected HFS+ volume contents
#
# The fixtures are committed rather than built during the test run, which is
# what lets the suite run on Linux and Windows. This script is the record of how
# they were made, not a build step -- so regenerating is a deliberate,
# macOS-only maintenance operation, and it rewrites every byte of the images it
# touches.
#
# Both volumes get the same tree, so a test can compare the two file systems
# against each other. The one exception is transparent compression, which ditto
# applies on both but which only the APFS reader currently decodes.
set -euo pipefail

if [[ "$(uname)" != "Darwin" ]]; then
  echo "error: fixture generation requires macOS (hdiutil)" >&2
  exit 1
fi

TARGET="${1:-all}"
case "$TARGET" in
  all|apfs|hfs+) ;;
  *) echo "usage: $0 [all|apfs|hfs+]" >&2; exit 2 ;;
esac

OUT_DIR="testdata/cli"
WORK="$(mktemp -d)"
MOUNT="$WORK/mnt"
trap 'hdiutil detach "$MOUNT" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

mkdir -p "$OUT_DIR" "$MOUNT"

# deterministic_bytes writes n bytes of reproducible pseudo-random data. Using
# /dev/urandom here would make every regeneration produce a different fixture,
# which is the opposite of what a committed fixture is for.
deterministic_bytes() {
  local count="$1" out="$2"
  head -c "$count" < <(openssl enc -aes-256-ctr -pass pass:go-apfs-v2-fixture -nosalt < /dev/zero 2>/dev/null) > "$out"
}

# populate writes the fixture tree into an attached volume.
populate() {
  local mount="$1"

  printf 'hello from apfs\n' > "$mount/hello.txt"
  mkdir -p "$mount/dir1/nested"
  printf 'deep file\n' > "$mount/dir1/nested/deep.txt"
  mkdir -p "$mount/ünïcødé"
  printf 'unicode name content\n' > "$mount/ünïcødé/файл.txt"
  : > "$mount/empty.txt"

  # Incompressible data spanning multiple DMG chunks.
  deterministic_bytes $((1536 * 1024)) "$mount/random.bin"

  # Executable
  printf '#!/bin/sh\necho ok\n' > "$mount/script.sh"
  chmod 0755 "$mount/script.sh"

  # Relative symlink and a hardlink
  ln -s hello.txt "$mount/link-to-hello"
  ln "$mount/hello.txt" "$mount/hardlink-to-hello"

  # A small extended attribute, stored inside its own attribute record.
  xattr -w com.example.test "value42" "$mount/hello.txt"

  # A large extended attribute. On HFS+ this cannot fit in an inline record, so
  # it forces the fork-data and extents record shapes the reader must handle.
  python3 -c 'import sys; sys.stdout.write("A" * 6000)' > "$WORK/bigattr"
  printf 'file with a large attribute\n' > "$mount/bigattr.txt"
  xattr -w com.example.big "$(cat "$WORK/bigattr")" "$mount/bigattr.txt"

  # A real resource fork. On HFS+ this lives in the catalog record rather than
  # the attributes file, but every tool reports it as com.apple.ResourceFork.
  printf 'resource fork contents\n' > "$mount/rsrc.txt"
  printf 'this is the resource fork payload\n' > "$mount/rsrc.txt/..namedfork/rsrc"

  # decmpfs-compressed file. ditto applies transparent compression on both file
  # systems; if it declines, the fallback copy keeps the tree complete and the
  # manifest records the file as uncompressed.
  seq 1 5000 > "$WORK/compressible.txt"
  ditto --hfsCompression "$WORK/compressible.txt" "$mount/compressed.txt" || \
    cp "$WORK/compressible.txt" "$mount/compressed.txt"

  sync
}

# write_manifest records the volume's contents: content hashes, sizes, modes,
# symlink targets, extended attributes and whether a file is compressed.
write_manifest() {
  local mount="$1" out="$2" volname="$3"

  python3 - "$mount" "$out" "$volname" <<'PYEOF'
import hashlib, json, os, stat, subprocess, sys

mount, out_path, volname = sys.argv[1], sys.argv[2], sys.argv[3]


def xattrs_of(path):
    """Extended attributes as {name: {size, sha256}}.

    Shelling out to xattr rather than using os.listxattr, which CPython only
    provides on Linux. Note macOS hides com.apple.decmpfs and the resource fork
    from a normal listing, so a compressed file reports fewer attributes here
    than the on-disk attributes file actually holds -- which is why tests assert
    that these are present rather than that they are all there is.
    """
    listing = subprocess.run(["xattr", "-s", path], capture_output=True, text=True)
    if listing.returncode != 0:
        return {}
    out = {}
    for name in listing.stdout.split():
        got = subprocess.run(["xattr", "-s", "-p", "-x", name, path], capture_output=True, text=True)
        if got.returncode != 0:
            continue
        raw = bytes.fromhex("".join(got.stdout.split()))
        out[name] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    return out


files = {}
for root, dirs, names in os.walk(mount):
    dirs.sort()
    # Skip file-system housekeeping
    dirs[:] = [d for d in dirs if d not in (".fseventsd", ".Spotlight-V100", ".Trashes", ".HFS+ Private Directory Data\r")]
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
            # A compressed file reads back decompressed, so the size and hash
            # recorded here are of the content a reader must reproduce.
            entry["size"] = os.path.getsize(full)
            h = hashlib.sha256()
            with open(full, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            entry["sha256"] = h.hexdigest()
            st = os.stat(full)
            entry["mode"] = oct(st.st_mode & 0o777)
            if getattr(st, "st_flags", 0) & stat.UF_COMPRESSED:
                entry["compressed"] = True
        attrs = xattrs_of(full)
        if attrs:
            entry["xattrs"] = attrs
        files[rel.replace(os.sep, "/")] = entry

with open(out_path, "w") as f:
    json.dump({"volumeName": volname, "files": files}, f, indent=1, sort_keys=True, ensure_ascii=False)
    f.write("\n")
print(f"    {len(files)} entries")
PYEOF
}

if [[ "$TARGET" == "all" || "$TARGET" == "apfs" ]]; then
  VOLNAME="ACCEPT"

  echo "==> Creating writable APFS image"
  hdiutil create -size 16m -fs APFS -volname "$VOLNAME" -type UDIF \
    -layout GPTSPUD "$WORK/rw.dmg" >/dev/null
  hdiutil attach -mountpoint "$MOUNT" -nobrowse "$WORK/rw.dmg" >/dev/null

  echo "==> Populating APFS volume"
  populate "$MOUNT"

  echo "==> Writing APFS manifest"
  write_manifest "$MOUNT" "$OUT_DIR/manifest.json" "$VOLNAME"

  echo "==> Detaching"
  hdiutil detach "$MOUNT" >/dev/null

  echo "==> Converting to fixture formats"
  rm -f "$OUT_DIR/basic.dmg" "$OUT_DIR/basic-bz2.dmg" "$OUT_DIR/basic-lzfse.dmg" "$OUT_DIR/basic.img.gz"
  hdiutil convert "$WORK/rw.dmg" -format UDZO -o "$OUT_DIR/basic.dmg" >/dev/null
  hdiutil convert "$WORK/rw.dmg" -format UDBZ -o "$OUT_DIR/basic-bz2.dmg" >/dev/null
  hdiutil convert "$WORK/rw.dmg" -format ULFO -o "$OUT_DIR/basic-lzfse.dmg" >/dev/null
  hdiutil convert "$WORK/rw.dmg" -format UDTO -o "$WORK/basic" >/dev/null
  gzip -9 -c "$WORK/basic.cdr" > "$OUT_DIR/basic.img.gz"
  rm -f "$WORK/rw.dmg" "$WORK/basic.cdr"
fi

if [[ "$TARGET" == "all" || "$TARGET" == "hfs+" ]]; then
  HFS_VOLNAME="HFSTEST"

  echo "==> Creating writable HFS+ image"
  hdiutil create -size 16m -fs HFS+ -volname "$HFS_VOLNAME" -type UDIF \
    -layout GPTSPUD "$WORK/hfs-rw.dmg" >/dev/null
  hdiutil attach -mountpoint "$MOUNT" -nobrowse "$WORK/hfs-rw.dmg" >/dev/null

  echo "==> Populating HFS+ volume"
  populate "$MOUNT"

  echo "==> Writing HFS+ manifest"
  write_manifest "$MOUNT" "$OUT_DIR/hfs-manifest.json" "$HFS_VOLNAME"

  echo "==> Detaching"
  hdiutil detach "$MOUNT" >/dev/null

  echo "==> Converting to fixture format"
  rm -f "$OUT_DIR/hfs-basic.dmg"
  hdiutil convert "$WORK/hfs-rw.dmg" -format UDZO -o "$OUT_DIR/hfs-basic.dmg" >/dev/null
  rm -f "$WORK/hfs-rw.dmg"
fi

echo "==> Done"
ls -la "$OUT_DIR"
