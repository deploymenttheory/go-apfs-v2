# APFS Tools Port Status

This document tracks the progress of porting libfsapfs tools from C to Go.

## Main Executables

### 1. fsapfsinfo → apfsinfo ✅ COMPLETE
**Status:** Fully ported and functional

**Location:** `cmd/apfsinfo/main.go`

**Dependencies (all ported):**
- ✅ `bodyfile.c/h` → `internal/tools/bodyfile.go`
- ✅ `digest_hash.c/h` → `internal/tools/md5.go`
- ✅ `info_handle.c/h` → `internal/tools/info_handle.go`
- ✅ `path_string.c/h` → `internal/tools/path_string.go`
- ✅ `fsapfstools_output.c/h` → Integrated into info_handle
- ✅ `fsapfstools_signal.c/h` → Native Go signal handling

**Features implemented:**
- ✅ Container information display
- ✅ Volume information display
- ✅ File system hierarchy browsing (`-H`)
- ✅ File entry by identifier (`-E <id>`)
- ✅ File entry by path (`-F <path>`)
- ✅ Bodyfile output (`-B`)
- ✅ MD5 hash calculation (`-d`)
- ✅ Password/recovery password support (`-p`, `-r`)
- ✅ Volume offset support (`-o`)
- ✅ Volume selection (`-f`)

**Command-line options:**
```
-B <file>     Write bodyfile output to file
-d            Calculate MD5 hashes
-E <id>       Display file entry by identifier
-F <path>     Display file entry by path
-f <index>    Select volume by index
-H            Display file system hierarchy
-h            Show help
-o <offset>   Specify volume offset
-p <password> User password
-r <password> Recovery password
-v            Verbose output
-V            Show version
```

### 2. fsapfsmount → apfsmount ⚠️ PARTIAL
**Status:** Basic structure complete, FUSE integration pending

**Location:** `cmd/apfsmount/main.go`

**Dependencies:**
- ✅ `mount_handle.c/h` → `internal/tools/mount_handle.go` (basic structure)
- ❌ `mount_file_entry.c/h` → Not yet ported
- ❌ `mount_file_system.c/h` → Not yet ported
- ❌ `mount_fuse.c/h` → Not yet ported
- ❌ `mount_dokan.c/h` → Not porting (Windows-specific)
- ❌ `mount_path_string.c/h` → Not yet ported

**Current features:**
- ✅ Container opening
- ✅ Password/recovery password support
- ✅ Volume enumeration
- ✅ Signal handling
- ❌ FUSE filesystem mounting
- ❌ File operations (read, readdir, stat, etc.)
- ❌ Extended attributes
- ❌ Symbolic link support

**Note:** Full FUSE implementation requires:
1. FUSE library integration (e.g., `github.com/hanwen/go-fuse/v2`)
2. Mount file entry abstraction layer
3. Mount file system abstraction layer
4. Path translation utilities
5. Proper inode management

## Supporting Components Status

### ✅ Completed Components

| C Source | Go Source | Description |
|----------|-----------|-------------|
| `bodyfile.c/h` | `internal/tools/bodyfile.go` | Bodyfile format generation with full Unicode escaping |
| `digest_hash.c/h` | `internal/tools/md5.go` | MD5 hash calculation for file entries |
| `path_string.c/h` | `internal/tools/path_string.go` | Path manipulation and escape/unescape functions |
| `info_handle.c/h` | `internal/tools/info_handle.go` | Container/volume info display with password unlocking |
| `mount_handle.c/h` | `internal/tools/mount_handle.go` | Basic mount handle structure |

### ❌ Pending Components

| C Source | Priority | Reason |
|----------|----------|--------|
| `mount_file_entry.c/h` | High | Required for FUSE file operations |
| `mount_file_system.c/h` | High | Required for FUSE filesystem abstraction |
| `mount_fuse.c/h` | High | Required for FUSE integration |
| `mount_path_string.c/h` | Medium | Mount-specific path handling |
| `fsapfstools_output.c/h` | Low | Output formatting (mostly integrated) |
| `fsapfstools_signal.c/h` | Low | Signal handling (Go has native support) |
| `mount_dokan.c/h` | Won't Port | Windows-specific, not needed |

## Key Implementation Details

### Bodyfile Format
The Go implementation fully replicates the C bodyfile escaping behavior:
- Control characters (U+0-U+1f, U+7f-U+9f) → `\x##`
- Unicode surrogates and undefined chars → `\U########`
- Escape character `\` → `\\`
- Pipe separator `|` → `\|`

### Path Handling
- Full Unicode path support
- Escape/unescape functions for special characters
- Path normalization and splitting
- Compatible with C implementation

### Password Unlocking
- User password support via `-p` flag
- Recovery password support via `-r` flag
- Automatic volume unlocking on open
- Warning messages for failed unlocks

## Testing Status

### apfsinfo Testing
- ⚠️ Needs testing with real APFS containers
- ⚠️ Needs testing with encrypted volumes
- ⚠️ Needs testing with various file types
- ⚠️ Needs bodyfile output validation

### apfsmount Testing
- ⚠️ Cannot test until FUSE implementation complete
- ⚠️ Needs mount/unmount testing
- ⚠️ Needs file operation testing
- ⚠️ Needs performance testing

## Next Steps

### Priority 1: Complete FUSE Support for apfsmount
1. Read and understand `mount_fuse.c`, `mount_file_entry.c`, `mount_file_system.c`
2. Choose Go FUSE library (recommend: `github.com/hanwen/go-fuse/v2`)
3. Implement `mount_file_entry.go` for file abstraction
4. Implement `mount_file_system.go` for filesystem abstraction
5. Implement `mount_fuse.go` for FUSE integration
6. Add comprehensive error handling
7. Test with real APFS containers

### Priority 2: Testing and Validation
1. Create test APFS containers (encrypted and unencrypted)
2. Test `apfsinfo` with various options
3. Validate bodyfile output format
4. Test MD5 hash calculations
5. Test password unlocking

### Priority 3: Documentation
1. Add usage examples for each tool
2. Document known limitations
3. Add troubleshooting guide
4. Create comparison with C tools

## Build Instructions

```bash
# Build apfsinfo
go build ./cmd/apfsinfo

# Build apfsmount
go build ./cmd/apfsmount

# Install both tools
go install ./cmd/apfsinfo ./cmd/apfsmount
```

## Usage Examples

### apfsinfo Examples

```bash
# Display container info
./apfsinfo /dev/disk2

# Display file hierarchy
./apfsinfo -H /dev/disk2

# Generate bodyfile with MD5 hashes
./apfsinfo -B output.bodyfile -d /dev/disk2

# Show specific file entry
./apfsinfo -F /Users/test/file.txt /dev/disk2

# Use with encrypted volume
./apfsinfo -p "password" /dev/disk2
```

### apfsmount Examples (when complete)

```bash
# Mount all volumes
./apfsmount /dev/disk2 /mnt/apfs

# Mount specific volume
./apfsmount -f 0 /dev/disk2 /mnt/apfs

# Mount with password
./apfsmount -p "password" /dev/disk2 /mnt/apfs
```

## Differences from C Implementation

### Advantages of Go Implementation
- Memory safety (no manual memory management)
- Better error handling with wrapped errors
- Native Unicode support
- Cleaner concurrency model
- Cross-compilation support

### Limitations
- FUSE support incomplete
- May have different performance characteristics
- Some C-specific optimizations not directly applicable

## Code Organization

```
go-apfs-v2/
├── cmd/
│   ├── apfsinfo/           # ✅ Complete
│   │   └── main.go
│   └── apfsmount/          # ⚠️ Partial
│       └── main.go
├── internal/
│   ├── apfs/               # Core APFS library
│   └── tools/              # Tool support code
│       ├── bodyfile.go     # ✅ Complete
│       ├── info_handle.go  # ✅ Complete
│       ├── md5.go          # ✅ Complete
│       ├── mount_handle.go # ✅ Basic structure
│       └── path_string.go  # ✅ Complete
```

## Contributing

When porting additional functionality:
1. Maintain API compatibility with C where reasonable
2. Use Go idioms (errors as values, defer for cleanup)
3. Add comprehensive comments referencing C source
4. Include error handling for all operations
5. Write unit tests
6. Update this status document

