//go:build ignore

// Generate the finite typed Darwin wrapper extension using x/sys's libSystem
// import and runtime-call pattern. No symbol lookup or generic FFI is exposed.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"
)

type binding struct {
	name, symbol, params, args, result, library string
	inode                                       bool
	threeArgs                                   bool
}

func main() {
	check := flag.Bool("check", false, "verify generated wrappers without changing files")
	flag.Parse()
	const system = "/usr/lib/libSystem.B.dylib"
	const quarantine = "/usr/lib/system/libquarantine.dylib"
	const xpc = "/usr/lib/system/libxpc.dylib"
	entries := []binding{
		{name: "FcntlGetPath", symbol: "fcntl", params: "fd int32, path *[unix.PathMax]byte", args: "uintptr(fd), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(path))", result: "int", threeArgs: true},
		{name: "Getattrlistat", symbol: "getattrlistat", params: "fd int32, path *byte, attributes *unix.Attrlist, data unsafe.Pointer, size uintptr, options uint64", args: "uintptr(fd), uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(attributes)), uintptr(data), size, uintptr(options)", result: "int"},
		{name: "Listxattr", symbol: "listxattr", params: "path, data *byte, size uintptr, options int32", args: "uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(data)), size, uintptr(options)", result: "size"},
		{name: "Getxattr", symbol: "getxattr", params: "path, name, data *byte, size uintptr, position uint32, options int32", args: "uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(data)), size, uintptr(position), uintptr(options)", result: "size"},
		{name: "Flistxattr", symbol: "flistxattr", params: "fd int32, data *byte, size uintptr, options int32", args: "uintptr(fd), uintptr(unsafe.Pointer(data)), size, uintptr(options)", result: "size"},
		{name: "Fgetxattr", symbol: "fgetxattr", params: "fd int32, name, data *byte, size uintptr, position uint32, options int32", args: "uintptr(fd), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(data)), size, uintptr(position), uintptr(options)", result: "size"},
		{name: "FilesecInit", symbol: "filesec_init", result: "pointer"},
		{name: "FilesecFree", symbol: "filesec_free", params: "security uintptr", args: "security", result: "void"},
		{name: "FilesecGetProperty", symbol: "filesec_get_property", params: "security uintptr, property int32, output unsafe.Pointer", args: "security, uintptr(property), uintptr(output)", result: "int"},
		{name: "Fstatx", symbol: "fstatx_np", params: "fd int32, stat *unix.Stat_t, security uintptr", args: "uintptr(fd), uintptr(unsafe.Pointer(stat)), security", result: "int", inode: true},
		{name: "FchmodExtended", symbol: "__fchmod_extended", params: "fd int32, uid, gid uint32, mode int32, security uintptr", args: "uintptr(fd), uintptr(uid), uintptr(gid), uintptr(mode), security", result: "int"},
		{name: "Fsetattrlist", symbol: "fsetattrlist", params: "fd int32, attributes *unix.Attrlist, data unsafe.Pointer, size uintptr, options uint32", args: "uintptr(fd), uintptr(unsafe.Pointer(attributes)), uintptr(data), size, uintptr(options)", result: "int"},
		{name: "Ffsctl", symbol: "ffsctl", params: "fd int32, command uintptr, data unsafe.Pointer, options uint32", args: "uintptr(fd), command, uintptr(data), uintptr(options)", result: "int"},
		{name: "Statx", symbol: "statx_np", params: "path *byte, stat *unix.Stat_t, security uintptr", args: "uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(stat)), security", result: "int", inode: true},
		{name: "Lstatx", symbol: "lstatx_np", params: "path *byte, stat *unix.Stat_t, security uintptr", args: "uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(stat)), security", result: "int", inode: true},
		{name: "ChmodExtended", symbol: "__chmod_extended", params: "path *byte, uid, gid uint32, mode int32, security uintptr", args: "uintptr(unsafe.Pointer(path)), uintptr(uid), uintptr(gid), uintptr(mode), security", result: "int"},
		{name: "OpenDprotected", symbol: "__open_dprotected_np", params: "path *byte, flags, class, dpflags int32, mode uint32", args: "uintptr(unsafe.Pointer(path)), uintptr(flags), uintptr(class), uintptr(dpflags), uintptr(mode)", result: "int"},
		{name: "MacSyscall", symbol: "__mac_syscall", params: "policy *byte, operation int32, data unsafe.Pointer", args: "uintptr(unsafe.Pointer(policy)), uintptr(operation), uintptr(data)", result: "int"},
		{name: "QuarantineProcessAlloc", symbol: "_qtn_proc_alloc", result: "pointer", library: quarantine},
		{name: "QuarantineProcessFree", symbol: "_qtn_proc_free", params: "process uintptr", args: "process", result: "void", library: quarantine},
		{name: "QuarantineProcessInit", symbol: "_qtn_proc_init_with_self", params: "process uintptr", args: "process", result: "int", library: quarantine},
		{name: "AppSandboxed", symbol: "_xpc_runtime_is_app_sandboxed", result: "bool", library: xpc},
		{name: "Getpwuid", symbol: "getpwuid_r", params: "id uint32, record *Passwd, buffer *byte, size uintptr, result **Passwd", args: "uintptr(id), uintptr(unsafe.Pointer(record)), uintptr(unsafe.Pointer(buffer)), size, uintptr(unsafe.Pointer(result))", result: "code"},
		{name: "Getpwnam", symbol: "getpwnam_r", params: "name *byte, record *Passwd, buffer *byte, size uintptr, result **Passwd", args: "uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(record)), uintptr(unsafe.Pointer(buffer)), size, uintptr(unsafe.Pointer(result))", result: "code"},
		{name: "Getgrgid", symbol: "getgrgid_r", params: "id uint32, record *Group, buffer *byte, size uintptr, result **Group", args: "uintptr(id), uintptr(unsafe.Pointer(record)), uintptr(unsafe.Pointer(buffer)), size, uintptr(unsafe.Pointer(result))", result: "code"},
		{name: "Getgrnam", symbol: "getgrnam_r", params: "name *byte, record *Group, buffer *byte, size uintptr, result **Group", args: "uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(record)), uintptr(unsafe.Pointer(buffer)), size, uintptr(unsafe.Pointer(result))", result: "code"},
		{name: "UserUUID", symbol: "mbr_uid_to_uuid", params: "id uint32, uuid *[16]byte", args: "uintptr(id), uintptr(unsafe.Pointer(uuid))", result: "code"},
		{name: "GroupUUID", symbol: "mbr_gid_to_uuid", params: "id uint32, uuid *[16]byte", args: "uintptr(id), uintptr(unsafe.Pointer(uuid))", result: "code"},
		{name: "UUIDIdentity", symbol: "mbr_uuid_to_id", params: "uuid *[16]byte, id *uint32, kind *int32", args: "uintptr(unsafe.Pointer(uuid)), uintptr(unsafe.Pointer(id)), uintptr(unsafe.Pointer(kind))", result: "code"},
	}
	const dir = "internal/darwinabi"
	must(os.MkdirAll(dir, 0755))
	for _, arch := range []string{"arm64", "amd64"} {
		var source, assembly strings.Builder
		source.WriteString("// Code generated by go run scripts/generate-darwin-wrappers.go; DO NOT EDIT.\n//go:build darwin && " + arch + "\n\npackage darwinabi\nimport (\"unsafe\"\n\n\"golang.org/x/sys/unix\")\n")
		assembly.WriteString("// Code generated by go run scripts/generate-darwin-wrappers.go; DO NOT EDIT.\n#include \"textflag.h\"\n")
		for _, item := range entries {
			library := item.library
			if library == "" {
				library = system
			}
			symbol := item.symbol
			if item.inode && arch == "amd64" {
				symbol += "$INODE64"
			}
			args := []string{}
			if item.args != "" {
				args = strings.Split(item.args, ", ")
			}
			width := 6
			if item.threeArgs {
				width = 3
			}
			for len(args) < width {
				args = append(args, "0")
			}
			ret := "(int32,error)"
			mode := "syscall6"
			if item.threeArgs {
				mode = "syscall3"
			}
			body := "if e != 0 { return int32(r), e }; return int32(r), nil"
			switch item.result {
			case "size":
				ret = "(int64,error)"
				mode = "syscall6X"
				body = "if e != 0 { return 0, e }; return int64(r), nil"
			case "pointer":
				ret = "uintptr"
				mode = "syscall6X"
				body = "return r"
			case "void":
				ret = ""
				body = ""
			case "code":
				ret = "int32"
				body = "return int32(r)"
			case "bool":
				ret = "bool"
				body = "return byte(r) != 0"
			}
			lhs := "r, _, e"
			if item.result == "pointer" || item.result == "code" || item.result == "bool" {
				lhs = "r, _, _"
			}
			if item.result == "void" {
				lhs = "_, _, _"
			}
			assign := ":="
			if item.result == "void" {
				assign = "="
			}
			fmt.Fprintf(&source, "\n// %s is the typed %s wrapper.\n//go:uintptrescapes\nfunc %s(%s) %s {\n%s %s %s(addr%s, %s)\n%s\n}\n", item.name, item.symbol, item.name, item.params, ret, lhs, assign, mode, item.name, strings.Join(args, ", "), body)
			fmt.Fprintf(&source, "var addr%s uintptr\n//go:cgo_import_dynamic imported%s %s %q\n", item.name, item.name, symbol, library)
			fmt.Fprintf(&assembly, "\nTEXT trampoline%s<>(SB),NOSPLIT,$0-0\n\tJMP imported%s(SB)\nGLOBL ·addr%s(SB), RODATA, $8\nDATA ·addr%s(SB)/8, $trampoline%s<>(SB)\n", item.name, item.name, item.name, item.name, item.name)
		}
		formatted, err := format.Source([]byte(source.String()))
		must(err)
		write(filepath.Join(dir, "zsyscall_darwin_"+arch+".go"), formatted, *check)
		write(filepath.Join(dir, "zsyscall_darwin_"+arch+".s"), []byte(assembly.String()), *check)
	}
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}

func write(path string, data []byte, check bool) {
	if check {
		current, err := os.ReadFile(path)
		must(err)
		if !bytes.Equal(current, data) {
			panic(path + ": stale generated wrapper; run go run scripts/generate-darwin-wrappers.go")
		}
		return
	}
	must(os.WriteFile(path, data, 0644))
}
