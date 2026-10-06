# Pathname-cache source supplement

This corpus explains the versioned symlink/trailing-slash lookup observations
without changing the source bindings of the earlier pathname authorization corpus.
The complete, unmodified `vfs_cache.c` from Apple's `xnu-11417.140.69` release is
retained with its original license notices. `source.json` identifies its upstream
URL, full-file hash, unchanged fragment, and five complete function bodies.

`cache_lookup_path` clears `NAMEI_TRAILINGSLASH` when restarting cached component
parsing. It sets the flag again only when the new pathname contains a terminal
slash. The existing pinned `lookup_handle_symlink` source rebuilds the path before
that restart. This supports the macOS 15 route that discards a caller's terminal
slash after following the final symlink; a slash inside the link target is parsed
again. Genuine macOS 26/27 captures instead require a directory for the original
terminal slash. The version routing is established by native results; this older
source is not presented as the implementation of an unreleased kernel source tree.

Run from the repository root:

```sh
go test -count=1 -v scripts/capture-pathname-authorization-ast.go scripts/capture-name-cache-ast_test.go
```

The supplement reuses the established AST body-range and dependency parsers. It
compiles the five unchanged bodies for arm64 and x86_64, with optional MAC,
trigger, firmlink and named-stream branches enabled and disabled, using `-Werror`.
Negative tests reject changed source hashes, body bounds and function inventories.
Each native runner retains the complete ASTs, compiler diagnostics, source/SDK
header bytes and hashes, exact commands, host/SDK identity and checkout revision.

The private vnode and mount field declarations are explicit syntax-only
projections extending the existing research header. They are never linked or
executed and do not claim native ABI layouts. Constants in the supplement come
from the already pinned `vnode_internal.h` and `mount_internal.h`; resource-fork
path spelling comes from the host kernel SDK's `sys/paths.h`. Native behavior is
qualified separately by all retained pathname-limit and existing-name cases.
