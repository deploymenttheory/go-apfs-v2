# Pathname authorization source evidence

These files preserve the Apple XNU policy source used to design and review portable pathname authorization. Native syscall captures establish observable behavior on macOS 15, 26 and 27. This source corpus explains the policy and its ordering; it does not replace those captures or assert that every macOS release uses identical private code.

`sources.json` pins eight complete C files to `xnu-11417.140.69`, their original Apple URLs and the SHA-256 of each decompressed file. The gzip files preserve the original license notices. `headers/sources.json` similarly pins 21 complete private headers used to review the declarations and constants needed by the source parser.

`functions.json` selects exact byte ranges and hashes for 24 complete function definitions and the original `vauth_ctx` declaration. It includes immutable checks, POSIX and ACL authorization, ownership/group helpers, create and rename authorization including the complete rename implementation, pathname lookup/search/creation, open authorization and its create/finish helpers, and process permission-override admission and observation. The capture script copies those source bytes unchanged; it rejects a changed hash, an invalid range, a missing function, a duplicate name or a truncated definition.

`declarations.h` makes those complete bodies parsable outside a kernel build. It supplies declarations for unresolved kernel calls and projections of private structure fields. Those projections preserve the relevant field types but **are not ABI layouts**. Allocation entry points remain unresolved declarations. The atomic expression definitions preserve the relaxed load/update operations through Clang builtins. The audit and native-xattr expressions preserve their input checks. No shim is linked or executed, and none enters a production package.

Run the qualification from the repository root on a Mac:

```sh
go test scripts/capture-pathname-authorization-ast.go scripts/capture-pathname-authorization-ast_test.go
go run scripts/capture-pathname-authorization-ast.go -out artifacts/pathname-authorization-ast
```

Clang parses the translation unit for arm64 and x86_64 with both minimal and enabled feature configurations. The enabled configuration includes MAC checks, AppleDouble pairing, audit, filesystem events, triggers, union mounts, volume paths, diagnostics, named resource forks and the secure-kernel branch; the minimal configuration exercises their complementary branches. These configurations deliberately expose both source paths. They do not purport to describe the configuration of a particular running kernel.

All four compilations must succeed with warnings treated as errors. For every function, the capture checks that Clang emitted a complete `CompoundStmt` whose opening and closing offsets match the selected original body. Header-only declarations, duplicate definitions, empty bodies and truncated ASTs fail qualification. The artifact retains compressed ASTs, exact compiler commands and diagnostics, the generated source, declaration shim, all SDK and Clang builtin header dependencies, source and artifact hashes, Git revision and per-function statement-node counts. The macOS 15, 26 and 27 CI jobs perform this qualification alongside the separate syscall oracle.

The remaining qualification work is runtime evidence: native mounted-volume controls, authorization and process-context cases, complete retained per-version fixtures, and all portable and native acceptance gates must still pass. Successful source parsing alone cannot close any of those requirements.
