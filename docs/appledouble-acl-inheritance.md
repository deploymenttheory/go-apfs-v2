# ACL creation and AppleDouble restoration

`appledouble.InheritACL(initial, parent, directory)` computes the ACL that local
Darwin creation derives from a captured parent ACL and an optional initial ACL.
Use it when creating a destination in a portable image or metadata model. It runs
in pure Go on Linux, macOS and Windows; it does not apply a macOS ACL as Linux
permissions or a Windows DACL.

Creation and restoration are separate operations. A destination may begin with
inherited permissions, but a valid `File.ACLUpdate` replaces its ACL after the
other AppleDouble metadata is restored. Do not merge the inherited ACL into that
replacement, or run `InheritACL` again. Missing, empty and ignored malformed ACL
records preserve the already-created destination ACL. This also differs from
ordinary `COPYFILE_ACL`, which combines explicit source entries with inherited
destination entries.

## Inputs and results

Both ACL arguments use source UUIDs. Resolve account-based text through the
existing explicit `ACLResolver` before calling this function; never resolve it
against an unrelated receiving host's account database.

- A nil parent means confirmed absence, or deliberately disabled inheritance.
  A failed parent read must be returned by the caller, not converted to nil.
- Initial explicit entries retain their order. Initial inherited entries are
  discarded. Eligible parent entries follow, retaining their relative order.
- Files select `file_inherit`; directories select `directory_inherit`.
  Inherited entries gain `inherited` and lose `only_inherit`. Files and entries
  with `limit_inherit` lose all propagation flags.
- Initial `no_inherit` suppresses parent entries. Parent global flags do not
  suppress a child's inheritance. The result's global flags are zero.
- Entry principal bytes, rights and unrelated flag bits are retained. Results
  do not alias either input.
- No initial ACL and no eligible parent entries produce nil. An explicit empty
  initial ACL produces a non-nil empty ACL; native storage can represent that
  result as absence.
- Allocation counts all initial entries, including those subsequently discarded,
  plus eligible parent entries. Above 128 returns `ErrACLInheritance`. Native
  creation reports ENOMEM for that boundary; the portable API reports a policy
  error rather than pretending the Go process ran out of memory.

Inputs individually exceeding 128 entries are rejected as invalid model inputs.
The function does not model remote filesystems that enforce their own inheritance.
Transport must select the policy appropriate to the source/destination model.

## Native evidence

The implementation follows Apple's complete `kauth_acl_inherit` function at
[XNU f6217f8](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_authorization.c),
whose source SHA-256 is
`6909f51300732fe195252b9de1ce0a2fb5d086af9072dc5746269a8ffeb2e249`.
The oracle retains the pinned source and Clang ASTs for arm64 and x86_64. Kernel
vnode services are declared as syntax-analysis stubs; the complete inheritance
function is unchanged. These ASTs are not a claim to compile or execute XNU.

Independent test-only C calls public `acl_set_file`, `openx_np`, `mkdirx_np`,
`acl_get_file`, `acl_copy_ext` and `copyfile(COPYFILE_UNPACK)`. No C, native helper,
private library or subprocess is used by production code.

The 850-case fixture covers both destination kinds, all 32 entry inheritance-flag
combinations, allow/deny, absent/empty/explicit/inherited initial ACLs, global
flags, mixed principals and ordered parent entries. Four cases require native
creation failure at the allocation limit and confirm no child remains. Twenty-two
cases restore AppleDouble records over actual inherited ACLs, including clearing,
malformed records and duplicates. Successful operations verify destination
identity, mode, ownership, BSD flags and size remain unchanged during unpack;
parent ACLs must also remain unchanged. These checks do not claim timestamp
preservation or write-failure qualification.

Run on a Mac:

```sh
CGO_ENABLED=0 go run scripts/verify-appledouble-acl-inherit.go
```

Every case must match both the portable policy and the archived native bytes.
The artifact retains raw inputs, readbacks, commands, host/SDK identity and source
hashes. `-capture` records observations but never reports policy qualification.
The portable unit suite replays the same fixture on all three operating systems;
`FuzzACLInheritance` exercises bounded composition and input ownership.

## Remaining ACL work

This closes creation-inheritance calculation and qualifies replacement over
inherited ACLs. [Source query capture and replay](appledouble-acl-identities.md)
are available; live source acquisition, real filesystem restoration ordering,
ownership and restrictive BSD flags, permission/write failures and portable
carriers remain shared transport work. Package PR #72 stays draft until the
complete AppleDouble release gate is met; codesign remains paused.
