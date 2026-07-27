# Contribution

Thanks for considering contributing to this project! We are really glad you are reading this, because we need volunteer developers to help this project come to fruition.

Please note we have a code of conduct, please follow it in all your interactions with the project.

## Issues

If you find any bugs, please file an issue in the [GitHub issues][GitHubIssues] page. Please fill out the provided template with the appropriate information.

If you are taking the time to mention a problem, even a seemingly minor one, it is greatly appreciated, and a totally valid contribution to this project. Thank you!

## Proving a refactor changed nothing

Renames, restructures and "no functional change" cleanups in the write path are
exactly where a silent regression hides, because the reviewer has no cheap way
to tell a pure rename from one that moved a byte. Since the writers are
deterministic (see [docs/reproducible-output.md](docs/reproducible-output.md)),
the check is a hash comparison:

```sh
# On the base commit
go build -o /tmp/apfs-before ./cmd/apfs
/tmp/apfs-before pack ./some/tree /tmp/before.dmg --source-date-epoch 1700000000

# On your branch
go build -o /tmp/apfs-after ./cmd/apfs
/tmp/apfs-after pack ./some/tree /tmp/after.dmg --source-date-epoch 1700000000

shasum -a 256 /tmp/before.dmg /tmp/after.dmg   # the two hashes must match
```

Cover the shapes your change touches — a plain volume, a case-sensitive one, one
carrying a snapshot, a nested directory tree — and both `--fs apfs` and
`--fs hfs+`. State in the pull request which you ran.

If the hashes legitimately differ because your change *is* meant to move bytes,
say so explicitly and describe which field moved and why. A byte change in the
write path should never be discovered by a reviewer; it should be announced by
the author.

<!-- References -->

<!-- Local -->
[GitHubIssues]: <https://github.com/segraef/Template/issues>
[Contributing]: CONTRIBUTING.md
