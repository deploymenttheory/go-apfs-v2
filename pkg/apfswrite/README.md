# pkg/apfswrite — APFS filesystem writer (GPL-2.0)

**This package is licensed under the GNU General Public License, version 2**
(see `LICENSE` in this directory), separately from the rest of this
repository, which is MIT.

It is a Go port of **mkapfs**, part of
[apfsprogs](https://github.com/linux-apfs/apfsprogs) by Ernesto A. Fernández,
which is GPL-2.0. Because a translation is a derivative work, this package and
any binary that links it (including the `apfs` CLI when built with APFS-write
support) are covered by the GPL-2.0. The MIT-licensed library packages in this
repository (`pkg/apfs`, `pkg/hfsplus`, `pkg/disk`) remain independently usable
under the MIT license when not combined with this package.

On-disk format details are additionally cross-referenced against Apple's
*Apple File System Reference* (see `spec/`).

Original work: Copyright (C) 2019 Ernesto A. Fernández.
Go port: Copyright (C) 2026 Deployment Theory.
