/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)vnode.h	8.17 (Berkeley) 5/20/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

/* Research-only declaration shim: opaque layout field projections are NOT runtime ABI. */
#define KERNEL 1
#define componentname sdk_componentname
#define cache_lookup sdk_cache_lookup
#define cache_enter sdk_cache_enter
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/kauth.h>
#include <sys/namei.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/ioccom.h>
#include <libkern/libkern.h>
#undef componentname
#undef cache_lookup
#undef cache_enter
enum path_operation { OP_LOOKUP,OP_MOUNT,OP_UNMOUNT,OP_STATFS,OP_OPEN,OP_LINK,OP_UNLINK,OP_RENAME,OP_CHDIR,OP_CHROOT,OP_MKNOD,OP_MKFIFO,OP_SYMLINK,OP_ACCESS,OP_PATHCONF,OP_READLINK,OP_GETATTR,OP_SETATTR,OP_TRUNCATE,OP_COPYFILE,OP_MKDIR,OP_RMDIR,OP_REVOKE,OP_EXCHANGEDATA,OP_SEARCHFS,OP_FSCTL,OP_GETXATTR,OP_SETXATTR,OP_REMOVEXATTR,OP_LISTXATTR,OP_MAXOP };
struct nameidata;
struct componentname {
uint32_t cn_nameiop,cn_flags;
vfs_context_t cn_context;
struct nameidata *cn_ndp;
char *cn_pnbuf; int cn_pnlen,cn_namelen; char *cn_nameptr;
uint32_t cn_hash; uint32_t cn_consume;
};
struct vfs_context { proc_t vc_proc; kauth_cred_t vc_ucred; };
struct vnode { uint32_t v_flag; uint16_t v_lflag; uint8_t v_type; uint16_t v_tag; int v_nc_generation; int32_t v_usecount; vnode_t v_parent; mount_t v_mount; const char *v_name; };
struct filedesc { vnode_t fd_rdir; uint32_t fd_flags; };
struct proc { struct filedesc p_fd; volatile u_short p_vfs_iopolicy; unsigned int p_flag; };
struct _iopol_param_t;
extern int securelevel,hz; extern unsigned int kdebug_enable;
extern vnode_t rootvnode;
extern lck_rw_t rootvnode_rw_lock;
#define PATHBUFLEN 256
struct nameidata {
	/*
	 * Arguments to namei/lookup.
	 */
	user_addr_t ni_dirp;            /* pathname pointer */
	enum    uio_seg ni_segflg;      /* location of pathname */
	enum    path_operation ni_op;   /* intended operation, see enum path_operation in vnode.h */
	/*
	 * Arguments to lookup.
	 */
	struct  vnode *ni_startdir;     /* starting directory */
	struct  vnode *ni_rootdir;      /* logical root directory */
	struct  vnode *ni_usedvp;       /* directory passed in via USEDVP */
	/*
	 * Results: returned from/manipulated by lookup
	 */
	struct  vnode *ni_vp;           /* vnode of result */
	struct  vnode *ni_dvp;          /* vnode of intermediate directory */
	/*
	 * Shared between namei and lookup/commit routines.
	 */
	u_int   ni_pathlen;             /* remaining chars in path */
	char    *ni_next;               /* next location in pathname */
	char    ni_pathbuf[PATHBUFLEN];
	u_long  ni_loopcnt;             /* count of symlinks encountered */

	struct componentname ni_cnd;
	int32_t ni_flag;
	int ni_ncgeneration;            /* For a batched vnop, grab generation beforehand */
};
#ifndef CN_SECLUDE_RENAME
#define CN_SECLUDE_RENAME 0x10000000 /*rename iff ￢(hard-linked ∨ opened ∨ mmaped)*/
#endif
#ifndef CN_RAW_ENCRYPTED
#define CN_RAW_ENCRYPTED 0x80000000 /* Look-up is for RO raw encrypted access. */
#endif
#ifndef NAMEI_CONTLOOKUP
#define NAMEI_CONTLOOKUP        0x002    /* Continue processing a lookup which was partially processed in a compound VNOP */
#endif
#ifndef NAMEI_TRAILINGSLASH
#define NAMEI_TRAILINGSLASH     0x004    /* There was at least one trailing slash after last component */
#endif
#ifndef NAMEI_UNFINISHED
#define NAMEI_UNFINISHED        0x008    /* We broke off a lookup to do a compound op */
#endif
#ifndef NAMEI_COMPOUNDOPEN
#define NAMEI_COMPOUNDOPEN      0x010
#endif
#ifndef NAMEI_COMPOUNDREMOVE
#define NAMEI_COMPOUNDREMOVE    0x020
#endif
#ifndef NAMEI_COMPOUNDMKDIR
#define NAMEI_COMPOUNDMKDIR     0x040
#endif
#ifndef NAMEI_COMPOUNDRMDIR
#define NAMEI_COMPOUNDRMDIR     0x080
#endif
#ifndef NAMEI_COMPOUNDRENAME
#define NAMEI_COMPOUNDRENAME    0x100
#endif
#ifndef NAMEI_COMPOUND_OP_MASK
#define NAMEI_COMPOUND_OP_MASK (NAMEI_COMPOUNDOPEN | NAMEI_COMPOUNDREMOVE | NAMEI_COMPOUNDMKDIR | NAMEI_COMPOUNDRMDIR | NAMEI_COMPOUNDRENAME)
#endif
#ifndef NAMEI_NOFOLLOW_ANY
#define NAMEI_NOFOLLOW_ANY      0x1000  /* no symlinks allowed in the path */
#endif
#ifndef NAMEI_ROOTDIR
#define NAMEI_ROOTDIR           0x2000  /* Limit lookup to ni_rootdir (similar to chroot) */
#endif
#ifndef NAMEI_RESOLVE_BENEATH
#define NAMEI_RESOLVE_BENEATH   0x4000  /* path resolution must not escape the starting directory */
#endif
#ifndef NOCACHE
#define NOCACHE         0x00000020 /* name must not be left in cache */
#endif
#ifndef NOCROSSMOUNT
#define NOCROSSMOUNT    0x00000100 /* do not cross mount points */
#endif
#ifndef RDONLY
#define RDONLY          0x00000200 /* lookup with read-only semantics */
#endif
#ifndef HASBUF
#define HASBUF          0x00000400 /* has allocated pathname buffer */
#endif
#ifndef DONOTAUTH
#define DONOTAUTH       0x00000800 /* do not authorize during lookup */
#endif
#ifndef SAVESTART
#define SAVESTART       0x00001000 /* save starting directory */
#endif
#ifndef ISSYMLINK
#define ISSYMLINK       0x00010000 /* symlink needs interpretation */
#endif
#ifndef WILLBEDIR
#define WILLBEDIR       0x00080000 /* new files will be dirs; allow trailing / */
#endif
#ifndef AUDITVNPATH1
#define AUDITVNPATH1    0x00100000 /* audit the path/vnode info */
#endif
#ifndef USEDVP
#define USEDVP          0x00400000 /* start the lookup at ndp.ni_dvp */
#endif
#ifndef CN_VOLFSPATH
#define CN_VOLFSPATH    0x00800000 /* user path was a volfs style path */
#endif
#ifndef CN_FIRMLINK_NOFOLLOW
#define CN_FIRMLINK_NOFOLLOW    0x01000000 /* Do not follow firm links */
#endif
#ifndef CN_WANTSRSRCFORK
#define CN_WANTSRSRCFORK 0x04000000
#endif
#ifndef CN_ALLOWRSRCFORK
#define CN_ALLOWRSRCFORK 0x08000000
#endif
#ifndef CN_NBMOUNTLOOK
#define CN_NBMOUNTLOOK  0x20000000 /* do not block for cross mount lookups */
#endif
#ifndef CN_SKIPNAMECACHE
#define CN_SKIPNAMECACHE        0x40000000      /* skip cache during lookup(), allow FS to handle all components */
#endif
#ifndef VL_DEAD
#define VL_DEAD         0x0010          /* vnode is dead, cleaned of filesystem-specific info */
#endif
#ifndef VROOT
#define VROOT           0x000001        /* root of its file system */
#endif
#ifndef VOPENEVT
#define VOPENEVT        0x800000        /* if process is P_CHECKOPENEVT, then or in the O_EVTONLY flag on open */
#endif
#ifndef VN_CREATE_DOOPEN
#define VN_CREATE_DOOPEN                (1<<4)  /* Open file if a batched operation is available */
#endif
#ifndef VNODE_REF_FORCE
#define VNODE_REF_FORCE 0x1
#endif
#ifndef VA_DP_RAWENCRYPTED
#define VA_DP_RAWENCRYPTED   0x0001
#endif
#ifndef VA_DP_RAWUNENCRYPTED
#define VA_DP_RAWUNENCRYPTED 0x0002
#endif
#ifndef VA_DP_AUTHENTICATE
#define VA_DP_AUTHENTICATE   0x0004
#endif
#ifndef KAUTH_WKG_NOT
#define KAUTH_WKG_NOT           0       /* not a well-known GUID */
#endif
#ifndef KAUTH_WKG_OWNER
#define KAUTH_WKG_OWNER         1
#endif
#ifndef KAUTH_WKG_GROUP
#define KAUTH_WKG_GROUP         2
#endif
#ifndef KAUTH_WKG_NOBODY
#define KAUTH_WKG_NOBODY        3
#endif
#ifndef KAUTH_WKG_EVERYBODY
#define KAUTH_WKG_EVERYBODY     4
#endif
#ifndef P_VFS_IOPOLICY_IGNORE_NODE_PERMISSIONS
#define P_VFS_IOPOLICY_IGNORE_NODE_PERMISSIONS          0x0040
#endif
#ifndef P_CHECKOPENEVT
#define P_CHECKOPENEVT  0x00080000      /* check if a vnode has the OPENEVT flag set on open */
#endif
#ifndef ERECYCLE
#define ERECYCLE        (-5)            /* restart lookup under heavy vnode pressure/recycling */
#endif
#ifndef EREDRIVEOPEN
#define EREDRIVEOPEN    (-6)            /* redrive open */
#endif
#ifndef EKEEPLOOKING
#define EKEEPLOOKING    (-7)
#endif
#define IMMUTABLE (UF_IMMUTABLE | SF_IMMUTABLE)
#define APPEND (UF_APPEND | SF_APPEND)
#define FD_CHROOT 0x01
#define RESOLVE_NOFOLLOW_ANY 0x00000001
#define RESOLVE_CHECKED 0x80000000
#define RETRY_NO_YIELD_COUNT 5
#define COMPOUND_OPEN_STATUS_DID_CREATE 0x00000001
int cache_lookup(vnode_t,vnode_t *,struct componentname *);
void cache_enter(vnode_t,vnode_t,struct componentname *);
#include <os/atomic.h>
#define MAXLONGPATHLEN 8192
#define Z_WAITOK 0x0000
#define Z_ZERO 0x0004
#define Z_NOFAIL 0x8000
extern void *ZV_NAMEI;
typedef struct fsioc_auth_fs { vnode_t authvp; uint64_t flags; } fsioc_auth_fs_t;
#define FSIOC_AUTH_FS _IOW('A',24,fsioc_auth_fs_t)
#define IOPOL_CMD_GET 1
#define IOPOL_CMD_SET 2
#define AUTHORIZED_ACCESS_ENTITLEMENT "com.apple.private.vfs.authorized-access"
struct mount { vnode_t mnt_vnodecovered; uint32_t mnt_flag; uint32_t mnt_kern_flag; };
struct _iopol_param_t { int iop_scope; int iop_iotype; int iop_policy; };
proc_t current_proc(void);
/* These expression macros preserve the relevant relaxed atomic operations;
 * this translation unit is parsed, never linked or executed. */
#define os_atomic_load(p,order) __atomic_load_n((p),__ATOMIC_RELAXED)
#define os_atomic_inc_orig(p,order) __atomic_fetch_add((p),1,__ATOMIC_RELAXED)
#define os_atomic_dec_orig(p,order) __atomic_fetch_sub((p),1,__ATOMIC_RELAXED)
#define os_atomic_andnot(p,v,order) __atomic_and_fetch((p),~(v),__ATOMIC_RELAXED)
#define os_atomic_or(p,v,order) __atomic_or_fetch((p),(v),__ATOMIC_RELAXED)
#define fdt_flag_test(fdt,flag) (((fdt)->fd_flags & (flag)) != 0)
void vnode_cache_authorized_action(vnode_t,vfs_context_t,kauth_action_t);
int vnode_compound_rename_available(vnode_t);
int kauth_authorize_fileop(kauth_cred_t,kauth_action_t,uintptr_t,uintptr_t);
int kauth_wellknown_guid(guid_t *);
int lookup_handle_found_vnode(struct nameidata *,struct componentname *,int,int,int *,int,int,int,vfs_context_t);
int lookup_check_for_resolve_prefix(char *,size_t,size_t,uint32_t *,size_t *);
void *zalloc(void *);
void zfree(void *,void *);
void *kalloc_data(size_t,uint32_t);
void kfree_data(void *,size_t);
bool proc_support_long_paths(proc_t);
int proc_is_forcing_hfs_case_sensitivity(proc_t);
void proc_dirs_lock_shared(proc_t);
void proc_dirs_unlock_shared(proc_t);
vnode_t vfs_context_cwd(vfs_context_t);
int lookup_handle_symlink(struct nameidata *,vnode_t *,bool *,vfs_context_t);
int vnode_ref_ext(vnode_t,int,int);
int lookup_handle_emptyname(struct nameidata *,struct componentname *,int);
int cache_lookup_path(struct nameidata *,struct componentname *,vnode_t,vfs_context_t,int *,vnode_t);
int vnode_issubdir(vnode_t,vnode_t,int *,vfs_context_t);
vfs_context_t vfs_context_kernel(void);
int namei_compound_available(vnode_t,struct nameidata *);
int VNOP_LOOKUP(vnode_t,vnode_t *,struct componentname *,vfs_context_t);
void kdebug_lookup(vnode_t,struct componentname *);
int vnode_compound_open_available(vnode_t);
void nameidone(struct nameidata *);
int VNOP_COMPOUND_OPEN(vnode_t,vnode_t *,struct nameidata *,int32_t,int32_t,uint32_t *,struct vnode_attr *,vfs_context_t);
int vn_authorize_open_existing(vnode_t,struct componentname *,int,vfs_context_t,void *);
boolean_t IOCurrentTaskHasEntitlement(const char *);
int VNOP_OPEN(vnode_t,int,vfs_context_t);
int VNOP_CLOSE(vnode_t,int,vfs_context_t);
int tsleep(void *,int,const char *,int);
errno_t vn_create(vnode_t,vnode_t *,struct nameidata *,struct vnode_attr *,uint32_t,int,uint32_t *,vfs_context_t);
#define MNTK_EXTENDED_ATTRS 0x00080000
#define NATIVE_XATTR(VP) ((VP)->v_mount ? (VP)->v_mount->mnt_kern_flag & MNTK_EXTENDED_ATTRS : 0)
int dot_underbar_check_paired_vnode(struct componentname *,vnode_t,vnode_t,vfs_context_t);
int mac_vnode_check_create(vfs_context_t,vnode_t,struct componentname *,struct vnode_attr *);
int mac_vnode_check_rename_swap(vfs_context_t,vnode_t,vnode_t,struct componentname *,vnode_t,vnode_t,struct componentname *);
int mac_vnode_check_rename(vfs_context_t,vnode_t,vnode_t,struct componentname *,vnode_t,vnode_t,struct componentname *);
int mac_vnode_check_lookup(vfs_context_t,vnode_t,struct componentname *);
int mac_vnode_check_lookup_preflight(vfs_context_t,vnode_t,const char *,size_t);
void mac_vnode_notify_open(vfs_context_t,vnode_t,int);
#define VOLFS_MIN_PATH_LEN 9
#define MAX_VOLFS_RESTARTS 5
int vfs_getrealpath(const char *,char *,size_t,vfs_context_t);
#define AUDITVNPATH2 0x00200000
#define ARG_UPATH1 0x0000000002000000ULL
#define ARG_UPATH2 0x0000000004000000ULL
struct kaudit_record;
struct uthread {int uu_flag; vnode_t uu_cdir; struct kaudit_record *uu_ar;};
typedef struct uthread *uthread_t;
uthread_t current_uthread(void);
extern int audit_syscalls;
#define AUDIT_RECORD() (current_uthread()->uu_ar)
#define AUDIT_SYSCALLS() __builtin_expect(audit_syscalls,0)
#define AUDIT_AUDITING(x) __builtin_expect(NULL != (x),0)
#define AUDIT_ARG(op,args...) do { if (AUDIT_SYSCALLS()) {struct kaudit_record *__ar=AUDIT_RECORD(); if (AUDIT_AUDITING(__ar)) audit_arg_ ## op (__ar, ## args);}}while(0)
void audit_arg_upath(struct kaudit_record *,vnode_t,const char *,uint64_t);
int lookup_traverse_union(vnode_t,vnode_t *,vfs_context_t);
int vnode_isshadow(vnode_t);
errno_t vnode_makenamedstream(vnode_t,vnode_t *,const char *,int,vfs_context_t);
#define XATTR_RESOURCEFORK_NAME "com.apple.ResourceFork"
#define FSE_CREATE_FILE 0
#define FSE_ARG_VNODE 0x0001
#define FSE_ARG_DONE 0xb33f
int need_fsevent(int,vnode_t);
int add_fsevent(int,vfs_context_t,...);

/* Pinned resource_private.h, proc_internal.h and user.h long-path policy. */
#define P_VFS_IOPOLICY_SUPPORT_LONG_PATHS 0x1000
#define UT_SUPPORT_LONG_PATHS 0x00100000
#define IOPOL_VFS_SUPPORT_LONG_PATHS_DEFAULT 0
#define IOPOL_VFS_SUPPORT_LONG_PATHS_ON 1
#define SUPPORT_LONG_PATHS_ENTITLEMENT "com.apple.private.vfs.support-long-paths"
thread_t current_thread(void);
void *get_bsdthread_info(thread_t);
