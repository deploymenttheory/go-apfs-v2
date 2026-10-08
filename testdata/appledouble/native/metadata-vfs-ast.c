/* Research-only declarations. The included Apple bodies are verbatim.
 * Helpers have declarations only; this translation unit is never linked. */
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/xattr.h>
#include <sys/kauth.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#define CONFIG_MACF 1
#define NAMEDSTREAMS 1
#define DUAL_EAS 1
/* VISNAMEDSTREAM is represented symbolically; no layout/ABI claim is made. */
extern const unsigned int VISNAMEDSTREAM;
extern const int EJUSTRETURN;
typedef struct vnode { unsigned int v_flag; } *vnode_t;
typedef void *uio_t;
typedef void *vfs_context_t;
extern const int KAUTH_VNODE_READ_EXTATTRIBUTES;
extern const int KAUTH_VNODE_WRITE_EXTATTRIBUTES;
#define XATTR_VNODE_SUPPORTED(vp) metadata_vnode_supported(vp)
int metadata_vnode_supported(vnode_t);
int xattr_validatename(const char *);
int vnode_authorize(vnode_t, vnode_t, int, vfs_context_t);
off_t uio_offset(uio_t);
mount_t vnode_mount(vnode_t);
uint32_t vfs_flags(mount_t);
int VNOP_GETXATTR(vnode_t,const char *,uio_t,size_t *,int,vfs_context_t);
int VNOP_SETXATTR(vnode_t,const char *,uio_t,int,vfs_context_t);
int VNOP_REMOVEXATTR(vnode_t,const char *,int,vfs_context_t);
int VNOP_LISTXATTR(vnode_t,uio_t,size_t *,int,vfs_context_t);
int default_getxattr(vnode_t,const char *,uio_t,size_t *,int,vfs_context_t);
int default_setxattr(vnode_t,const char *,uio_t,int,vfs_context_t);
int default_removexattr(vnode_t,const char *,int,vfs_context_t);
int default_listxattr(vnode_t,uio_t,size_t *,int,vfs_context_t);
int mac_vnode_check_getextattr(vfs_context_t,vnode_t,const char *,uio_t);
int mac_vnode_check_setextattr(vfs_context_t,vnode_t,const char *,uio_t);
int mac_vnode_check_deleteextattr(vfs_context_t,vnode_t,const char *);
int mac_vnode_check_listextattr(vfs_context_t,vnode_t);
void mac_vnode_notify_setextattr(vfs_context_t,vnode_t,const char *,uio_t);
void mac_vnode_notify_deleteextattr(vfs_context_t,vnode_t,const char *);
void mac_vnode_label_update_extattr(mount_t,vnode_t,const char *);

#include "metadata-vfs-bodies.inc"
