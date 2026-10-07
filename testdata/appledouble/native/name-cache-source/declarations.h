/* Declaration-only research supplement. Constants originate in the pinned
 * vnode_internal.h and mount_internal.h; these are not runtime ABI layouts. */
extern unsigned int crc32tab[256];
extern int nc_smr_enabled;
#define VL_DRAIN 0x0002
#define VL_TERMINATE 0x0004
#define VMOUNTEDHERE 0x40000000
#define MNTK_AUTH_CACHE_TTL 0x00008000
#define MNTK_AUTH_OPAQUE 0x20000000
#define VISHARDLINK 0x100000
#define VFMLINKTARGET 0x20000000
extern uint32_t mount_generation;
void vfs_smr_enter(void);
void vfs_smr_leave(void);
void name_cache_lock_shared(void);
void name_cache_unlock(void);
#define NAME_CACHE_LOCK_SHARED() name_cache_lock_shared()
#define NAME_CACHE_UNLOCK() name_cache_unlock()
kauth_cred_t vnode_cred(vnode_t);
int vfs_context_issuser(vfs_context_t);
boolean_t cache_check_vnode_issubdir(vnode_t,vnode_t,int *,vnode_t *);
vnode_t cache_lookup_smr(vnode_t,struct componentname *,uint32_t *);
vnode_t cache_lookup_locked(vnode_t,struct componentname *,uint32_t *);
bool vnode_hold_smr(vnode_t);
int vnode_getwithvid_drainok(vnode_t,uint32_t);
#include <sys/paths.h>
#define MNTK_NAMED_STREAMS 0x00040000
int vnode_trigger_resolve(vnode_t,struct nameidata *,vfs_context_t);
