// Qualification only. Check public declarations from the selected host SDK;
// private signatures remain qualified by the independent existing C observers.
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/unistd.h>
#include <pwd.h>
#include <grp.h>
#include <membership.h>
#include <stddef.h>
#define SIGNATURE(name, result, ...) \
 _Static_assert(__builtin_types_compatible_p(__typeof__(&name), result (*)(__VA_ARGS__)), #name " signature")
SIGNATURE(fcntl, int, int, int, ...);
_Static_assert(MAXPATHLEN == 1024, "F_GETPATH output capacity");
SIGNATURE(listxattr, ssize_t, const char *, char *, size_t, int);
SIGNATURE(flistxattr, ssize_t, int, char *, size_t, int);
SIGNATURE(getxattr, ssize_t, const char *, const char *, void *, size_t, u_int32_t, int);
SIGNATURE(fgetxattr, ssize_t, int, const char *, void *, size_t, u_int32_t, int);
SIGNATURE(filesec_init, filesec_t, void);
SIGNATURE(filesec_free, void, filesec_t);
SIGNATURE(filesec_get_property, int, filesec_t, filesec_property_t, void *);
SIGNATURE(fstatx_np, int, int, struct stat *, filesec_t);
SIGNATURE(statx_np, int, const char *, struct stat *, filesec_t);
SIGNATURE(lstatx_np, int, const char *, struct stat *, filesec_t);
SIGNATURE(getattrlistat, int, int, const char *, void *, void *, size_t, unsigned long);
SIGNATURE(fgetattrlist, int, int, void *, void *, size_t, unsigned int);
_Static_assert(sizeof(vol_capabilities_attr_t) == 32 && offsetof(vol_capabilities_attr_t, valid) == 16, "volume capability layout");
_Static_assert(VOL_CAPABILITIES_INTERFACES == 1 && VOL_CAP_INT_EXTENDED_SECURITY == 0x400, "volume ACL capability");
SIGNATURE(fsetattrlist, int, int, void *, void *, size_t, unsigned int);
SIGNATURE(ffsctl, int, int, unsigned long, void *, unsigned int);
SIGNATURE(getpwuid_r, int, uid_t, struct passwd *, char *, size_t, struct passwd **);
SIGNATURE(getpwnam_r, int, const char *, struct passwd *, char *, size_t, struct passwd **);
SIGNATURE(getgrgid_r, int, gid_t, struct group *, char *, size_t, struct group **);
SIGNATURE(getgrnam_r, int, const char *, struct group *, char *, size_t, struct group **);
SIGNATURE(mbr_uid_to_uuid, int, uid_t, uuid_t);
SIGNATURE(mbr_gid_to_uuid, int, gid_t, uuid_t);
SIGNATURE(mbr_uuid_to_id, int, const uuid_t, id_t *, int *);
_Static_assert(sizeof(ssize_t)==8 && sizeof(size_t)==8 && sizeof(void *)==8,"64-bit return/argument widths");
_Static_assert(sizeof(int)==4 && sizeof(uid_t)==4 && sizeof(gid_t)==4,"32-bit argument widths");
_Static_assert(sizeof(struct passwd)==72 && offsetof(struct passwd,pw_uid)==16 && offsetof(struct passwd,pw_change)==24 && offsetof(struct passwd,pw_expire)==64,"passwd layout");
_Static_assert(sizeof(struct group)==32 && offsetof(struct group,gr_gid)==16 && offsetof(struct group,gr_mem)==24,"group layout");
_Static_assert(sizeof(struct stat)==144 && offsetof(struct stat,st_ino)==8,"stat64 layout");
_Static_assert(sizeof(struct attrlist)==24,"attrlist layout");

// Private signature also used by the existing path/copyfile native observer.
extern int __open_dprotected_np(const char *, int, int, int, int);
#ifdef DARWIN_WRAPPERS_ORACLE
#include <errno.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int fd = __open_dprotected_np(argv[1], O_RDONLY, -1, 0, 0);
    int saved = fd < 0 ? errno : 0;
    if (fd >= 0 && close(fd) != 0) return 3;
    printf("{\"success\":%s,\"errno\":%d}\n", fd >= 0 ? "true" : "false", saved);
    return 0;
}
#endif
