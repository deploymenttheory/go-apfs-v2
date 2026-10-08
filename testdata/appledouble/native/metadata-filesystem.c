/* Independent filesystem metadata oracle. Production never invokes this tool. */
#include <sys/types.h>
#include <copyfile.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/xattr.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *names[] = {"com.example.phase2", "com.apple.FinderInfo", "com.apple.ResourceFork"};
static const unsigned char plain[] = "native-value";
static const unsigned char changed[] = "changed-value";

static void hex(const void *data, size_t n) {
    const unsigned char *p = data;
    putchar('"');
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    putchar('"');
}

/* Query size and content separately, preserving errors from each actual call. */
static void observe(const char *path, int fd, int held) {
    unsigned char buf[65536];
    printf("{\"attributes\":[");
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
        if (i) putchar(',');
        errno = 0;
        ssize_t size = held ? fgetxattr(fd, names[i], NULL, 0, 0, 0)
                            : getxattr(path, names[i], NULL, 0, 0, XATTR_NOFOLLOW);
        int size_error = size < 0 ? errno : 0;
        errno = 0;
        ssize_t n = held ? fgetxattr(fd, names[i], buf, sizeof(buf), 0, 0)
                         : getxattr(path, names[i], buf, sizeof(buf), 0, XATTR_NOFOLLOW);
        int read_error = n < 0 ? errno : 0;
        printf("{\"name\":\"%s\",\"size\":%zd,\"size_errno\":%d,\"read\":%zd,\"read_errno\":%d,\"bytes\":", names[i], size, size_error, n, read_error);
        hex(buf, n < 0 ? 0 : (size_t)n);
        putchar('}');
    }
    errno = 0;
    ssize_t n = held ? flistxattr(fd, (char *)buf, sizeof(buf), 0)
                     : listxattr(path, (char *)buf, sizeof(buf), XATTR_NOFOLLOW);
    int error = n < 0 ? errno : 0;
    printf("],\"list_result\":%zd,\"list_errno\":%d,\"list_bytes\":", n, error);
    hex(buf, n < 0 ? 0 : (size_t)n);
    putchar('}');
}

static int install(const char *path, int different) {
    unsigned char finder[32] = {0};
    memcpy(finder, different ? "DIFF" : "TEST", 4);
    const unsigned char *p = different ? changed : plain;
    size_t n = different ? sizeof(changed)-1 : sizeof(plain)-1;
    printf("{\"setup\":[");
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
        if (i) putchar(',');
        const void *value = i == 1 ? (const void *)finder : (const void *)p;
        size_t length = i == 1 ? sizeof(finder) : n;
        errno = 0;
        int result = setxattr(path, names[i], value, length, 0, XATTR_NOFOLLOW);
        printf("{\"name\":\"%s\",\"result\":%d,\"errno\":%d}", names[i], result, result < 0 ? errno : 0);
    }
    printf("]}\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: oracle path action\n"); return 2; }
    const char *path = argv[1], *action = argv[2];
    if (!strcmp(action, "pack")) {
        char *destination = NULL;
        if (asprintf(&destination, "%s.packed", path) < 0) return 1;
        int result = copyfile(path, destination, NULL, COPYFILE_PACK | COPYFILE_ALL);
        if (result != 0) perror("copyfile pack");
        free(destination);
        return result != 0;
    }
    if (!strcmp(action, "seed")) return install(path, 0);
    if (!strcmp(action, "seed-different")) return install(path, 1);
    struct statfs volume;
    if (statfs(path, &volume) != 0) { perror("statfs"); return 1; }
    if (!strcmp(action, "mount")) {
        struct stat root;
        if (lstat(path, &root) != 0) { perror("lstat mount"); return 1; }
        printf("{\"filesystem\":\"%s\",\"volume_flags\":%u,\"mount_owner\":%u,"
               "\"uid\":%u,\"euid\":%u,\"gid\":%u,\"egid\":%u,"
               "\"root_uid\":%u,\"root_gid\":%u,\"root_mode\":%u}\n",
               volume.f_fstypename, volume.f_flags, (unsigned)volume.f_owner,
               (unsigned)getuid(), (unsigned)geteuid(), (unsigned)getgid(), (unsigned)getegid(),
               (unsigned)root.st_uid, (unsigned)root.st_gid, (unsigned)(root.st_mode & 07777));
        return 0;
    }
    errno = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    int open_error = fd < 0 ? errno : 0;
    printf("{\"filesystem\":\"%s\",\"volume_flags\":%u,\"open_errno\":%d,\"before_path\":", volume.f_fstypename, volume.f_flags, open_error);
    observe(path, fd, 0);
    printf(",\"before_held\":");
    if (fd >= 0) observe(path, fd, 1); else printf("null");
    errno = 0;
    int result = 0;
    if (!strcmp(action, "set")) result = setxattr(path, names[0], changed, sizeof(changed)-1, 0, XATTR_NOFOLLOW);
    else if (!strcmp(action, "create")) result = setxattr(path, names[0], changed, sizeof(changed)-1, 0, XATTR_NOFOLLOW | XATTR_CREATE);
    else if (!strcmp(action, "replace")) result = setxattr(path, names[0], changed, sizeof(changed)-1, 0, XATTR_NOFOLLOW | XATTR_REPLACE);
    else if (!strcmp(action, "empty-plain")) result = setxattr(path, names[0], "", 0, 0, XATTR_NOFOLLOW);
    else if (!strcmp(action, "set-fork")) result = setxattr(path, names[2], changed, sizeof(changed)-1, 0, XATTR_NOFOLLOW);
    else if (!strcmp(action, "create-fork")) result = setxattr(path, names[2], changed, sizeof(changed)-1, 0, XATTR_NOFOLLOW | XATTR_CREATE);
    else if (!strcmp(action, "replace-fork")) result = setxattr(path, names[2], changed, sizeof(changed)-1, 0, XATTR_NOFOLLOW | XATTR_REPLACE);
    else if (!strcmp(action, "remove")) result = removexattr(path, names[0], XATTR_NOFOLLOW);
    else if (!strcmp(action, "remove-fork")) result = removexattr(path, names[2], XATTR_NOFOLLOW);
    else if (!strcmp(action, "remove-finder")) result = removexattr(path, names[1], XATTR_NOFOLLOW);
    else if (!strcmp(action, "zero-finder")) {
        unsigned char zero[32] = {0};
        result = setxattr(path, names[1], zero, sizeof(zero), 0, XATTR_NOFOLLOW);
    } else if (strcmp(action, "read")) { fprintf(stderr, "unknown action\n"); return 2; }
    int error = result < 0 ? errno : 0;
    printf(",\"result\":%d,\"errno\":%d,\"after_path\":", result, error);
    observe(path, fd, 0);
    printf(",\"after_held\":");
    if (fd >= 0) observe(path, fd, 1); else printf("null");
    errno = 0;
    int closed = fd >= 0 ? close(fd) : 0;
    int close_error = closed < 0 ? errno : 0;
    printf(",\"close_errno\":%d}\n", close_error);
    return 0;
}
