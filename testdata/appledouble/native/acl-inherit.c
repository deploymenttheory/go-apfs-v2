// Independent creation/unpack oracle. Never linked into the Go library.
#include <sys/acl.h>
#include <sys/kauth.h>
#include <sys/stat.h>
#include <copyfile.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(offsetof(struct kauth_filesec, fsec_acl) == 36, "ACL header");
_Static_assert(sizeof(struct kauth_ace) == 24, "ACE size");
static void fail(const char *what) { perror(what); exit(2); }
static acl_t load(const char *path) {
    FILE *f = fopen(path, "rb"); if (!f) fail("input");
    struct stat st; if (fstat(fileno(f), &st)) fail("input stat");
    char *p = calloc((size_t)st.st_size + 1, 1); if (!p) fail("allocate");
    if (fread(p, 1, (size_t)st.st_size, f) != (size_t)st.st_size) fail("input read");
    if (fclose(f)) fail("input close");
    acl_t acl = acl_from_text(p); free(p); if (!acl) fail("parse ACL");
    return acl;
}
static void print_acl(const char *path) {
    errno = 0; acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
    if (!acl) {
        int e = errno; struct stat st;
        if (e != ENOENT || lstat(path, &st)) fail("read ACL");
        printf("null"); return;
    }
    ssize_t n = acl_size(acl); if (n < 0) fail("ACL size");
    unsigned char *p = malloc((size_t)n); if (!p) fail("ACL allocate");
    n = acl_copy_ext(p, acl, n); if (n < 0) fail("ACL export");
    printf("\""); for (ssize_t i = 0; i < n; i++) printf("%02x", p[i]); printf("\"");
    free(p); acl_free(acl);
}
int main(int argc, char **argv) {
    if (argc != 6) return 2;
    char parent[4096], child[4096];
    if (snprintf(parent, sizeof(parent), "%s/parent", argv[1]) >= (int)sizeof(parent) ||
        snprintf(child, sizeof(child), "%s/child", parent) >= (int)sizeof(child)) return 2;
    umask(0);
    if (mkdir(parent, 0700)) fail("parent create");
    acl_t acl = load(argv[2]);
    if (acl_set_file(parent, ACL_TYPE_EXTENDED, acl)) fail("parent ACL");
    acl_free(acl);
    printf("{\"Parent\":"); print_acl(parent);
    filesec_t sec = filesec_init(); if (!sec) fail("filesec");
    mode_t mode = 0700;
    if (filesec_set_property(sec, FILESEC_MODE, &mode)) fail("mode");
    acl = NULL;
    if (strcmp(argv[3], "-")) {
        acl = load(argv[3]);
        if (filesec_set_property(sec, FILESEC_ACL, &acl)) fail("initial ACL");
    }
    errno = 0; int rc;
    if (!strcmp(argv[4], "directory")) rc = mkdirx_np(child, sec);
    else if (!strcmp(argv[4], "file")) {
        int fd = openx_np(child, O_CREAT | O_EXCL | O_RDWR, sec);
        rc = fd < 0 ? -1 : 0;
        if (fd >= 0 && close(fd)) fail("child close");
    } else return 2;
    int error = rc ? errno : 0;
    filesec_free(sec); if (acl) acl_free(acl);
    printf(",\"CreateCode\":%d,\"CreateErrno\":%d", rc, error);
    if (rc) {
        struct stat st;
        if (lstat(child, &st) == 0 || errno != ENOENT) fail("failed creation left child");
        printf("}\n"); return 0;
    }
    struct stat before, after;
    if (lstat(child, &before)) fail("before stat");
    printf(",\"Created\":"); print_acl(child);
    if (strcmp(argv[5], "-")) {
        errno = 0;
        rc = copyfile(argv[5], child, NULL, COPYFILE_UNPACK);
        error = rc ? errno : 0;
        printf(",\"UnpackCode\":%d,\"UnpackErrno\":%d,\"Restored\":", rc, error);
        print_acl(child);
    }
    if (lstat(child, &after)) fail("after stat");
    if (before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_mode != after.st_mode || before.st_uid != after.st_uid ||
        before.st_gid != after.st_gid || before.st_flags != after.st_flags ||
        before.st_size != after.st_size) fail("unrelated destination metadata changed");
    printf(",\"DestinationUnchanged\":true,\"ParentAfter\":"); print_acl(parent);
    printf("}\n"); return 0;
}
