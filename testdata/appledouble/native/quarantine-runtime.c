// Native research only. Changes quarantine state solely in this short-lived
// helper process; it never targets another process or changes system policy.
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static void *(*file_alloc)(void);
static void (*file_free)(void *);
static int (*file_capture)(void *, int);
static int (*file_export)(void *, char *, size_t *);
static void *(*proc_alloc)(void);
static void (*proc_free)(void *);
static int (*proc_capture)(void *);
static int (*proc_export)(void *, char *, size_t *);

static void fail(const char *operation) {
    fprintf(stderr, "%s: errno=%d %s\n", operation, errno, strerror(errno));
    exit(2);
}
static void hex(const void *data, size_t length) {
    const unsigned char *bytes = data;
    putchar('"');
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
    putchar('"');
}
static char *load(const char *path, size_t *length) {
    FILE *f = fopen(path, "rb");
    if (!f) fail("open input");
    struct stat st;
    if (fstat(fileno(f), &st) || st.st_size < 0 || st.st_size > 4096) fail("input size");
    *length = (size_t)st.st_size;
    char *data = calloc(*length + 1, 1);
    if (!data || fread(data, 1, *length, f) != *length) fail("read input");
    if (fclose(f)) fail("close input");
    return data;
}
static void snapshot(void) {
    void *p = proc_alloc();
    if (!p) fail("allocate process capture");
    errno = 0;
    int code = proc_capture(p), saved = errno;
    char data[4096]; size_t length = sizeof data;
    int serialized = proc_export(p, data, &length);
    if (serialized || length > sizeof data) fail("serialize process capture");
    printf("{\"InitCode\":%d,\"InitErrno\":%d,\"Serialized\":", code, saved);
    hex(data, length); putchar('}');
    proc_free(p);
}
static void xattr(int fd) {
    unsigned char data[4096];
    errno = 0;
    ssize_t length = fgetxattr(fd, "com.apple.quarantine", data, sizeof data, 0, 0);
    int saved = errno;
    if (length < 0 && saved != ENOATTR) fail("read destination quarantine");
    struct stat st;
    if (fstat(fd, &st)) fail("stat destination");
    printf("{\"Present\":%s,\"Errno\":%d,\"Bytes\":", length >= 0 ? "true" : "false", saved);
    hex(data, length < 0 ? 0 : (size_t)length);
    printf(",\"Envelope\":");
    if (length >= 0) {
        void *q = file_alloc(); if (!q) fail("allocate readback import");
        if (file_capture(q, fd)) fail("import readback");
        char envelope[4096]; size_t n = sizeof envelope;
        if (file_export(q, envelope, &n) || n > sizeof envelope) fail("export readback");
        hex(envelope, n); file_free(q);
    } else hex("", 0);
    putchar('}');
}
static int baseline_code, baseline_errno;
static int destination(const char *path, int directory, const char *baseline) {
    if (directory && mkdir(path, 0700)) fail("create directory");
    int fd = open(path, directory ? O_RDONLY : O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) fail("create destination");
    if (strcmp(baseline, "-")) {
        size_t length; char *data = load(baseline, &length);
        errno = 0;
        baseline_code = fsetxattr(fd, "com.apple.quarantine", data, length, 0, 0);
        baseline_errno = errno;
        free(data);
    }
    return fd;
}
int main(int argc, char **argv) {
    // process input or -, destination, file envelope, kind, creation order, baseline or -
    if (argc != 7) return 2;
    int directory = !strcmp(argv[4], "directory"), before = !strcmp(argv[5], "before");
    if ((!directory && strcmp(argv[4], "file")) || (!before && strcmp(argv[5], "after"))) return 2;
    void *library = dlopen("/usr/lib/system/libquarantine.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!library) fail("load libquarantine");
    proc_alloc = dlsym(library, "_qtn_proc_alloc");
    proc_free = dlsym(library, "_qtn_proc_free");
    proc_capture = dlsym(library, "_qtn_proc_init_with_self");
    proc_export = dlsym(library, "_qtn_proc_to_data");
    int (*proc_import)(void *, const void *, size_t) = dlsym(library, "_qtn_proc_init_with_data");
    int (*proc_apply)(void *) = dlsym(library, "_qtn_proc_apply_to_self");
    file_alloc = dlsym(library, "_qtn_file_alloc");
    file_free = dlsym(library, "_qtn_file_free");
    file_capture = dlsym(library, "_qtn_file_init_with_fd");
    file_export = dlsym(library, "_qtn_file_to_data");
    int (*file_import)(void *, const void *, size_t) = dlsym(library, "_qtn_file_init_with_data");
    int (*file_apply)(void *, int) = dlsym(library, "_qtn_file_apply_to_fd");
    if (!proc_alloc || !proc_free || !proc_capture || !proc_export || !proc_import || !proc_apply ||
        !file_alloc || !file_free || !file_capture || !file_export || !file_import || !file_apply) fail("required exports");
    printf("{\"Start\":%lld,\"UID\":%u,\"EUID\":%u,\"Before\":", (long long)time(NULL), getuid(), geteuid());
    snapshot();
    int fd = before ? destination(argv[2], directory, argv[6]) : -1;
    printf(",\"Requested\":");
    if (strcmp(argv[1], "-")) {
        size_t length; char *data = load(argv[1], &length);
        // qtn_proc_init_with_data takes a counted text buffer, excluding NUL.
        // Fixtures use canonical, NUL-free input; do not reuse the file ABI here.
        if (memchr(data, 0, length)) fail("NUL in process request");
        void *p = proc_alloc(); if (!p) fail("allocate process request");
        int rc = proc_import(p, data, length); free(data);
        if (rc) fail("parse process request");
        char serialized[4096]; size_t n = sizeof serialized;
        if (proc_export(p, serialized, &n) || n > sizeof serialized) fail("export process request");
        hex(serialized, n);
        errno = 0; rc = proc_apply(p); int saved = errno;
        printf(",\"ProcessApplyCode\":%d,\"ProcessApplyErrno\":%d", rc, saved);
        proc_free(p);
    } else printf("null,\"ProcessApplyCode\":0,\"ProcessApplyErrno\":0");
    printf(",\"Effective\":"); snapshot();
    if (!before) fd = destination(argv[2], directory, argv[6]);
    printf(",\"BaselineSetCode\":%d,\"BaselineSetErrno\":%d,\"Prepared\":", baseline_code, baseline_errno); xattr(fd);
    size_t length; char *data = load(argv[3], &length);
    void *q = file_alloc(); if (!q) fail("allocate file quarantine");
    int rc = file_import(q, data, length); free(data);
    if (rc) fail("parse file envelope");
    errno = 0; rc = file_apply(q, fd); int saved = errno;
    printf(",\"FileApplyCode\":%d,\"FileApplyErrno\":%d,\"Applied\":", rc, saved);
    xattr(fd);
    printf(",\"End\":%lld}\n", (long long)time(NULL));
    file_free(q); if (close(fd)) fail("close destination");
    dlclose(library); return 0;
}
