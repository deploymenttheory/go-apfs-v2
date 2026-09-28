// Independent filesystem-xattr import and process-context oracle, test-only.
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    void *lib = dlopen("/usr/lib/system/libquarantine.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    void *(*alloc)(void) = dlsym(lib, "_qtn_file_alloc");
    void (*release)(void *) = dlsym(lib, "_qtn_file_free");
    int (*init)(void *, int) = dlsym(lib, "_qtn_file_init_with_fd");
    int (*serialize)(void *, char *, size_t *) = dlsym(lib, "_qtn_file_to_data");
    void *(*proc_alloc)(void) = dlsym(lib, "_qtn_proc_alloc");
    void (*proc_free)(void *) = dlsym(lib, "_qtn_proc_free");
    int (*proc_init)(void *) = dlsym(lib, "_qtn_proc_init_with_self");
    uint32_t (*proc_flags)(void *) = dlsym(lib, "_qtn_proc_get_flags");
    int (*proc_data)(void *, char *, size_t *) = dlsym(lib, "_qtn_proc_to_data");
    if (!alloc || !release || !init || !serialize || !proc_alloc || !proc_free || !proc_init || !proc_data || !proc_flags) { fprintf(stderr, "missing exports\n"); return 2; }
    void *p = proc_alloc();
    char context[4096] = {0}; size_t count = sizeof(context);
if (!p) { fprintf(stderr, "allocate process context\n"); return 2; }
    errno = 0; int init_rc = proc_init(p); int init_errno = errno;
    uint32_t context_flags = proc_flags(p);
    errno = 0; int data_rc = proc_data(p, context, &count); int data_errno = errno;
    // A missing/unserializable context is an observation, never proof of an
    // unquarantined process. Preserve both native statuses independently.
    if (data_rc) context[0] = 0;
    fprintf(stderr, "process: init=%d errno=%d flags=%08x serialize=%d errno=%d data=%s\n", init_rc, init_errno, context_flags, data_rc, data_errno, context);
    proc_free(p);
    FILE *input = fopen(argv[1], "rb"); struct stat st;
    if (!input || fstat(fileno(input), &st) || st.st_size < 0) { fprintf(stderr, "input setup\n"); return 2; }
    size_t length = (size_t)st.st_size; char *b = calloc(length + 1, 1);
    if (!b || fread(b, 1, length, input) != length) { fprintf(stderr, "read input\n"); return 2; }
    fclose(input);
    FILE *target = fopen(argv[3], "w+b");
    if (!target || fsetxattr(fileno(target), "com.apple.quarantine", b, length, 0, 0)) { perror("set xattr"); return 2; }
ssize_t size = fgetxattr(fileno(target), "com.apple.quarantine", NULL, 0, 0, 0);
    char *actual = calloc(length + 1, 1);
    if (!actual || size != (ssize_t)length || fgetxattr(fileno(target), "com.apple.quarantine", actual, length, 0, 0) != size || memcmp(actual, b, length)) { fprintf(stderr, "xattr setup readback differs\n"); return 2; }
    free(actual);
    free(b);
    // Verify exact setup bytes in the Go harness by retaining the source file.
    void *q = alloc(); if (!q) return 2;
    int rc = init(q, fileno(target)); fclose(target);
    if (rc) { fprintf(stderr, "import refused: code=%d\n", rc); release(q); return 1; }
    size_t capacity = 1024 * 1024; char *out = malloc(capacity); if (!out) return 2;
    rc = serialize(q, out, &capacity);
    if (rc) { fprintf(stderr, "serialize failed: code=%d\n", rc); return 2; }
    FILE *output = fopen(argv[2], "wb"); if (!output) return 2;
    int failed = fwrite(out, 1, capacity, output) != capacity;
    if (fclose(output)) failed = 1;
    free(out); release(q); dlclose(lib);
    return failed ? 2 : 0;
}
