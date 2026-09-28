// Independent copyfile/application oracle. No production Go code links this helper.
#include <copyfile.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static void *(*allocate)(void);
static void (*release)(void *);
static int (*initialize)(void *, const void *, size_t);
static int (*apply)(void *, int);
static void *load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("open envelope"); exit(2); }
    struct stat st;
    if (fstat(fileno(f), &st) || st.st_size < 0) { perror("stat envelope"); exit(2); }
    size_t n = (size_t)st.st_size;
    char *b = calloc(n + 1, 1);
    if (!b || fread(b, 1, n, f) != n) { fprintf(stderr, "read envelope\n"); exit(2); }
    fclose(f);
    void *q = allocate();
    if (!q) { fprintf(stderr, "allocate quarantine\n"); exit(2); }
    int rc = initialize(q, b, n); free(b);
    if (rc) { fprintf(stderr, "initialize envelope: %d\n", rc); exit(2); }
    return q;
}
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    void *library = dlopen("/usr/lib/system/libquarantine.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    allocate = dlsym(library, "_qtn_file_alloc");
    release = dlsym(library, "_qtn_file_free");
    initialize = dlsym(library, "_qtn_file_init_with_data");
    apply = dlsym(library, "_qtn_file_apply_to_fd");
    if (!allocate || !release || !initialize || !apply) { fprintf(stderr, "missing quarantine exports\n"); return 2; }
    if (!strcmp(argv[1], "unpack")) {
        if (argc != 5) return 2;
        copyfile_state_t state = copyfile_state_alloc();
        if (!state) return 2;
        void *q = NULL;
        if (strcmp(argv[4], "-")) {
            q = load(argv[4]);
            if (copyfile_state_set(state, COPYFILE_STATE_QUARANTINE, &q)) { perror("set state"); return 2; }
        }
        int rc = copyfile(argv[2], argv[3], state, COPYFILE_XATTR | COPYFILE_UNPACK);
        int saved = errno;
        if (q) release(q);
        copyfile_state_free(state);
        if (rc) { fprintf(stderr, "unpack failed: errno=%d %s\n", saved, strerror(saved)); return 1; }
    } else if (!strcmp(argv[1], "apply")) {
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) { perror("open destination"); return 2; }
        for (int i = 3; i < argc; i++) {
            void *q = load(argv[i]);
            int rc = apply(q, fd); int saved = errno; release(q);
            if (rc) { fprintf(stderr, "apply failed: code=%d errno=%d %s\n", rc, saved, strerror(saved)); close(fd); return 1; }
        }
        close(fd);
    } else return 2;
    dlclose(library);
    return 0;
}
