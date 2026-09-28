// Independent native quarantine oracle. Private symbols are used only by this
// research helper; the Go SDK never loads or links libquarantine.
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    void *library = dlopen("/usr/lib/system/libquarantine.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    void *(*allocate)(void) = dlsym(library, "_qtn_file_alloc");
    void (*release)(void *) = dlsym(library, "_qtn_file_free");
    int (*initialize)(void *, const void *, size_t) = dlsym(library, "_qtn_file_init_with_data");
    int (*serialize)(void *, char *, size_t *) = dlsym(library, "_qtn_file_to_data");
    uint32_t (*flags)(void *) = dlsym(library, "_qtn_file_get_flags");
    const char *(*error_string)(int) = dlsym(library, "_qtn_error");
    if (!allocate || !release || !initialize || !serialize || !flags || !error_string) { fprintf(stderr, "symbols alloc=%p free=%p init=%p serialize=%p flags=%p error=%p: %s\n", allocate, release, initialize, serialize, flags, error_string, dlerror()); return 2; }
    FILE *f = fopen(argv[1], "rb"); if (!f) return 2;
    struct stat st; if (fstat(fileno(f), &st) || st.st_size < 0) { fclose(f); return 2; }
    size_t length = (size_t)st.st_size;
    char *input = calloc(length + 1, 1); if (!input) { fclose(f); return 2; }
    if (fread(input, 1, length, f) != length) { free(input); fclose(f); return 2; }
    fclose(f);
    void *q = allocate(); if (!q) { free(input); return 2; }
    int rc = initialize(q, input, length); free(input);
    if (rc) { fprintf(stderr, "parse refused: code=%d %s\n", rc, error_string(rc)); release(q); return 1; }
    size_t capacity = 1024 * 1024;
    char *output = malloc(capacity); if (!output) { release(q); return 2; }
    rc = serialize(q, output, &capacity);
    if (rc) { fprintf(stderr, "serialize failed: code=%d %s\n", rc, error_string(rc)); free(output); release(q); return 2; }
    printf("flags=%08x bytes=%zu\n", flags(q), capacity);
    f = fopen(argv[2], "wb"); if (!f) { free(output); release(q); return 2; }
    int failed = fwrite(output, 1, capacity, f) != capacity;
    if (fclose(f)) failed = 1;
    free(output); release(q); dlclose(library); return failed ? 2 : 0;
}
