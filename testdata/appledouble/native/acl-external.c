// Independent acl_copy_int / acl_to_text oracle; never linked into the SDK.
#include <sys/acl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
static int save(const char *path, const void *p, size_t n) {
    FILE *f = fopen(path, "wb"); if (!f) return -1;
    int rc = fwrite(p, 1, n, f) == n ? 0 : -1;
    if (fclose(f)) rc = -1;
    return rc;
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    FILE *f = fopen(argv[1], "rb"); if (!f) return 2;
    struct stat st; if (fstat(fileno(f), &st) || st.st_size < 44) { fclose(f); return 2; }
    size_t size = (size_t)st.st_size;
    unsigned char *p = malloc(size); if (!p) { fclose(f); return 2; }
    if (fread(p, 1, size, f) != size) { free(p); fclose(f); return 2; }
    fclose(f);
    uint32_t count; memcpy(&count, p + 36, 4); count = ntohl(count);
    // acl_copy_int has no input-length argument. Never ask it to overread.
    if (count <= 128 && size < 44 + 24 * count) { free(p); return 2; }
    acl_t acl = acl_copy_int(p); free(p);
    if (!acl) { fprintf(stderr, "import failed: errno=%d %s\n", errno, strerror(errno)); return 1; }
    ssize_t n = acl_size(acl);
    void *binary = n < 0 ? NULL : malloc((size_t)n);
    if (!binary || acl_copy_ext(binary, acl, n) < 0 || save(argv[2], binary, (size_t)n)) { free(binary); acl_free(acl); return 2; }
    free(binary);
    char *text = acl_to_text(acl, &n);
    if (!text || save(argv[3], text, (size_t)n)) { acl_free(text); acl_free(acl); return 2; }
    acl_free(text); acl_free(acl); return 0;
}
