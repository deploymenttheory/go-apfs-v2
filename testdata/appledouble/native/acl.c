// Independent macOS ACL oracle; never linked into the Go SDK.
#include <sys/acl.h>
#include <sys/kauth.h>
#include <sys/stat.h>
#include <copyfile.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
_Static_assert(offsetof(struct kauth_filesec, fsec_acl) == 36, "ACL header");
_Static_assert(sizeof(struct kauth_ace) == 24, "ACE size");
static char *load(const char *path) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    struct stat st; if (fstat(fileno(f), &st)) { fclose(f); return NULL; }
    char *p = calloc((size_t)st.st_size + 1, 1); if (!p) { fclose(f); return NULL; }
    if (fread(p, 1, (size_t)st.st_size, f) != (size_t)st.st_size) { free(p); fclose(f); return NULL; }
    fclose(f); return p;
}
static int save(const char *path, const void *p, size_t n) {
    FILE *f = fopen(path, "wb"); if (!f) return -1;
    int rc = fwrite(p, 1, n, f) == n ? 0 : -1;
    if (fclose(f)) rc = -1;
    return rc;
}
static int export_acl(acl_t acl, const char *binary, const char *text) {
    ssize_t n = acl_size(acl); if (n < 0) return -1;
    void *p = malloc((size_t)n); if (!p) return -1;
    ssize_t written = acl_copy_ext(p, acl, n);
    int rc = written < 0 ? -1 : save(binary, p, (size_t)written); free(p);
    if (rc) return rc;
    char *s = acl_to_text(acl, &n); if (!s) return -1;
    rc = save(text, s, (size_t)n); acl_free(s); return rc;
}
int main(int argc, char **argv) {
    if (argc < 4) return 2;
    int rc = -1; acl_t acl = NULL;
    if (!strcmp(argv[1], "parse") && argc == 5) {
        char *text = load(argv[2]); if (!text) { perror("read"); return 2; }
        acl = acl_from_text(text); free(text);
        if (acl) rc = export_acl(acl, argv[3], argv[4]);
    } else if (!strcmp(argv[1], "get") && argc == 5) {
        acl = acl_get_file(argv[2], ACL_TYPE_EXTENDED);
        if (acl) rc = export_acl(acl, argv[3], argv[4]);
    } else if (!strcmp(argv[1], "set") && argc == 4) {
        char *text = load(argv[2]); if (!text) { perror("read"); return 2; }
        acl = acl_from_text(text); free(text);
        if (acl) rc = acl_set_file(argv[3], ACL_TYPE_EXTENDED, acl);
    } else if (!strcmp(argv[1], "pack") && argc == 4) {
        rc = copyfile(argv[2], argv[3], NULL, COPYFILE_ACL | COPYFILE_XATTR | COPYFILE_PACK);
    } else return 2;
    int error = errno;
    if (acl) acl_free(acl);
    if (rc) { fprintf(stderr, "%s failed: errno=%d %s\n", argv[1], error, strerror(error)); return 1; }
    return 0;
}
