// Test-only enumeration: retain every attribute restored by native copyfile.
#include <sys/xattr.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    ssize_t n = listxattr(argv[1], NULL, 0, 0);
    if (n < 0) { perror("list size"); return 1; }
    char *b = malloc(n ? (size_t)n : 1);
    if (!b) return 1;
    ssize_t actual = listxattr(argv[1], b, (size_t)n, 0);
    if (actual < 0) { perror("list"); free(b); return 1; }
    FILE *f = fopen(argv[2], "wb");
    if (!f) { free(b); return 1; }
    int failed = fwrite(b, 1, (size_t)actual, f) != (size_t)actual;
    free(b);
    return fclose(f) != 0 || failed;
}
