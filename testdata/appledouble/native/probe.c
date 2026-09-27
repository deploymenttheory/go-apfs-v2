#include <copyfile.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
int main(int argc, char **argv) {
    if (argc < 4) return 2;
    int rc = 0;
    if (!strcmp(argv[1], "pack") || !strcmp(argv[1], "unpack")) {
        copyfile_flags_t flags = COPYFILE_XATTR | (!strcmp(argv[1], "pack") ? COPYFILE_PACK : COPYFILE_UNPACK);
        rc = copyfile(argv[2], argv[3], NULL, flags);
    } else if (argc == 5 && !strcmp(argv[1], "set")) {
        FILE *f = fopen(argv[4], "rb"); if (!f) { perror("open value"); return 1; }
        struct stat st; if (fstat(fileno(f), &st)) return 1;
        void *b = malloc(st.st_size ? (size_t)st.st_size : 1); if (!b) return 1;
        if (fread(b, 1, st.st_size, f) != (size_t)st.st_size) return 1;
        fclose(f); rc = setxattr(argv[2], argv[3], b, st.st_size, 0, 0); free(b);
    } else if (argc == 5 && !strcmp(argv[1], "get")) {
        ssize_t n = getxattr(argv[2], argv[3], NULL, 0, 0, 0); if (n < 0) { perror("get size"); return 1; }
        void *b = malloc(n ? (size_t)n : 1); if (!b) return 1;
        if (getxattr(argv[2], argv[3], b, n, 0, 0) != n) return 1;
        FILE *f = fopen(argv[4], "wb"); if (!f) return 1;
        if (fwrite(b, 1, n, f) != (size_t)n) return 1;
        rc = fclose(f); free(b);
    } else return 2;
    if (rc) { fprintf(stderr, "%s failed: errno=%d %s\n", argv[1], errno, strerror(errno)); return 1; }
    return 0;
}
