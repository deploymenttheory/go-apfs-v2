// Native metadata-copy and logical rewrite control. Test helper only.
#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void print_time(const char *name, struct timespec time) {
    printf("\"%s\":{\"Sec\":%lld,\"Nsec\":%ld}", name,
           (long long)time.tv_sec, time.tv_nsec);
}

static int replacement_compressed_oracle(const char *source, const char *target) {
    int from = open(source, O_RDONLY);
    if (from < 0) return 2;
    int to = open(target, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (to < 0) { close(from); return 3; }
    struct stat original, created, copied, rewritten;
    int result = fstat(from, &original);
    if (!result) result = fstat(to, &created);
    if (!result) result = fcopyfile(from, to, NULL, COPYFILE_SECURITY | COPYFILE_METADATA);
    if (!result) result = fstat(to, &copied);
    const char payload[] = "rewritten logical contents";
    if (!result && pwrite(to, payload, sizeof(payload)-1, 0) != sizeof(payload)-1) result = -1;
    if (!result && ftruncate(to, sizeof(payload)-1)) result = -1;
    if (!result) result = fstat(to, &rewritten);
    if (result) fprintf(stderr, "native metadata rewrite: %s\n", strerror(errno));
    int a = close(to), b = close(from);
    if (!result && !a && !b) {
        printf("{");
        print_time("source_modified", original.st_mtimespec);
        printf(","); print_time("created", created.st_birthtimespec);
        printf(","); print_time("copied_birth", copied.st_birthtimespec);
        printf(","); print_time("copied_modified", copied.st_mtimespec);
        printf(","); print_time("rewritten_birth", rewritten.st_birthtimespec);
        printf("}\n");
    }
    return result || a || b;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    return replacement_compressed_oracle(argv[1], argv[2]);
}
