// Native metadata-copy and logical rewrite control. Test helper only.
#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int replacement_compressed_oracle(const char *source, const char *target) {
    int from = open(source, O_RDONLY);
    if (from < 0) return 2;
    int to = open(target, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (to < 0) { close(from); return 3; }
    int result = fcopyfile(from, to, NULL, COPYFILE_SECURITY | COPYFILE_METADATA);
    const char payload[] = "rewritten logical contents";
    if (!result && pwrite(to, payload, sizeof(payload)-1, 0) != sizeof(payload)-1) result = -1;
    if (!result && ftruncate(to, sizeof(payload)-1)) result = -1;
    if (result) fprintf(stderr, "native metadata rewrite: %s\n", strerror(errno));
    int a = close(to), b = close(from);
    return result || a || b;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    return replacement_compressed_oracle(argv[1], argv[2]);
}
