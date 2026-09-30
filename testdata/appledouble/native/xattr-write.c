// Qualification only: direct libSystem calls, independent of the Go adapter.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 6) return 2;
    size_t n = strlen(argv[5]);
    if (n % 2 || n > 262144) return 3;
    unsigned char value[131072], readback[131072];
    for (size_t i = 0; i < n / 2; i++) {
        unsigned int b;
        if (sscanf(argv[5] + 2 * i, "%2x", &b) != 1) return 4;
        value[i] = (unsigned char)b;
    }
    int fd = open(argv[2], O_RDONLY | (!strcmp(argv[3], "link") ? O_SYMLINK : 0));
    if (fd < 0) return 5;
    int write_error = 0;
    if (!strcmp(argv[1], "set") && fsetxattr(fd, argv[4], value, n / 2, 0, 0) < 0) write_error = errno;
    ssize_t size = fgetxattr(fd, argv[4], readback, sizeof(readback), 0, 0);
    int read_error = size < 0 ? errno : 0;
    printf("{\"WriteError\":%d,\"ReadError\":%d,\"Size\":%zd,\"ValueHex\":\"", write_error, read_error, size);
    for (ssize_t i = 0; i < size; i++) printf("%02x", readback[i]);
    puts("\"}");
    close(fd);
    return 0;
}
