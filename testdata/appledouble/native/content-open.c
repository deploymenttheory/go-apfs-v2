/* Native reference for held, no-follow regular-file content acquisition. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int parent = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent < 0) return 3;
    int fd = openat(parent, argv[2], O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    int error = fd < 0 ? errno : 0;
    close(parent);
    int type = 0;
    unsigned char data[64];
    ssize_t count = 0;
    if (!error) {
        struct stat st;
        if (fstat(fd, &st) < 0) error = errno;
        else if (!S_ISREG(st.st_mode)) type = 1;
        else if ((count = read(fd, data, sizeof(data))) < 0) { error = errno; count = 0; }
        close(fd);
    }
    printf("{\"errno\":%d,\"wrong_type\":%s,\"hex\":\"", error, type ? "true" : "false");
    for (ssize_t i = 0; i < count; i++) printf("%02x", data[i]);
    puts("\"}");
    return 0;
}
