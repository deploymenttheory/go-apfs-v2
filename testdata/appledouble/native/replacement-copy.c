// Native metadata-copy control for replacement writers. Test helper only.
#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/clonefile.h>
#include <unistd.h>
#include <time.h>

static int replacement_copy_oracle(int argc, char **argv) {
    if (argc != 4) return 2;
    int source = open(argv[1], O_RDONLY);
    if (source < 0) return 3;
    errno = 0;
    int clone_result = fclonefileat(source, AT_FDCWD, argv[3], 0);
    int clone_error = clone_result == 0 ? 0 : errno;
    if (clone_result == 0 && unlink(argv[3]) != 0) return 4;
    int target = open(argv[2], O_CREAT | O_EXCL | O_RDWR, 0600);
    if (target < 0) return 5;
    errno = 0;
    time_t copy_begin = time(NULL);
    int copy_result = fcopyfile(source, target, NULL, COPYFILE_SECURITY | COPYFILE_METADATA);
    time_t copy_end = time(NULL);
    int copy_error = copy_result == 0 ? 0 : errno;
    int close_target = close(target);
    int close_source = close(source);
    printf("{\"clone_errno\":%d,\"copy_errno\":%d,\"copy_begin\":%lld,\"copy_end\":%lld}\n", clone_error, copy_error, (long long)copy_begin, (long long)copy_end);
    return copy_result != 0 || close_target != 0 || close_source != 0;
}

int main(int argc, char **argv) { return replacement_copy_oracle(argc, argv); }
