/* Native MachOEditor metadata-copy contract: copyfile with a held destination.
 * Production never executes this oracle. Security signerutils.cpp calls
 * copyfile(source, NULL, state, COPYFILE_SECURITY | COPYFILE_METADATA).
 */
#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/xattr.h>

/* Compile-time qualification of the typed held positional xattr wrapper. */
_Static_assert(__builtin_types_compatible_p(__typeof__(&fsetxattr), int (*)(int, const char *, const void *, size_t, u_int32_t, int)), "fsetxattr signature");

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: oracle source target\n"); return 2; }
    int target = open(argv[2], O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (target < 0) { perror("open target"); return 1; }
    copyfile_state_t state = copyfile_state_alloc();
    if (!state) { perror("copyfile_state_alloc"); close(target); return 1; }
    if (copyfile_state_set(state, COPYFILE_STATE_DST_FD, &target) != 0) {
        perror("copyfile_state_set"); copyfile_state_free(state); close(target); return 1;
    }
    errno = 0;
    int result = copyfile(argv[1], NULL, state, COPYFILE_SECURITY | COPYFILE_METADATA);
    int failure = result < 0 ? errno : 0;
    int freed = copyfile_state_free(state);
    int closed = close(target);
    printf("{\"result\":%d,\"errno\":%d,\"free_result\":%d,\"close_result\":%d}\n", result, failure, freed, closed);
    return 0;
}
