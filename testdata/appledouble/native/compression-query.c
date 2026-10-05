// Research-only malformed and extended compression-metadata query controls.
// Reuse the guarded path/held query recorder; never interpret corrupt payloads.
#define main compression_policy_capture_main
#include "compression-policy.c"
#undef main

static void put_hex(int fd, const char *name, const char *value, const char *label) {
    if (!strcmp(value, "none")) return;
    size_t length = strlen(value);
    if ((length & 1) || length > 8192) exit(2);
    unsigned char bytes[4096];
    for (size_t i = 0; i < length/2; i++) {
        unsigned int x;
        if (sscanf(value+2*i, "%2x", &x) != 1) exit(2);
        bytes[i] = (unsigned char)x;
    }
    errno = 0;
    int result = fsetxattr(fd, name, bytes, length/2, 0, 0), error = errno;
    printf("\"%s\":{\"result\":%d,\"errno\":%d},", label, result, error);
}

int main(int argc, char **argv) {
    if (argc != 6) return 2;
    void *library = dlopen("/System/Library/PrivateFrameworks/AppleFSCompression.framework/AppleFSCompression", RTLD_NOW);
    if (!library) return 2;
    int fd = open(argv[1], O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC, 0600);
    if (fd < 0) die("create query control");
    printf("{");
    put_hex(fd, "com.apple.decmpfs", argv[2], "attribute_install");
    put_hex(fd, "com.apple.ResourceFork", argv[3], "fork_install");
    errno = 0;
    int result = fchflags(fd, (unsigned)strtoul(argv[4], NULL, 0)), error = errno;
    printf("\"flag_install\":{\"result\":%d,\"errno\":%d},", result, error);
    struct stat state;
    if (fstat(fd, &state)) die("stat query control");
    printf("\"initial_flags\":%u,\"initial_size\":%lld,", state.st_flags, (long long)state.st_size);
    int (*fquery)(int, void *) = dlsym(library, "fqueryCompressionInfo");
    if (!fquery) return 2;
    unsigned char info[96];
    memset(info, 0xa5, sizeof(info));
    errno = 0;
    result = fquery(fd, info); error = errno;
    query_record("initial_held_query", result, error, info);
    printf(",");
    if (close(fd)) die("close query control");
    inspect(library, argv[1], argv[5]);
    printf("}\n");
    if (dlclose(library)) return 2;
    return 0;
}
