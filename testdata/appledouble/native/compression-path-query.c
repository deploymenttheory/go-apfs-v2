// Native evidence only: query compression without opening file contents.
#define main compression_policy_main
#include "compression-policy.c"
#undef main

static int path_query_probe(const char *path) {
    void *library = dlopen("/System/Library/PrivateFrameworks/AppleFSCompression.framework/AppleFSCompression", RTLD_NOW);
    if (!library) die("compression framework");
    int (*query)(const char *, void *) = dlsym(library, "queryCompressionInfo");
    if (!query) return 2;
    struct stat before, after;
    if (lstat(path, &before)) die("before metadata");
    unsigned char info[96];
    memset(info, 0xa5, sizeof(info));
    errno = 0;
    int result = query(path, info), error = errno;
    if (lstat(path, &after)) die("after metadata");
    printf("{");
    query_record("path_query", result, error, info);
    printf(",\"flags_unchanged\":%s,\"size_unchanged\":%s,\"identity_unchanged\":%s}\n",
        before.st_flags == after.st_flags ? "true" : "false",
        before.st_size == after.st_size ? "true" : "false",
        before.st_dev == after.st_dev && before.st_ino == after.st_ino ? "true" : "false");
    return dlclose(library) ? 2 : 0;
}

int main(int argc, char **argv) { return argc == 2 ? path_query_probe(argv[1]) : 2; }
