// Native compression policy and query observations. Test helper only.
// The query result is captured as raw bytes with a trailing canary: no private
// framework structure is inferred from the codesign AST-only header stub.
#include <CoreFoundation/CoreFoundation.h>
#include <compression.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static void die(const char *what) { perror(what); exit(2); }
// Measure through Apple's codec, independently of the Go encoder. Used only to
// select real inputs immediately around native whole-file decision boundaries.
static void measure(const char *path, const char *type) {
    unsigned requested = (unsigned)strtoul(type, NULL, 0);
    compression_algorithm algorithm;
    switch (requested) {
        case 3: algorithm = (compression_algorithm)0x205; break;
        case 7: algorithm = (compression_algorithm)0x900; break;
        case 11: algorithm = (compression_algorithm)0x801; break;
        case 13: algorithm = (compression_algorithm)0x702; break;
        default: fprintf(stderr, "unsupported measured codec\n"); exit(2);
    }
    FILE *file = fopen(path, "rb");
    if (!file) die("measure input");
    unsigned char input[65536], output[65536];
    uint64_t total = 0;
    size_t n;
    while ((n = fread(input, 1, sizeof(input), file)) != 0) {
        // The public zlib API returns raw DEFLATE; filesystem storage adds 78 5e.
        size_t capacity = requested == 3 ? (n > 2 ? n - 2 : 0) : n;
        size_t encoded = compression_encode_buffer(output, capacity, input, n, NULL, algorithm);
        if (requested == 3 && encoded) {
            encoded += 2;
            if (encoded >= n) encoded = 0;
        }
        total += encoded ? encoded : n + 1;
    }
    if (ferror(file) || fclose(file)) die("measure read/close");
    printf("%llu\n", (unsigned long long)total);
}
static void hex(const unsigned char *p, size_t n) {
    putchar('"');
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    putchar('"');
}
static void save_attribute(const char *path, const char *name, const char *prefix, const char *suffix) {
    ssize_t n = getxattr(path, name, NULL, 0, 0, XATTR_SHOWCOMPRESSION);
    if (n < 0) { if (errno == ENOATTR) return; die("attribute size"); }
    if (n > (128 << 20)) { errno = EFBIG; die("bounded policy attribute"); }
    void *data = malloc(n ? (size_t)n : 1);
    if (!data) die("allocate attribute");
    if (getxattr(path, name, data, (size_t)n, 0, XATTR_SHOWCOMPRESSION) != n) die("read attribute");
    char output[4096];
    int length = snprintf(output, sizeof(output), "%s.%s", prefix, suffix);
    if (length < 0 || (size_t)length >= sizeof(output)) { errno = ENAMETOOLONG; die("output path"); }
    FILE *file = fopen(output, "wb");
    if (!file) die("open attribute output");
    if (fwrite(data, 1, (size_t)n, file) != (size_t)n || fclose(file)) die("save attribute");
    free(data);
}
static void query_record(const char *label, int result, int error, const unsigned char *info) {
    bool guard = true;
    for (size_t i = 32; i < 96; i++) if (info[i] != 0xa5) guard = false;
    printf("\"%s\":{\"result\":%d,\"errno\":%d,\"bytes\":", label, result, error);
    hex(info, 32);
    printf(",\"guard\":%s}", guard ? "true" : "false");
    if (!guard) { fprintf(stderr, "query result exceeded observed ABI extent\n"); exit(2); }
}
static void inspect(void *library, const char *path, const char *prefix) {
    int (*query)(const char *, void *) = dlsym(library, "queryCompressionInfo");
    int (*fquery)(int, void *) = dlsym(library, "fqueryCompressionInfo");
    if (!query || !fquery) { fprintf(stderr, "missing query exports\n"); exit(2); }
    unsigned char info[96];
    memset(info, 0xa5, sizeof(info));
    errno = 0;
    int result = query(path, info), error = errno;
    query_record("path_query", result, error, info);
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) { printf(",\"open_errno\":%d", errno); return; }
    memset(info, 0xa5, sizeof(info));
    errno = 0;
    result = fquery(fd, info); error = errno;
    printf(","); query_record("held_query", result, error, info);
    struct stat st;
    if (fstat(fd, &st)) die("stat held input");
    printf(",\"flags\":%u,\"size\":%lld,\"blocks\":%lld,\"links\":%u,\"mode\":%u",
        st.st_flags, (long long)st.st_size, (long long)st.st_blocks, st.st_nlink, st.st_mode);
    if (close(fd)) die("close held input");
    save_attribute(path, "com.apple.decmpfs", prefix, "attr");
    save_attribute(path, "com.apple.ResourceFork", prefix, "fork");
}
int main(int argc, char **argv) {
    if (argc != 4 && argc != 6) return 2;
    if (argc == 4 && !strcmp(argv[1], "measure")) {
        measure(argv[2], argv[3]);
        return 0;
    }
    void *library = dlopen("/System/Library/PrivateFrameworks/AppleFSCompression.framework/AppleFSCompression", RTLD_NOW);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    printf("{");
    if (argc == 6 && !strcmp(argv[1], "compress")) {
        void *(*create)(const void *, const void *, const void *, const void *, CFDictionaryRef) = dlsym(library, "CreateCompressionQueue");
        bool (*compress)(void *, const char *, const char *) = dlsym(library, "CompressFile");
        void (*finish)(void *) = dlsym(library, "FinishCompressionAndCleanUp");
        if (!create || !compress || !finish) return 2;
        CFMutableDictionaryRef options = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (strcmp(argv[4], "default")) {
            CFStringRef type = CFStringCreateWithCString(NULL, argv[4], kCFStringEncodingUTF8);
            CFDictionarySetValue(options, CFSTR("CompressionTypes"), type);
            CFRelease(type);
        }
        if (!strcmp(argv[5], "yes")) CFDictionarySetValue(options, CFSTR("AllowStoringDataInXattr"), kCFBooleanTrue);
        else if (!strcmp(argv[5], "no")) CFDictionarySetValue(options, CFSTR("AllowStoringDataInXattr"), kCFBooleanFalse);
        else if (strcmp(argv[5], "default")) return 2;
        void *queue = create(NULL, NULL, NULL, NULL, options);
        if (!queue) return 2;
        errno = 0;
        bool accepted = compress(queue, argv[2], NULL);
        int queue_error = errno;
        finish(queue);
        CFRelease(options);
        printf("\"accepted\":%s,\"queue_errno\":%d,", accepted ? "true" : "false", queue_error);
    } else if (strcmp(argv[1], "inspect")) return 2;
    inspect(library, argv[2], argv[3]);
    printf("}\n");
    if (dlclose(library)) return 2;
    return 0;
}
