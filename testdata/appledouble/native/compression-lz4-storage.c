// Qualification-only independent native decoding of small LZ4 image fixtures.
// Always used alongside kernel reads, never as a replacement for their outcome.
#include <compression.h>
#include <sys/xattr.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *message) { fprintf(stderr, "%s\n", message); exit(2); }
static uint32_t u32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static unsigned char *attribute(const char *path, const char *name, size_t *size) {
    ssize_t n = getxattr(path, name, NULL, 0, 0, XATTR_NOFOLLOW|XATTR_SHOWCOMPRESSION);
    if (n < 0 || n > 2*1024*1024) fail("native storage fixture extent");
    unsigned char *data = malloc(n ? (size_t)n : 1);
    if (!data) fail("allocate native fixture");
    if (getxattr(path, name, data, n ? (size_t)n : 1, 0, XATTR_NOFOLLOW|XATTR_SHOWCOMPRESSION) != n) fail("read native fixture");
    *size = (size_t)n;
    return data;
}
static void decode(const unsigned char *input, size_t n, size_t logical) {
    unsigned char output[65536];
    if (!n || !logical || logical > sizeof(output)) fail("native block extent");
    size_t written;
    if (input[0] == 0xff) {
        if (n-1 != logical) fail("stored LZ4 extent");
        memcpy(output, input+1, logical);
        written = logical;
    } else {
        written = compression_decode_buffer(output, logical, input, n, NULL, COMPRESSION_LZ4);
    }
    if (written != logical || fwrite(output, 1, written, stdout) != written) fail("native block decode/write");
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    size_t size;
    unsigned char *attr = attribute(argv[1], "com.apple.decmpfs", &size);
    if (size < 16 || size > 3802 || memcmp(attr, "fpmc", 4)) fail("native attribute header");
    uint32_t type = u32(attr+4);
    uint64_t logical = (uint64_t)u32(attr+8) | (uint64_t)u32(attr+12)<<32;
    if (!logical || logical > 2*1024*1024) fail("native logical fixture extent");
    if (type == 15) {
        decode(attr+16, size-16, (size_t)logical);
    } else if (type == 16) {
        size_t fork_size;
        unsigned char *fork = attribute(argv[1], "com.apple.ResourceFork", &fork_size);
        size_t blocks = ((size_t)logical+65535)/65536, index = 4*(blocks+1);
        if (fork_size < index || u32(fork) != index || u32(fork+4*blocks) != fork_size) fail("native fork index");
        for (size_t i=0; i<blocks; i++) {
            uint32_t start = u32(fork+4*i), end = u32(fork+4*(i+1));
            if (start < index || end <= start || end > fork_size) fail("native fork block");
            size_t remaining = (size_t)logical-i*65536;
            decode(fork+start, end-start, remaining < 65536 ? remaining : 65536);
        }
        free(fork);
    } else fail("native fixture is not LZ4");
    free(attr);
    return fflush(stdout) ? 2 : 0;
}
