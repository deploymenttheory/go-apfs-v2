// Native buffer oracle only. Bounds allow expansion of a 1 MiB input before
// native decoding, rather than confusing the test driver's cap with a codec error.
#include <compression.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void fail(const char *message) { perror(message); exit(2); }
int main(int argc, char **argv) {
    if (argc != 4 && argc != 5) return 2;
    FILE *file = fopen(argv[2], "rb");
    if (!file) fail("open input");
    if (fseek(file, 0, SEEK_END)) fail("seek input");
    long length = ftell(file);
    if (length < 0 || length > 2*1024*1024) return 2;
    rewind(file);
    unsigned char *input = calloc((size_t)length+64, 1);
    unsigned char *output = calloc(2*1024*1024+64, 1);
    if (!input || !output) fail("allocate buffers");
    if (fread(input, 1, (size_t)length, file) != (size_t)length || fclose(file)) fail("read input");
    size_t count;
    size_t capacity = argc == 5 ? (size_t)strtoull(argv[4], NULL, 0) : 2*1024*1024;
    if (capacity > 2*1024*1024) return 2;
    if (!strcmp(argv[1], "decode:256")) count = compression_decode_buffer(output, capacity, input, (size_t)length, NULL, COMPRESSION_LZ4);
    else if (!strcmp(argv[1], "256")) count = compression_encode_buffer(output, 2*1024*1024, input, (size_t)length, NULL, COMPRESSION_LZ4);
    else return 2;
    file = fopen(argv[3], "wb");
    if (!file) fail("open output");
    if (fwrite(output, 1, count, file) != count || fclose(file)) fail("write output");
    printf("%zu\n", count);
    free(input); free(output);
    return 0;
}
