// Research only: call the host's public Compression buffer API independently
// of the Go implementation. Retain both successful and declined encodings.
#include <compression.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void fail(const char *s) { perror(s); exit(2); }
int main(int argc, char **argv) {
    if (argc != 4 && argc != 5) return 2;
    FILE *in = fopen(argv[2], "rb"); if (!in) fail("input");
    if (fseek(in, 0, SEEK_END)) fail("seek");
    long length = ftell(in); if (length < 0 || length > 1048576) return 2;
    rewind(in);
    uint8_t *source = calloc(1048640, 1), *output = calloc(2097216, 1);
    if (!source || !output) fail("allocate");
    if (fread(source, 1, length, in) != (size_t)length) fail("read");
    if (fclose(in)) fail("close input");
    int decode = strncmp(argv[1], "decode:", 7) == 0;
    compression_algorithm algorithm = (compression_algorithm)strtoul(argv[1] + (decode ? 7 : 0), NULL, 0);
    size_t capacity = argc == 5 ? (size_t)strtoull(argv[4], NULL, 0) : 2097216;
    if (capacity > 2097216) return 2;
    size_t count = decode
        ? compression_decode_buffer(output, capacity, source, (size_t)length, NULL, algorithm)
        : compression_encode_buffer(output, capacity, source, (size_t)length, NULL, algorithm);
    FILE *out = fopen(argv[3], "wb"); if (!out) fail("output");
    if (fwrite(output, 1, count, out) != count) fail("write");
    if (fclose(out)) fail("close output");
    free(source); free(output);
    printf("%zu\n", count);
    return 0;
}
