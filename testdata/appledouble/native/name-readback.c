/* Read-only native cross-version verification of retained filename images.
 * stdout retains the result document; stderr records native call boundaries.
 */
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *case_id = "-";
static int candidate = -1;

static void must(int bad, const char *message) {
    if (bad) {
        perror(message);
        exit(2);
    }
}

static void trace(const char *phase, const char *operation,
                  long long result, int error) {
    int saved = errno;
    if (fprintf(stderr,
                "NATIVE %s case=%s candidate=%d operation=%s result=%lld errno=%d\n",
                phase, case_id, candidate, operation, result, error) < 0 ||
        fflush(stderr) == EOF) {
        exit(2);
    }
    errno = saved;
}

/* Keep each native operation in the original order and preserve its errno.
 * START is flushed before entering a potentially blocking filesystem call.
 */
#define OBSERVE(result, operation, expression) do { \
    trace("START", operation, 0, 0); \
    result = (expression); \
    int observed_errno = errno; \
    trace("END", operation, (long long)(result), (result) < 0 ? observed_errno : 0); \
    errno = observed_errno; \
} while (0)

static void unhex(const char *text, char *out) {
    size_t length = strlen(text);
    must(length % 2 || length > 2048, "hex length");
    for (size_t i = 0; i < length; i += 2) {
        unsigned value;
        must(sscanf(text + i, "%2x", &value) != 1 || !value, "hex");
        out[i / 2] = (char)value;
    }
    out[length / 2] = 0;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int root, base, status;
    OBSERVE(root, "open-root", open(argv[1], O_RDONLY | O_DIRECTORY));
    must(root < 0, "root");
    OBSERVE(base, "openat-corpus", openat(root, "collation", O_RDONLY | O_DIRECTORY));
    must(base < 0, "corpus");
    FILE *input = fopen(argv[2], "r");
    must(!input, "cases");
    char *line = NULL;
    size_t capacity = 0;
    unsigned count = 0;
    printf("{\"cases\":[");
    while (getline(&line, &capacity, input) >= 0) {
        line[strcspn(line, "\n")] = 0;
        char *id = strtok(line, "\t");
        char *created = strtok(NULL, "\t");
        char *queried = strtok(NULL, "\t");
        must(!id || !created || !queried || strtok(NULL, "\t"), "fields");
        case_id = id;
        candidate = -1;
        int directory;
        OBSERVE(directory, "openat-case", openat(base, id, O_RDONLY | O_DIRECTORY));
        must(directory < 0, "case root");
        char names[2][1025];
        unhex(created, names[0]);
        unhex(queried, names[1]);
        printf("%s{\"id\":\"%s\",\"results\":[", count ? "," : "", id);
        for (int i = 0; i < 2; i++) {
            candidate = i;
            errno = 0;
            int file;
            OBSERVE(file, "openat-file", openat(directory, names[i], O_RDONLY));
            int error = file < 0 ? errno : 0;
            struct stat st = {0};
            ssize_t read_count = -1;
            if (file >= 0) {
                OBSERVE(status, "fstat-file", fstat(file, &st));
                must(status, "file stat");
                char byte;
                OBSERVE(read_count, "read-file", read(file, &byte, 1));
                must(read_count < 0, "read file");
                OBSERVE(status, "close-file", close(file));
                must(status, "close file");
            }
            printf("%s{\"errno\":%d,\"inode\":%llu,\"size\":%lld,\"read\":%lld}",
                   i ? "," : "", error, (unsigned long long)st.st_ino,
                   (long long)st.st_size, (long long)read_count);
        }
        printf("]}");
        must(fflush(stdout) == EOF, "flush case result");
        candidate = -1;
        OBSERVE(status, "close-case", close(directory));
        must(status, "close case");
        count++;
        if (count % 100 == 0) {
            must(fprintf(stderr, "NATIVE PROGRESS cases=%u last=%s\n", count, id) < 0 ||
                 fflush(stderr) == EOF, "progress");
        }
    }
    must(ferror(input), "read cases");
    case_id = "-";
    free(line);
    must(fclose(input), "close cases");
    OBSERVE(status, "close-corpus", close(base));
    must(status, "close corpus");
    OBSERVE(status, "close-root", close(root));
    must(status, "close root");
    printf("],\"count\":%u}\n", count);
    return 0;
}
