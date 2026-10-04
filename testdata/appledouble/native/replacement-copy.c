// Native metadata-copy control for replacement writers. Test helper only.
#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/clonefile.h>
#include <unistd.h>
#include <time.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

static void fail(const char *operation) {
    fprintf(stderr, "%s: errno=%d %s\n", operation, errno, strerror(errno));
    exit(20);
}
static void hex(const void *data, size_t length) {
    const unsigned char *bytes = data;
    putchar('"');
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
    putchar('"');
}
#include "quarantine-process-capture.h"

static void replacement_process_context(void) {
    char version[64]; size_t length = sizeof(version);
    if (sysctlbyname("kern.osproductversion", version, &length, NULL, 0)) fail("host version");
    void *library = dlopen("/usr/lib/system/libquarantine.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!library) fail("libquarantine control");
    void *(*allocate)(void) = dlsym(library, "_qtn_proc_alloc");
    void (*release)(void *) = dlsym(library, "_qtn_proc_free");
    int (*capture)(void *) = dlsym(library, "_qtn_proc_init_with_self");
    if (!allocate || !release || !capture) fail("process control functions");
    void *process = allocate(); if (!process) fail("process control allocation");
    errno = 0; int code = capture(process), saved = errno;
    printf(",\"host_major\":%d,\"process_init_code\":%d,\"process_init_errno\":%d", atoi(version), code, saved);
    release(process); dlclose(library);
    raw_process_snapshot();
}

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
    printf("{\"clone_errno\":%d,\"copy_errno\":%d,\"copy_begin\":%lld,\"copy_end\":%lld", clone_error, copy_error, (long long)copy_begin, (long long)copy_end);
    replacement_process_context(); puts("}");
    return copy_result != 0 || close_target != 0 || close_source != 0;
}

int main(int argc, char **argv) { return replacement_copy_oracle(argc, argv); }
