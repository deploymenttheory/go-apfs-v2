// Independent native ABI observer for the current process only. Production
// policy and AppleDouble parsing are not delegated to this test library.
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

struct process_info {
    uint64_t agent_length;
    char *agent;
    uint64_t metadata_length;
    char *metadata;
    uint64_t tracking_length;
    char *tracking;
    uint64_t flags;
    int32_t pid;
    uint32_t reserved;
};
_Static_assert(sizeof(struct process_info) == 64, "process ABI size");
_Static_assert(offsetof(struct process_info, flags) == 48, "flags offset");
_Static_assert(offsetof(struct process_info, pid) == 56, "self PID offset");

struct file_get { int64_t fd; uint64_t *length; char *data; };
struct file_set { int64_t fd; uint64_t length; const char *data; };
_Static_assert(sizeof(struct file_get) == 24 && sizeof(struct file_set) == 24, "file ABI size");
_Static_assert(offsetof(struct file_get, data) == 16 && offsetof(struct file_set, data) == 16, "file data offset");

int appledouble_quarantine_apply(int fd, const char *input, uint64_t length) {
    void *library = dlopen("/usr/lib/system/libquarantine.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!library) return ENOSYS;
    void *(*allocate)(void) = dlsym(library, "_qtn_file_alloc");
    void (*release)(void *) = dlsym(library, "_qtn_file_free");
    int (*parse)(void *, const void *, size_t) = dlsym(library, "_qtn_file_init_with_data");
    int (*apply)(void *, int) = dlsym(library, "_qtn_file_apply_to_fd");
    if (!allocate || !release || !parse || !apply) { dlclose(library); return ENOSYS; }
    void *q = input ? allocate() : NULL;
    if (input && !q) { dlclose(library); return ENOMEM; }
    int result = input ? parse(q, input, (size_t)length) : 0;
    if (!result) result = apply(q, fd);
    if (q) release(q);
    dlclose(library);
    return result;
}

int appledouble_quarantine_capture(unsigned char *agent, uint64_t *agent_length,
    unsigned char *metadata, uint64_t *metadata_length, unsigned char *tracking,
    uint64_t *tracking_length, uint64_t *flags, int *saved_errno) {
    int (*query)(const char *, int, void *) = dlsym(RTLD_DEFAULT, "__mac_syscall");
    if (!query) { *saved_errno = ENOSYS; return -1; }
    char a[257] = {0}, m[65] = {0}, t[64] = {0};
    struct process_info info = { .agent = a, .metadata = m, .tracking = t };
    errno = 0;
    int result = query("Quarantine", 84, &info);
    *saved_errno = errno;
    if (result) return result;
    if (info.agent_length > 255 || info.metadata_length > 64 || info.tracking_length > 64) {
        *saved_errno = EOVERFLOW; return -1;
    }
    memcpy(agent, a, info.agent_length);
    memcpy(metadata, m, info.metadata_length);
    memcpy(tracking, t, info.tracking_length);
    *agent_length = info.agent_length;
    *metadata_length = info.metadata_length;
    *tracking_length = info.tracking_length;
    *flags = info.flags;
    return 0;
}
