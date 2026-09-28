// Test-only raw process capture. Calls the libSystem wrapper used by
// libquarantine; there are no direct numbered syscalls or production linkage.
// ABI observed in libquarantine 217.0.4 __qtn_syscall_quarantine_getprocinfo.
// Generic wrapper declaration: Apple XNU security/mac.h, commit
// f6217f891ac0bb64f3d375211650a4c1ff8ca1ea, __mac_syscall.
#include <stddef.h>
struct quarantine_process_info {
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
_Static_assert(sizeof(struct quarantine_process_info) == 64, "process info ABI size");
_Static_assert(offsetof(struct quarantine_process_info, agent) == 8, "agent ABI offset");
_Static_assert(offsetof(struct quarantine_process_info, metadata) == 24, "metadata ABI offset");
_Static_assert(offsetof(struct quarantine_process_info, tracking) == 40, "tracking ABI offset");
_Static_assert(offsetof(struct quarantine_process_info, flags) == 48, "flags ABI offset");
_Static_assert(offsetof(struct quarantine_process_info, pid) == 56, "pid ABI offset");
static void raw_process_query(int operation, int32_t pid) {
    int (*query)(const char *, int, void *) = dlsym(RTLD_DEFAULT, "__mac_syscall");
    if (!query) fail("load process-info libSystem wrapper");
    // The private protocol returns lengths, not caller-selected capacities.
    // These are the bounded buffers passed by qtn_proc_init_with_pid itself.
    char agent[257] = {0}, metadata[65] = {0}, tracking[64] = {0};
    struct quarantine_process_info info = {0};
    info.agent = agent; info.metadata = metadata; info.tracking = tracking; info.pid = pid;
    errno = 0;
    int code = query("Quarantine", operation, &info), saved = errno;
    if (info.agent_length > 256 || info.metadata_length > 64 || info.tracking_length > 64)
        fail("process-info buffer bounds");
    printf("{\"Code\":%d,\"Errno\":%d,\"Flags\":%llu,\"Agent\":", code, saved, (unsigned long long)info.flags);
    hex(agent, (size_t)info.agent_length);
    printf(",\"Metadata\":"); hex(metadata, (size_t)info.metadata_length);
    // Tracking bytes are unrelated to this planner and can contain host state.
    // Keep their length as a scope diagnostic, without publishing those bytes.
    printf(",\"TrackingLength\":%llu}", (unsigned long long)info.tracking_length);
}
static void raw_process_snapshot(void) {
    // Explicit-PID queries may require privileges even for the current PID.
    // Record those refusals and an invalid-PID control; neither is absence.
    if (getpid() <= 0) fail("current PID");
    printf(",\"Raw\":{\"Self\":"); raw_process_query(84, 0);
    printf(",\"PID\":"); raw_process_query(85, getpid());
    printf(",\"InvalidPID\":"); raw_process_query(85, -1);
    putchar('}');
}
