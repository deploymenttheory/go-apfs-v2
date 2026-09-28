// Native research only. Open a link's own vnode with O_SYMLINK and retain
// independent path/fd identity plus target state before and after application.
#include <dirent.h>
static int baseline_code, baseline_errno;
static int target_fd = -1, target_content_fd = -1, destination_type;
static char target_path[4096], destination_path[4096];
static int destination_kind(const char *kind) {
    if (!strcmp(kind, "file")) return 0;
    if (!strcmp(kind, "directory")) return 1;
    if (!strcmp(kind, "symlink-file")) return 2;
    if (!strcmp(kind, "symlink-directory")) return 3;
    if (!strcmp(kind, "symlink-dangling")) return 4;
    return -1;
}
static int destination(const char *path, int kind, const char *baseline) {
    destination_type = kind;
    if (strlen(path) >= sizeof destination_path) fail("destination path length");
    strcpy(destination_path, path);
    if (kind >= 2) {
        strcpy(target_path, path);
        char *slash = strrchr(target_path, '/');
        if (!slash) fail("destination parent");
        strcpy(slash + 1, "target");
        if (kind != 4) {
            if (kind == 3 && mkdir(target_path, 0700)) fail("create target directory");
            target_fd = open(target_path, kind == 3 ? O_RDONLY : O_CREAT | O_EXCL | O_RDWR, 0600);
            if (target_fd < 0) fail("open target");
            target_content_fd = kind == 3 ? openat(target_fd, "guard", O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, 0600) : target_fd;
            if (target_content_fd < 0) fail("open target content");
            const char content[] = "target-content\n";
            if (write(target_content_fd, content, sizeof content - 1) != sizeof content - 1) fail("write target content");
            const char quarantine[] = "0081;23456789;TargetAgent;TargetID";
            if (fsetxattr(target_fd, "com.apple.quarantine", quarantine, sizeof quarantine - 1, 0, 0)) fail("prepare target quarantine");
        }
        if (symlink("target", path)) fail("create symlink");
    } else if (kind == 1 && mkdir(path, 0700)) fail("create directory");
    int flags = kind >= 2 ? O_RDONLY | O_SYMLINK : (kind == 1 ? O_RDONLY : O_CREAT | O_EXCL | O_RDWR);
    int fd = open(path, flags, 0600);
    if (fd < 0) fail("open destination vnode");
    if (strcmp(baseline, "-")) {
        size_t length; char *data = load(baseline, &length);
        errno = 0;
        baseline_code = fsetxattr(fd, "com.apple.quarantine", data, length, 0, 0);
        baseline_errno = errno;
        free(data);
    }
    return fd;
}
static void destination_snapshot(int fd) {
    struct stat actual, named;
    if (fstat(fd, &actual) || lstat(destination_path, &named)) fail("destination identity");
    int identical = actual.st_dev == named.st_dev && actual.st_ino == named.st_ino && actual.st_mode == named.st_mode;
    if (!identical) fail("destination descriptor followed link");
    printf("{\"Mode\":%u,\"IdentityMatches\":true,\"LinkTarget\":", actual.st_mode & S_IFMT);
    if (destination_type >= 2) {
        char target[4096]; ssize_t n = readlink(destination_path, target, sizeof target);
        if (n < 0 || !S_ISLNK(actual.st_mode)) fail("read link vnode");
        hex(target, (size_t)n);
    } else hex("", 0);
    putchar('}');
}
static void target_snapshot(void) {
    if (destination_type < 2) { printf("null"); return; }
    struct stat named, actual;
    errno = 0;
    int rc = lstat(target_path, &named), saved = errno;
    if (destination_type == 4) {
        if (rc != -1 || saved != ENOENT) fail("dangling target changed");
        printf("{\"Present\":false,\"Errno\":%d}", saved); return;
    }
    if (rc || fstat(target_fd, &actual) || named.st_dev != actual.st_dev || named.st_ino != actual.st_ino) fail("target identity changed");
    unsigned char content[64]; ssize_t n = pread(target_content_fd, content, sizeof content, 0);
    if (n < 0) fail("read target content");
    int entries = 0;
    if (destination_type == 3) {
        DIR *d = opendir(target_path); if (!d) fail("open target directory listing");
        struct dirent *entry;
        while ((entry = readdir(d))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            if (strcmp(entry->d_name, "guard")) fail("target directory entry changed");
            entries++;
        }
        if (closedir(d)) fail("close target directory listing");
    }
    printf("{\"Present\":true,\"Errno\":0,\"Device\":%llu,\"Inode\":%llu,\"Mode\":%u,\"Entries\":%d,\"Content\":", (unsigned long long)actual.st_dev, (unsigned long long)actual.st_ino, actual.st_mode & S_IFMT, entries);
    hex(content, (size_t)n);
    printf(",\"Quarantine\":"); xattr(target_fd); putchar('}');
}
