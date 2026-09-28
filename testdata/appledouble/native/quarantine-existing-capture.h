// Native research only. Replaces the base helper's xattr observer so malformed
// destination bytes and libquarantine import errors remain independent evidence.
static void xattr(int fd) {
    unsigned char data[4096];
    errno = 0;
    ssize_t length = fgetxattr(fd, "com.apple.quarantine", data, sizeof data, 0, 0);
    int saved = errno;
    if (length < 0 && saved != ENOATTR) fail("read destination quarantine");
    struct stat st;
    if (fstat(fd, &st)) fail("stat destination");
    printf("{\"Present\":%s,\"Errno\":%d,\"Bytes\":", length >= 0 ? "true" : "false", saved);
    hex(data, length < 0 ? 0 : (size_t)length);
    printf(",\"Envelope\":");
    int imported = 0, import_errno = 0;
    if (length >= 0) {
        void *q = file_alloc(); if (!q) fail("allocate readback import");
        errno = 0;
        imported = file_capture(q, fd); import_errno = errno;
        if (imported == 0) {
            char envelope[4096]; size_t n = sizeof envelope;
            if (file_export(q, envelope, &n) || n > sizeof envelope) fail("export readback");
            hex(envelope, n);
        } else hex("", 0);
        file_free(q);
    } else hex("", 0);
    printf(",\"Import\":{\"Code\":%d,\"Errno\":%d}}", imported, import_errno);
}
