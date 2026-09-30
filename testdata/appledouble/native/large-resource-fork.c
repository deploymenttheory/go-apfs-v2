// Qualification only. Independently inspect the native named stream with 64-bit
// offsets and CommonCrypto SHA-256; never linked into the Go implementation.
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "--create") && strcmp(argv[1], "--hash"))) return 2;
    int create = !strcmp(argv[1], "--create");
    int data = open(argv[2], create ? O_RDWR | O_CREAT | O_NOFOLLOW : O_RDONLY | O_NOFOLLOW, 0600);
    if (data < 0) { perror("open data"); return 1; }
    int fork = openat(data, "..namedfork/rsrc", create ? O_RDWR | O_CREAT : O_RDONLY, 0600);
    if (fork < 0) { perror("openat fork"); close(data); return 1; }
    const off_t size = ((off_t)1 << 32) + 17;
    if (create && (ftruncate(fork, size) ||
        pwrite(fork, "fork-start", 10, 0) != 10 ||
        pwrite(fork, "boundary-crossing", 17, ((off_t)1 << 32) - 8) != 17 ||
        pwrite(fork, "\xff", 1, size - 1) != 1)) {
        perror("create native fork"); close(fork); close(data); return 1;
    }
    struct stat ds, rs;
    if (fstat(data, &ds) || fstat(fork, &rs)) { perror("fstat"); close(fork); close(data); return 1; }
    unsigned char buffer[65536], digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    off_t offset = 0;
    for (;;) {
        ssize_t n = pread(fork, buffer, sizeof(buffer), offset);
        if (n < 0) { perror("pread fork"); close(fork); close(data); return 1; }
        if (!n) break;
        CC_SHA256_Update(&ctx, buffer, (CC_LONG)n);
        offset += n;
    }
    CC_SHA256_Final(digest, &ctx);
    printf("{\"Size\":%lld,\"ReadBytes\":%lld,\"Blocks\":%lld,\"SameIdentity\":%s,\"SHA256\":\"",(long long)rs.st_size,(long long)offset,(long long)rs.st_blocks,(ds.st_dev==rs.st_dev && ds.st_ino==rs.st_ino)?"true":"false");
    for (size_t i=0;i<sizeof(digest);i++) printf("%02x",digest[i]);
    puts("\"}");
    int failed=ferror(stdout);
    failed |= close(fork)!=0;
    failed |= close(data)!=0;
    return failed ? 1 : 0;
}
