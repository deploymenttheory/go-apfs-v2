// Qualification-only independent no-follow metadata and xattr reads.
#include <sys/stat.h>
#include <sys/acl.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "hfs-finder-source.h"

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--source-finder") == 0) {
        unsigned char input[32]; if(strlen(argv[3])!=64) return 2;
        for(size_t i=0;i<32;i++) { unsigned v; if(sscanf(argv[3]+2*i,"%2x",&v)!=1) return 2; input[i]=(unsigned char)v; }
        struct cnode node={.c_attr={.ca_mode=(mode_t)strtoul(argv[2],NULL,0)}};
        if(hfs_zero_hidden_fields(&node,input)) return 1;
        return fwrite(input,1,sizeof(input),stdout)==sizeof(input)&&fflush(stdout)==0?0:1;
    }
    if (argc == 5 && strcmp(argv[1], "--apply-finder") == 0) {
        unsigned char input[64], value[32]; size_t n = strlen(argv[3])/2;
        if (n > sizeof(input) || strlen(argv[3])%2) return 2;
        for (size_t i=0;i<n;i++) { unsigned v; if (sscanf(argv[3]+2*i,"%2x",&v)!=1) return 2; input[i]=(unsigned char)v; }
        errno=0; int rc=setxattr(argv[2],"com.apple.FinderInfo",input,n,0,XATTR_NOFOLLOW); int seterror=rc?errno:0;
        if (!rc && strcmp(argv[4],"-") && lchflags(argv[2],(unsigned)strtoul(argv[4],NULL,0))) { perror("lchflags"); return 1; }
        errno=0; ssize_t length=getxattr(argv[2],"com.apple.FinderInfo",value,sizeof(value),0,XATTR_NOFOLLOW); int geterror=length<0?errno:0;
        struct stat st; if(lstat(argv[2],&st)) { perror("lstat"); return 1; }
        printf("{\"Code\":%d,\"Errno\":%d,\"Length\":%zd,\"GetErrno\":%d,\"Flags\":%u,\"Value\":\"",rc,seterror,length,geterror,st.st_flags);
        if(length>=0)for(ssize_t i=0;i<length;i++)printf("%02x",value[i]);
        printf("\"}\n"); return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--security") == 0) {
        filesec_t f = filesec_init();
        struct stat st;
        if (!f || lstatx_np(argv[2], &st, f) != 0) { perror("lstatx_np"); return 1; }
        void *raw = NULL; size_t n = 0;
        if (filesec_get_property(f, FILESEC_ACL_RAW, &raw) != 0 ||
            filesec_get_property(f, FILESEC_ACL_ALLOCSIZE, &n) != 0 || n < 44 || n > 3116) {
            perror("filesec security"); filesec_free(f); return 1;
        }
        size_t written = fwrite(raw, 1, n, stdout);
        filesec_free(f);
        return written == n && fflush(stdout) == 0 ? 0 : 1;
    }
    if (argc == 4 && strcmp(argv[1], "--xattr") == 0) {
        ssize_t size = getxattr(argv[2], argv[3], NULL, 0, 0, XATTR_NOFOLLOW);
        if (size < 0) { perror("getxattr size"); return 1; }
        if (size > 64 * 1024 * 1024) { fprintf(stderr, "oracle allocation bound\n"); return 1; }
        unsigned char *data = malloc(size ? (size_t)size : 1);
        if (!data) { perror("malloc"); return 1; }
        ssize_t read = getxattr(argv[2], argv[3], data, size ? (size_t)size : 1, 0, XATTR_NOFOLLOW);
        if (read != size) { perror("getxattr read"); free(data); return 1; }
        size_t written = fwrite(data, 1, (size_t)size, stdout);
        free(data);
        if (written != (size_t)size || fflush(stdout) != 0) { perror("write"); return 1; }
        return 0;
    }
    if (argc != 2) return 2;
    struct stat s;
    if (lstat(argv[1], &s) != 0) { perror("lstat"); return 1; }
    printf("{\"UID\":%u,\"GID\":%u,\"Mode\":%u,\"Flags\":%u,\"Inode\":%llu,\"Times\":[%lld,%lld,%lld,%lld]}\n",
        s.st_uid, s.st_gid, s.st_mode, s.st_flags, (unsigned long long)s.st_ino,
        (long long)s.st_birthtimespec.tv_sec*1000000000+s.st_birthtimespec.tv_nsec,
        (long long)s.st_mtimespec.tv_sec*1000000000+s.st_mtimespec.tv_nsec,
        (long long)s.st_ctimespec.tv_sec*1000000000+s.st_ctimespec.tv_nsec,
        (long long)s.st_atimespec.tv_sec*1000000000+s.st_atimespec.tv_nsec);
    return 0;
}
