// Qualification only: independent no-follow observations of Go's native projection.
#include <sys/stat.h>
#include <sys/xattr.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(int argc,char **argv) {
    if(argc!=2 && argc!=3) return 2;
    if(argc==3) {
        ssize_t n=getxattr(argv[1],argv[2],NULL,0,0,XATTR_NOFOLLOW);
        if(n<0 || n>64*1024*1024) {perror("getxattr size");return 1;}
        unsigned char *p=malloc(n?(size_t)n:1);
        if(!p)return 1;
        ssize_t got=getxattr(argv[1],argv[2],p,(size_t)n,0,XATTR_NOFOLLOW);
        if(got!=n) {perror("getxattr read");free(p);return 1;}
        int ok=fwrite(p,1,(size_t)n,stdout)==(size_t)n && fflush(stdout)==0;
        free(p);return ok?0:1;
    }
    struct stat st;
    if(lstat(argv[1],&st)) {perror("lstat");return 1;}
    printf("{\"UID\":%u,\"GID\":%u,\"Mode\":%u,\"Flags\":%u,\"Times\":[%lld,%lld,%lld,%lld]}\n",
        st.st_uid,st.st_gid,(unsigned)st.st_mode,st.st_flags,
        (long long)st.st_birthtimespec.tv_sec*1000000000LL+st.st_birthtimespec.tv_nsec,
        (long long)st.st_mtimespec.tv_sec*1000000000LL+st.st_mtimespec.tv_nsec,
        (long long)st.st_ctimespec.tv_sec*1000000000LL+st.st_ctimespec.tv_nsec,
        (long long)st.st_atimespec.tv_sec*1000000000LL+st.st_atimespec.tv_nsec);
    return ferror(stdout)?1:0;
}
