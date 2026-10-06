// Test-only, read-only kernel oracle for foreign carrier recompression images.
// Observe inode metadata before opening compressed data; read-open can itself
// invoke decmpfs validation. Full payload and raw storage are retained separately.
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *operation) { perror(operation); exit(2); }
static void path(char *out,size_t size,const char *root,const char *name,const char *suffix) {
    int n=snprintf(out,size,"%s/%s%s",root,name,suffix);
    if(n<0||(size_t)n>=size) {errno=ENAMETOOLONG;fail("path");}
}
static void save(const char *root,const char *name,const char *suffix,const void *bytes,size_t size) {
    char output[4096];path(output,sizeof(output),root,name,suffix);
    FILE *f=fopen(output,"wb");if(!f)fail("create observation");
    if(fwrite(bytes,1,size,f)!=size||fclose(f))fail("save observation");
}
static void attribute(int fd,const char *attribute,const char *root,const char *name,const char *suffix) {
    errno=0;ssize_t size=fgetxattr(fd,attribute,NULL,0,0,XATTR_SHOWCOMPRESSION);
    if(size<0&&errno!=ENOATTR)fail("attribute size");
    if(size<0)size=0;
    if(size>16*1024*1024) {errno=EFBIG;fail("attribute bound");}
    unsigned char *b=malloc((size_t)size+1);if(!b)fail("attribute allocation");
    if(size&&fgetxattr(fd,attribute,b,(size_t)size,0,XATTR_SHOWCOMPRESSION)!=size)fail("attribute read");
    save(root,name,suffix,b,(size_t)size);free(b);
}
int main(int argc,char **argv) {
    if(argc!=3)return 2;
    char name[256],input[4096];unsigned char buffer[65536];
    while(fgets(name,sizeof(name),stdin)) {
        size_t length=strlen(name);if(!length||name[length-1]!='\n')return 2;name[length-1]=0;
        if(!*name||strspn(name,"abcdefghijklmnopqrstuvwxyz0123456789-._")!=strlen(name)||strstr(name,".."))return 2;
        path(input,sizeof(input),argv[1],name,"");
        struct stat st;if(lstat(input,&st))fail("pre-open stat");if(!S_ISREG(st.st_mode))return 2;
        int fd=open(input,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)fail("open data");
        struct stat held;if(fstat(fd,&held))fail("held stat");
        if(held.st_dev!=st.st_dev||held.st_ino!=st.st_ino||held.st_size!=st.st_size||held.st_nlink!=st.st_nlink)return 2;
        attribute(fd,"com.apple.decmpfs",argv[2],name,".attr");
        attribute(fd,"com.apple.ResourceFork",argv[2],name,".fork");
        char output[4096];path(output,sizeof(output),argv[2],name,".data");FILE *f=fopen(output,"wb");if(!f)fail("create data");
        int64_t total=0;
        for(;;) {ssize_t n=read(fd,buffer,sizeof(buffer));if(n<0) {if(errno==EINTR)continue;fail("kernel read");}if(n==0)break;if(fwrite(buffer,1,(size_t)n,f)!=(size_t)n)fail("save data");total+=n;}
        if(fclose(f)||close(fd))fail("close data");
        if(total!=st.st_size)return 2;
        printf("{\"name\":\"%s\",\"size\":%lld,\"flags\":%u,\"mode\":%u,\"links\":%u,\"inode\":%llu,\"birth_sec\":%lld,\"birth_nsec\":%ld,\"change_sec\":%lld,\"change_nsec\":%ld,\"modify_sec\":%lld,\"modify_nsec\":%ld,\"access_sec\":%lld,\"access_nsec\":%ld,\"read_size\":%lld}\n",name,(long long)st.st_size,st.st_flags,st.st_mode,st.st_nlink,(unsigned long long)st.st_ino,(long long)st.st_birthtimespec.tv_sec,st.st_birthtimespec.tv_nsec,(long long)st.st_ctimespec.tv_sec,st.st_ctimespec.tv_nsec,(long long)st.st_mtimespec.tv_sec,st.st_mtimespec.tv_nsec,(long long)st.st_atimespec.tv_sec,st.st_atimespec.tv_nsec,(long long)total);
    }
    if(ferror(stdin)||fflush(stdout))fail("observation stream");
    return 0;
}
