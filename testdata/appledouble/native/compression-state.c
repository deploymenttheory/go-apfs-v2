// Native filesystem oracle for active and inactive decmpfs storage. Test only.
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

static void fail(const char *what) { perror(what); exit(2); }
static unsigned char *load(const char *path, size_t *size) {
    FILE *f=fopen(path,"rb"); if(!f)fail("input");
    if(fseek(f,0,SEEK_END))fail("seek"); long n=ftell(f);
    if(n<0||n>262144||fseek(f,0,SEEK_SET))fail("input bounds");
    unsigned char *b=malloc((size_t)n+1);if(!b)fail("allocate");
    if(fread(b,1,(size_t)n,f)!=(size_t)n||fclose(f))fail("read input");
    *size=(size_t)n;return b;
}
static void save(const char *prefix,const char *suffix,const void *b,size_t n) {
    char path[4096];if(snprintf(path,sizeof(path),"%s.%s",prefix,suffix)>=(int)sizeof(path))exit(2);
    FILE *f=fopen(path,"wb");if(!f)fail("output");
    if(fwrite(b,1,n,f)!=n||fclose(f))fail("save");
}
static void attribute(int fd,const char *name,const char *prefix,const char *suffix) {
    unsigned char b[262144];errno=0;ssize_t n=fgetxattr(fd,name,b,sizeof(b),0,XATTR_SHOWCOMPRESSION);int error=n<0?errno:0;
    if(n<0&&error!=ENOATTR)fail("capture attribute");
    save(prefix,suffix,b,n<0?0:(size_t)n);
    printf(",\"%s_size\":%lld,\"%s_errno\":%d",suffix,(long long)n,suffix,error);
}
int main(int argc,char **argv) {
    // create path attr fork data flags mutate-prefix; observe path output-prefix
    if(argc==8&&!strcmp(argv[1],"create")) {
        int f=open(argv[2],O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0644);if(f<0)fail("create");
        size_t n;unsigned char *b=load(argv[5],&n);if(write(f,b,n)!=(ssize_t)n)fail("data");free(b);
        b=load(argv[3],&n);if(fsetxattr(f,"com.apple.decmpfs",b,n,0,0))fail("attribute");free(b);
        if(strcmp(argv[4],"-")){b=load(argv[4],&n);if(fsetxattr(f,"com.apple.ResourceFork",b,n,0,0))fail("fork");free(b);}
        if(fchflags(f,(unsigned int)strtoul(argv[6],NULL,0))||fsync(f)||close(f))fail("activate/close");
        if(!strcmp(argv[7],"edit")) {
            f=open(argv[2],O_RDWR|O_CLOEXEC);if(f<0)fail("reopen");
            if(pwrite(f,"WXYZ",4,0)!=4||fsync(f)||close(f))fail("edit");
        } else if(strcmp(argv[7],"keep"))return 2;
        return 0;
    }
    if(argc!=4||strcmp(argv[1],"observe"))return 2;
    int f=open(argv[2],O_RDONLY|O_CLOEXEC);if(f<0)fail("observe open");
    struct stat st;if(fstat(f,&st))fail("stat");
    printf("{\"flags\":%u,\"size\":%lld,\"mode\":%u",st.st_flags,(long long)st.st_size,st.st_mode);
    attribute(f,"com.apple.decmpfs",argv[3],"attr");attribute(f,"com.apple.ResourceFork",argv[3],"fork");
    unsigned char b[262144];size_t total=0;int error=0;
    for(;;){if(total==sizeof(b))exit(2);ssize_t n=read(f,b+total,sizeof(b)-total);if(n<0){error=errno;break;}if(n==0)break;total+=(size_t)n;}
    save(argv[3],"data",b,total);if(close(f))fail("close observation");
    printf(",\"read_errno\":%d,\"read_size\":%zu}\n",error,total);return 0;
}
