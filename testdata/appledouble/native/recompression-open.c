// Independent kernel read/write acquisition of supplied compression storage.
// This probe never asks AppleFSCompression or the Go decoder to open the data.
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void fail(const char *what){perror(what);exit(2);}
static void hex(const unsigned char *p,size_t n){putchar('"');for(size_t i=0;i<n;i++)printf("%02x",p[i]);putchar('"');}
static unsigned char *load(const char *path,size_t *length){FILE *f=fopen(path,"rb");if(!f)fail("input");if(fseek(f,0,SEEK_END))fail("seek");long n=ftell(f);if(n<0||n>1048576)fail("input extent");rewind(f);unsigned char *p=malloc((size_t)n+1);if(!p||fread(p,1,(size_t)n,f)!=(size_t)n||fclose(f))fail("input read");*length=(size_t)n;return p;}
static void snapshot(const char *path){struct stat s;if(stat(path,&s))fail("stat");printf("{\"flags\":%u,\"size\":%lld,\"attribute\":",s.st_flags,(long long)s.st_size);const char *names[]={"com.apple.decmpfs","com.apple.ResourceFork"};for(int i=0;i<2;i++){if(i)printf(",\"fork\":");errno=0;ssize_t n=getxattr(path,names[i],NULL,0,0,XATTR_SHOWCOMPRESSION);if(n<0){if(errno!=ENOATTR)fail("xattr size");printf("null");continue;}if(n>1048576)fail("xattr bound");unsigned char *p=malloc((size_t)n+1);if(!p||getxattr(path,names[i],p,(size_t)n,0,XATTR_SHOWCOMPRESSION)!=n)fail("xattr");hex(p,(size_t)n);free(p);}printf("}");}
int main(int argc,char **argv){if(argc!=4)return 2;const char *attribute=argv[1],*fork=argv[2],*path=argv[3];int fd=open(path,O_CREAT|O_EXCL|O_RDWR,0600);if(fd<0||close(fd))fail("create");size_t n;unsigned char *p=load(attribute,&n);if(setxattr(path,"com.apple.decmpfs",p,n,0,0))fail("attribute install");free(p);if(strcmp(fork,"-")){p=load(fork,&n);if(setxattr(path,"com.apple.ResourceFork",p,n,0,0))fail("fork install");free(p);}if(chflags(path,UF_COMPRESSED))fail("activate");printf("{\"before\":");snapshot(path);errno=0;fd=open(path,O_RDWR);int open_error=fd<0?errno:0;printf(",\"open_errno\":%d,\"after_open\":",open_error);snapshot(path);printf(",\"data\":");int read_error=0;if(fd<0)printf("null");else{p=malloc(1048577);if(!p)fail("read allocation");size_t total=0;while(total<1048577){ssize_t got=pread(fd,p+total,1048577-total,(off_t)total);if(got<0){read_error=errno;break;}if(!got)break;total+=(size_t)got;}if(total>1048576)fail("logical growth");hex(p,total);free(p);if(close(fd))fail("close");}printf(",\"read_errno\":%d,\"after_close\":",read_error);snapshot(path);printf("}\n");if(chflags(path,0)||unlink(path))fail("cleanup");return 0;}
