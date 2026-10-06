// Research-only native held-file checkpoints; no Go production code is called.
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>
static void fail(const char *s) { perror(s); exit(2); }
static void hex(const unsigned char *p, size_t n) { putchar('"'); for(size_t i=0;i<n;i++) printf("%02x",p[i]); putchar('"'); }
static void snap(int fd) {
 struct stat s; struct statfs v; if(fstat(fd,&s)||fstatfs(fd,&v))fail("snapshot");
 printf("{\"dev\":%lld,\"inode\":%llu,\"links\":%u,\"size\":%lld,\"mode\":%u,\"flags\":%u,\"filesystem\":\"%s\",\"mount_flags\":%u,\"mtime\":[%lld,%ld],\"atime\":[%lld,%ld],\"ctime\":[%lld,%ld],\"birth\":[%lld,%ld],\"attribute\":",(long long)s.st_dev,(unsigned long long)s.st_ino,s.st_nlink,(long long)s.st_size,s.st_mode,s.st_flags,v.f_fstypename,v.f_flags,(long long)s.st_mtimespec.tv_sec,s.st_mtimespec.tv_nsec,(long long)s.st_atimespec.tv_sec,s.st_atimespec.tv_nsec,(long long)s.st_ctimespec.tv_sec,s.st_ctimespec.tv_nsec,(long long)s.st_birthtimespec.tv_sec,s.st_birthtimespec.tv_nsec);
 unsigned char b[8192]; ssize_t n=fgetxattr(fd,"com.apple.decmpfs",b,sizeof(b),0,XATTR_SHOWCOMPRESSION); if(n<0){if(errno!=ENOATTR)fail("attribute");printf("null");}else hex(b,(size_t)n); printf("}");
}
static void create(int root, int compressed) {
 int f=openat(root,"file",O_CREAT|O_EXCL|O_RDWR,0644);if(f<0)fail("create");
 unsigned char plain[32768];for(size_t i=0;i<sizeof(plain);i++)plain[i]=(unsigned char)('A'+i%23);
 if(compressed){unsigned char storage[8192]={0x66,0x70,0x6d,0x63,3,0,0,0,0,128,0,0,0,0,0,0};uLongf n=sizeof(storage)-16;if(compress2(storage+16,&n,plain,sizeof(plain),Z_DEFAULT_COMPRESSION)!=Z_OK)fail("compress");if(fsetxattr(f,"com.apple.decmpfs",storage,n+16,0,0))fail("activate");if(compressed==1&&fchflags(f,UF_COMPRESSED))fail("compression flag");if(compressed==2&&write(f,plain,sizeof(plain))!=(ssize_t)sizeof(plain))fail("inactive payload");}
 else if(write(f,plain,sizeof(plain))!=(ssize_t)sizeof(plain))fail("write");
 struct timeval ts[2]={{1550000000,123456},{1600000000,654321}};if(futimes(f,ts)||close(f))fail("setup times/close");
}
int main(int argc,char **argv){
 if(argc!=5)return 2;const char *dir=argv[1],*route=argv[2],*mutation=argv[3];int compressed=atoi(argv[4]);
 int rootMoved=0,leafMoved=0;if(mkdir(dir,0700))fail("mkdir");int root=open(dir,O_RDONLY|O_DIRECTORY);if(root<0)fail("root");create(root,compressed);
 int observer=openat(root,"file",O_RDONLY);if(observer<0)fail("observer");printf("{\"route\":\"%s\",\"mutation\":\"%s\",\"compressed\":%d,\"before\":",route,mutation,compressed);snap(observer);
 char original[4096],moved[4096];if(snprintf(original,sizeof(original),"%s/file",dir)>=(int)sizeof(original)||snprintf(moved,sizeof(moved),"%s-renamed",dir)>=(int)sizeof(moved))return 2;
 if(!strcmp(mutation,"root-before")){if(rename(dir,moved))fail("rename root");rootMoved=1;}
 errno=0;int input=!strcmp(route,"root")?openat(root,"file",O_RDWR):open(original,O_RDWR);int error=input<0?errno:0;printf(",\"open_errno\":%d,\"after_open\":",error);snap(observer);
 if(input>=0){
  if(!strcmp(mutation,"leaf-after")){if(renameat(root,"file",root,"moved"))fail("rename leaf");leafMoved=1;}
  if(!strcmp(mutation,"root-after")){if(rename(dir,moved))fail("rename held root");rootMoved=1;}
  int copy=fcntl(input,F_DUPFD_CLOEXEC,0);if(copy<0)fail("duplicate");printf(",\"after_duplicate\":");snap(copy);
  errno=0;ssize_t n=write(input,"",0);printf(",\"zero_write_errno\":%d,\"after_zero_write\":",n<0?errno:0);snap(copy);
  unsigned char b[32769];n=pread(copy,b,sizeof(b),0);if(n<0)fail("read");printf(",\"data\":");hex(b,(size_t)n);
  if(close(copy)||close(input))fail("close input");
 }
 printf(",\"after_close\":");snap(observer);printf("}\n");if(close(observer)||unlinkat(root,leafMoved?"moved":"file",0)||close(root))fail("cleanup");
 if(rmdir(rootMoved?moved:dir))fail("rmdir");return 0;
}
