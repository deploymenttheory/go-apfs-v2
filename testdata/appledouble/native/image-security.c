// Test-only no-follow source acquisition, public libSystem versus unchanged statx1.
#define main security_copy_reference_main
#include "security-copy.c"
#undef main
#define ACL_MIN_SIZE_HEURISTIC KAUTH_FILESEC_SIZE(16)
extern int __lstat64_extended(const char *,struct stat *,void *,size_t *);
#include "image-statx-source.h"
typedef const uint16_t *ConstUniCharArrayPtr;
typedef uint32_t ItemCount;
#include "image-fold-source.h"
#include <sys/xattr.h>
int main(int argc,char **argv){
 if(argc==4&&!strcmp(argv[1],"--xattr")){unsigned char data[65536];errno=0;ssize_t n=getxattr(argv[2],argv[3],data,sizeof(data),0,XATTR_NOFOLLOW);int e=n<0?errno:0;printf("{\"Length\":%zd,\"Errno\":%d,\"Value\":",n,e);if(n<0)printf("null");else hex(data,(size_t)n);printf("}\n");return 0;}
 uint16_t nul[]={0},last[]={0xffff},ascii[]={'z'};
 if(FastUnicodeCompare(nul,1,last,1)!=0||FastUnicodeCompare(nul,1,ascii,1)!=1)fail("native NUL collation");
 if(argc!=2)return 2;filesec_t public=filesec_init(),reference=filesec_init();if(!public||!reference)fail("source filesec");struct stat a,b;
 errno=0;int rc=lstatx_np(argv[1],&a,public),error=rc?errno:0;printf("{\"Code\":%d,\"Errno\":%d",rc,error);
 const char *path=argv[1];errno=0;int compare=statx1(&path,lstatx_syscall,&b,reference),other=compare?errno:0;
 printf(",\"ReferenceCode\":%d,\"ReferenceErrno\":%d",compare,other);
 if(!rc){printf(",\"Properties\":");print_properties(public);printf(",\"UID\":%u,\"GID\":%u,\"Mode\":%u,\"Flags\":%u,\"Inode\":%llu",a.st_uid,a.st_gid,a.st_mode,a.st_flags,(unsigned long long)a.st_ino);}
 if(!rc){printf(",\"Times\":[%lld,%lld,%lld,%lld]",(long long)a.st_birthtimespec.tv_sec*1000000000+a.st_birthtimespec.tv_nsec,(long long)a.st_mtimespec.tv_sec*1000000000+a.st_mtimespec.tv_nsec,(long long)a.st_ctimespec.tv_sec*1000000000+a.st_ctimespec.tv_nsec,(long long)a.st_atimespec.tv_sec*1000000000+a.st_atimespec.tv_nsec);}
 if(!compare){printf(",\"ReferenceProperties\":");print_properties(reference);printf(",\"SameIdentity\":%s",!rc&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino?"true":"false");}
 printf("}\n");filesec_free(public);filesec_free(reference);return 0;
}
