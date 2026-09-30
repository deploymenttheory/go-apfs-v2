// Native provider evidence only. No copyfile policy or xattr-name exception is
// implemented here: record each actual syscall result and independent readback.
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/xattr.h>
#include <sys/acl.h>
#include <membership.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
extern bool _xpc_runtime_is_app_sandboxed(void);
#include "xattr-provider-context.h"
static void hex(const unsigned char *p,ssize_t n){for(ssize_t i=0;i<n;i++)printf("%02x",p[i]);}
static void value(int fd,const char *name){
 errno=0;ssize_t size=fgetxattr(fd,name,NULL,0,0,0);int se=size<0?errno:0;
 if(size>1024*1024)exit(10);unsigned char *bytes=calloc(size>0?(size_t)size:1,1);if(!bytes)exit(11);
 ssize_t n=-1;int re=0;if(size>=0){errno=0;n=fgetxattr(fd,name,bytes,(size_t)size,0,0);re=n<0?errno:0;}if(n>size)exit(12);
 printf("{\"Size\":%lld,\"SizeErrno\":%d,\"Read\":%lld,\"ReadErrno\":%d,\"Hex\":\"",(long long)size,se,(long long)n,re);hex(bytes,n);printf("\"}");free(bytes);
}
static void ace(acl_t *acl,uuid_t principal,int elevated){
 acl_entry_t entry;acl_permset_t permissions;
 if(acl_create_entry(acl,&entry)||acl_set_tag_type(entry,ACL_EXTENDED_ALLOW)||acl_set_qualifier(entry,principal)||acl_get_permset(entry,&permissions))exit(13);
 if(elevated){acl_perm_t rights[]={ACL_WRITE_DATA,ACL_APPEND_DATA,ACL_WRITE_ATTRIBUTES,ACL_WRITE_EXTATTRIBUTES,ACL_WRITE_SECURITY,ACL_SYNCHRONIZE};for(unsigned i=0;i<sizeof(rights)/sizeof(rights[0]);i++)if(acl_add_perm(permissions,rights[i]))exit(14);}
 else if(acl_add_perm(permissions,ACL_READ_DATA))exit(15);
 if(acl_set_permset(entry,permissions))exit(16);
}
static void set_acl(int fd,int kind){
 if(!kind)return;acl_t acl=acl_init(kind);if(!acl)exit(17);
 if(kind==2){uuid_t owner;if(mbr_uid_to_uuid(getuid(),owner))exit(18);ace(&acl,owner,1);}
 uuid_t synthetic={1};ace(&acl,synthetic,0);if(acl_set_fd(fd,acl)||acl_free(acl))exit(19);
}
static void context(int fd){
 provider_context_json(fd);
}
int main(int argc,char **argv){
 if(argc!=7)return 2;int kind=atoi(argv[1]),directory=kind==1,link=kind>=2,mode=(int)strtol(argv[2],NULL,8),acl_kind=atoi(argv[3]),access=atoi(argv[4]),writing=!strcmp(argv[6],"write");
 char root[4096];if(snprintf(root,sizeof(root),"%s/remove-effects-XXXXXX",argv[5])>=(int)sizeof(root)||!mkdtemp(root))return 3;char path[4096];if(snprintf(path,sizeof(path),"%s/object",root)>=(int)sizeof(path))return 4;
 if(directory&&mkdir(path,0700))return 5;
 char target[4096];if(snprintf(target,sizeof(target),"%s/referent",root)>=(int)sizeof(target))return 28;
 if(kind==2){int t=open(target,O_CREAT|O_EXCL|O_RDWR,0600);if(t<0||write(t,"TARGET",6)!=6||close(t))return 29;}
 if(link&&symlink("referent",path))return 30;
 int seed=open(path,link?O_RDONLY|O_SYMLINK:directory?O_RDONLY:O_CREAT|O_EXCL|O_RDWR,0600);if(seed<0)return 6;
 if(fsetxattr(seed,"com.example.removable","owned",5,0,0))return 7;set_acl(seed,acl_kind);if(fchmod(seed,(mode_t)mode))return 8;
 errno=0;int fd=open(path,access|(link?O_SYMLINK:0));int oe=fd<0?errno:0;
 printf("{\"Operation\":\"%s\",\"Directory\":%s,\"Symlink\":%s,\"Dangling\":%s,\"RequestedMode\":%d,\"ACLKind\":%d,\"RequestedAccess\":%d,\"OpenErrno\":%d,\"BeforeContext\":",writing?"write":"remove",directory?"true":"false",link?"true":"false",kind==3?"true":"false",mode,acl_kind,access,oe);context(fd>=0?fd:seed);
 printf(",\"NamesHex\":\"");char names[1024*1024];ssize_t n=0;if(fd>=0){n=flistxattr(fd,names,sizeof(names),0);if(n<0)return 9;}hex((unsigned char *)names,n);printf("\",\"Operations\":[");
 int first=1;for(ssize_t at=0;at<n;){size_t length=strnlen(names+at,(size_t)(n-at));if(length==(size_t)(n-at))return 24;const char *name=names+at;
  if(!first)putchar(',');first=0;printf("{\"NameHex\":\"");hex((const unsigned char *)name,(ssize_t)length);printf("\",\"Before\":");value(fd,name);
  printf(",\"InputHex\":\"");if(writing)hex((const unsigned char *)"replacement",11);printf("\"");
  errno=0;int result=writing?fsetxattr(fd,name,"replacement",11,0,0):fremovexattr(fd,name,0);int re=result<0?errno:0;printf(",\"Code\":%d,\"Errno\":%d,\"After\":",result,re);value(fd,name);putchar('}');at+=(ssize_t)length+1;
 }
 printf("],\"AfterContext\":");context(fd>=0?fd:seed);
 if(fd>=0&&close(fd))return 25;if(fchmod(seed,0700)||close(seed))return 26;
 if(kind==2){int t=open(target,O_RDONLY);char bytes[7]={0};if(t<0||read(t,bytes,7)!=6||memcmp(bytes,"TARGET",6)||close(t)||unlink(target))return 31;}
 if(kind==3){struct stat absent;errno=0;if(lstat(target,&absent)==0||errno!=ENOENT)return 32;}
 if((directory?rmdir(path):unlink(path))||rmdir(root))return 27;
 puts(",\"CleanupVerified\":true}");return 0;
}
