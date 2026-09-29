// Test-only unchanged copyfile_security oracle and real COPYFILE_ACL calls.
#include <sys/types.h>
#include <sys/acl.h>
#include <sys/kauth.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <copyfile.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static void fail(const char *s){perror(s);exit(2);}
static void print_acl(acl_t acl){
 if(!acl){printf("null");return;}ssize_t n=acl_size(acl);if(n<44)fail("ACL size");unsigned char *b=malloc((size_t)n);if(!b)fail("ACL allocation");if(acl_copy_ext(b,acl,n)!=n)fail("ACL export");printf("\"");for(ssize_t i=0;i<n;i++)printf("%02x",b[i]);printf("\"");free(b);
}
static acl_t load_acl(const char *path){
 if(!strcmp(path,"-"))return NULL;FILE *f=fopen(path,"rb");if(!f)fail("input open");unsigned char b[3117];size_t n=fread(b,1,sizeof(b),f);if(ferror(f)||fclose(f)||n<44||n>3116)fail("input size");acl_t acl=acl_copy_int(b);if(!acl)fail("ACL import");return acl;
}
static acl_t get_acl(filesec_t sec){acl_t acl=NULL;errno=0;if(filesec_get_property(sec,FILESEC_ACL,&acl)&&errno!=ENOENT)fail("ACL property");return acl;}
static acl_t destination_acl,captured_acl;
static int captures,writes;
static int model_stat(int fd,struct stat *st,filesec_t sec){(void)fd;memset(st,0,sizeof(*st));captures++;return destination_acl?filesec_set_property(sec,FILESEC_ACL,&destination_acl):0;}
static int model_chmod(int fd,filesec_t sec){(void)fd;writes++;captured_acl=get_acl(sec);return 0;}
// A private local object for the extracted function, never passed to libSystem.
struct _copyfile_state {copyfile_flags_t flags;filesec_t fsec;int src_fd,dst_fd;struct stat sb;unsigned internal_flags;const char *src,*dst;};
#define copyfile_debug(...) ((void)0)
#define copyfile_warn(...) ((void)0)
#define fstatx_np model_stat
#define fchmodx_np model_chmod
#include "acl-copy-source.h"
#undef fstatx_np
#undef fchmodx_np
static void snapshot(int fd,struct stat *st){
 filesec_t sec=filesec_init();if(!sec)fail("stat state");if(fstatx_np(fd,st,sec))fail("stat security");acl_t acl=get_acl(sec);printf("{\"ACL\":");print_acl(acl);printf(",\"UID\":%u,\"GID\":%u,\"Mode\":%u,\"Flags\":%u}",st->st_uid,st->st_gid,st->st_mode,st->st_flags);if(acl)acl_free(acl);filesec_free(sec);
}
static void check_payload(int fd,const char *want){char b[7]={0};if(pread(fd,b,sizeof(b),0)!=6||memcmp(b,want,6))fail("payload changed");}
static int create_target(const char *path,int directory,acl_t acl){
 if(directory&&mkdir(path,0700))fail("directory create");int fd=open(path,directory?O_RDONLY:(O_RDWR|O_CREAT|O_EXCL),0600);if(fd<0)fail("target open");if(acl&&acl_set_fd(fd,acl))fail("target ACL");if(fchmod(fd,0755))fail("target mode");return fd;
}
int main(int argc,char **argv){
 if(argc<4)return 2;acl_t src=load_acl(argv[2]),dst=load_acl(argv[3]);
 if(!strcmp(argv[1],"model")){
  filesec_t sec=filesec_init();if(!sec)fail("source state");if(src&&filesec_set_property(sec,FILESEC_ACL,&src))fail("source ACL");destination_acl=dst;
  struct _copyfile_state state={.flags=COPYFILE_ACL,.fsec=sec};errno=0;int rc=copyfile_security(&state),error=rc?errno:0;
  printf("{\"Code\":%d,\"Errno\":%d,\"Captures\":%d,\"Writes\":%d,\"ACL\":",rc,error,captures,writes);print_acl(captured_acl);printf(",\"SourceCache\":");acl_t cache=get_acl(sec);print_acl(cache);printf("}\n");if(cache)acl_free(cache);if(captured_acl)acl_free(captured_acl);filesec_free(sec);
 }else{
  if(argc!=5)return 2;int directory=!strcmp(argv[1],"directory");if(!directory&&strcmp(argv[1],"file"))return 2;
  char source[4096],target[4096];if(snprintf(source,sizeof(source),"%s/source",argv[4])>=(int)sizeof(source)||snprintf(target,sizeof(target),"%s/target",argv[4])>=(int)sizeof(target))return 2;
  int s=create_target(source,directory,src),d=create_target(target,directory,dst);struct stat sb,db,sa,da;int sp=s,dp=d;if(directory){sp=openat(s,"sentinel",O_RDWR|O_CREAT|O_EXCL,0600);dp=openat(d,"sentinel",O_RDWR|O_CREAT|O_EXCL,0600);if(sp<0||dp<0)fail("sentinel open");}if(write(sp,"source",6)!=6||write(dp,"target",6)!=6)fail("payload setup");
  struct statfs fs;if(fstatfs(d,&fs)||strcmp(fs.f_fstypename,"apfs"))fail("requires APFS copy targets");printf("{\"Filesystem\":\"%s\",\"SourceBefore\":",fs.f_fstypename);snapshot(s,&sb);printf(",\"Before\":");snapshot(d,&db);errno=0;int rc=fcopyfile(s,d,NULL,COPYFILE_ACL),error=rc?errno:0;
  printf(",\"Code\":%d,\"Errno\":%d,\"SourceAfter\":",rc,error);snapshot(s,&sa);printf(",\"After\":");snapshot(d,&da);
  check_payload(sp,"source");check_payload(dp,"target");if(directory&&(close(sp)||close(dp)))fail("sentinel close");
  printf(",\"IdentityUnchanged\":%s,\"PayloadUnchanged\":true}\n",sb.st_dev==sa.st_dev&&sb.st_ino==sa.st_ino&&db.st_dev==da.st_dev&&db.st_ino==da.st_ino?"true":"false");if(close(s)||close(d))fail("target close");
 }
 if(src)acl_free(src);if(dst)acl_free(dst);return 0;
}
