// Qualification only. All extracted Apple functions remain unchanged.
#include <copyfile.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/attr.h>
#include <libkern/OSByteOrder.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "xattr_flags.h"
static int _xpc_runtime_is_app_sandboxed(void){return 0;}
#include "xattr-policy-source.h"
#define ADH_MAGIC 0x00051607
#define ADH_VERSION 0x00020000
#define AD_FINDERINFO 9
#define AD_RESOURCE 2
#define ATTR_HDR_MAGIC 0x41545452
#define ATTR_MAX_HDR_SIZE (65536+18)
#define cfMakeFileInvisible 1
#define XATTR_QUARANTINE_NAME "com.apple.quarantine"
#define XATTR_ROOT_INSTALLED_NAME "com.apple.root.installed"
#define copyfile_debug(...) ((void)0)
#define copyfile_warn(...) ((void)0)
#include "unpack-layout-source.h"
struct _copyfile_state {
 unsigned copyIntent,flags,internal_flags; int src_fd,dst_fd,err;
 struct stat sb; const char *src,*dst; char *xattr_name; void *ctx;
 off_t totalCopied; copyfile_callback_t statuscb;
};
static int listmode,remove_error,write_errors[4],stat_error,times_error,qcode,acode,scode,actions[3],target,directory,ordinary,calls,verified,allocated,live_fd=-1;
static void event(const char *kind,const char *name,int code,long long copied,const void *data,size_t length){
 if(calls++)printf(",");printf("{\"Kind\":\"%s\",\"Name\":\"%s\",\"Code\":%d,\"Copied\":%lld,\"Value\":\"",kind,name,code,copied);
 const unsigned char *b=data;for(size_t i=0;i<length;i++)printf("%02x",b[i]);printf("\"}");
}
static ssize_t model_list(int fd,char *b,size_t n,int flags){
 if(fd!=10||flags)exit(3);int e=0;ssize_t count=0;
 if(live_fd>=0){count=flistxattr(live_fd,b,n,0);if(count<0)e=errno;}
 else if(!b){e=listmode==2?EPERM:listmode==3?ENOTSUP:listmode==4?EIO:0;count=listmode?23:0;}
 else {e=listmode==5?ERANGE:0;count=listmode==6?0:23;if(n<23)exit(3);memcpy(b,"user.stale\0user.failed\0",23);}
 if(e)count=-1;event(b?"list-names":"list-size","",e,count,b&&count>0?b:NULL,b&&count>0?(size_t)count:0);errno=e;return count;
}
static int model_remove(int fd,const char *name,int flags){
 if(fd!=10||flags)exit(3);int e=strcmp(name,"user.failed")==0?remove_error:0;
 if(live_fd>=0)e=fremovexattr(live_fd,name,0)?errno:0;
 event("remove",name,e,0,NULL,0);errno=e;return e?-1:0;
}
static int kind(const char *name){return ordinary?1:strcmp(name,XATTR_FINDERINFO_NAME)==0?2:3;}
static int model_set(int fd,const char *name,const void *b,size_t n,uint32_t pos,int flags){
 if(fd!=10||pos||flags)exit(3);int k=kind(name),e=write_errors[k];
 if(live_fd>=0){e=fsetxattr(live_fd,name,b,n,0,0)?errno:0;if(!e){unsigned char out[512];ssize_t got=fgetxattr(live_fd,name,out,sizeof(out),0,0);if(got!=(ssize_t)n||memcmp(out,b,n))exit(4);verified++;}}
 event(k==1?"ordinary":k==2?"finder-info":"resource-fork",name,e,0,b,n);errno=e;return e?-1:0;
}
static int model_stat(int fd,struct stat *s){
 if(fd!=10)exit(3);int e=stat_error;
 if(live_fd>=0)e=fstat(live_fd,s)?errno:0;
 else {memset(s,0,sizeof(*s));s->st_mode=directory?S_IFDIR:S_IFREG;s->st_mtimespec.tv_sec=123;s->st_atimespec.tv_sec=456;}
 event("fork-stat","",e,0,NULL,0);errno=e;return e?-1:0;
}
static int model_times(int fd,struct attrlist *a,void *b,size_t n,unsigned long flags){
 if(fd!=10||a->commonattr!=(ATTR_CMN_MODTIME|ATTR_CMN_ACCTIME)||flags||n!=2*sizeof(struct timespec))exit(3);int e=times_error;
 if(live_fd>=0)e=fsetattrlist(live_fd,a,b,n,flags)?errno:0;
 event("fork-times","",e,0,NULL,0);errno=e;return e?-1:0;
}
static int callback(int what,int when,copyfile_state_t s,const char *src,const char *dst,void *ctx){
 if(what!=COPYFILE_COPY_XATTR||s->src!=src||s->dst!=dst||s->ctx!=ctx)exit(3);
 int k=kind(s->xattr_name),i=when==COPYFILE_START?0:when==COPYFILE_ERR?1:2;
 int action=(!target||target==k)?actions[i]:COPYFILE_CONTINUE;
 char label[40];snprintf(label,sizeof(label),"%s-%s",k==1?"ordinary":k==2?"finder-info":"resource-fork",i==0?"start":i==1?"error":"finish");
 event(label,s->xattr_name,action,s->totalCopied,NULL,0);return action;
}
static int copyfile_unpack_quarantine(copyfile_state_t s,attr_entry_t *a,void *data){(void)s;event("quarantine","",qcode,0,data,a->length);return qcode;}
static int copyfile_unpack_acl(copyfile_state_t s,uint32_t n,void *data){(void)s;event("acl","",acode,0,data,n);return acode;}
static int copyfile_stat(copyfile_state_t s){event("stat","",scode,s->internal_flags&cfMakeFileInvisible?1:0,NULL,0);return scode;}
static void *model_malloc(size_t n){if(!allocated++ && listmode==7 && live_fd<0){event("list-allocation","",ENOMEM,0,NULL,0);errno=ENOMEM;return NULL;}return malloc(n);}
#define fsetxattr model_set
#include "xattr-restore-source.h"
static int ordinary_xattr(copyfile_state_t s,attr_entry_t *a,void *b){ordinary=1;int rc=copyfile_unpack_xattr(s,a,b);ordinary=0;return rc;}
#define copyfile_unpack_xattr ordinary_xattr
#define flistxattr model_list
#define fremovexattr model_remove
#define fstat model_stat
#define fsetattrlist model_times
#define malloc model_malloc
#include "unpack-source.h"
#undef malloc
#undef fsetxattr
#undef flistxattr
#undef fremovexattr
#undef fstat
#undef fsetattrlist
int main(int argc,char **argv){
 if(argc!=2&&argc!=3)return 2;int img,stat_flag,cb;unsigned intent;int index=0;
 while(scanf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %u",&img,&listmode,&remove_error,&write_errors[1],&write_errors[2],&write_errors[3],&stat_error,&times_error,&qcode,&acode,&scode,&stat_flag,&cb,&actions[0],&actions[1],&actions[2],&target,&directory,&intent)==19){
  char path[2048];snprintf(path,sizeof(path),"%s/%d.ad",argv[1],img);int fd=open(path,O_RDONLY);if(fd<0)return 2;
  struct _copyfile_state s={.src_fd=fd,.dst_fd=10,.flags=stat_flag?COPYFILE_STAT:0,.totalCopied=77,.copyIntent=intent,.statuscb=cb?callback:NULL};if(fstat(fd,&s.sb))return 2;
  char dst[2048];if(argc==3){snprintf(dst,sizeof(dst),"%s/%d",argv[2],index++);if(directory&&mkdir(dst,0700))return 2;live_fd=open(dst,O_RDONLY|(directory?0:O_CREAT),0600);if(live_fd<0)return 2;if(fsetxattr(live_fd,"user.stale","a",1,0,0)||fsetxattr(live_fd,"user.failed","b",1,0,0))return 2;}
  calls=0;verified=0;allocated=0;errno=0;printf("{\"Events\":[");int rc=copyfile_unpack(&s);if(live_fd>=0){char out[8];if(fgetxattr(live_fd,"user.stale",out,sizeof(out),0,0)>=0||errno!=ENOATTR)return 4;if(fgetxattr(live_fd,"user.failed",out,sizeof(out),0,0)>=0||errno!=ENOATTR)return 4;}
  printf("],\"Code\":%d,\"StateError\":%d,\"Copied\":%lld,\"Invisible\":%s,\"CallbackCleared\":%s,\"VerifiedWrites\":%d,\"RemovedSeeds\":%s}",rc,s.err,(long long)s.totalCopied,s.internal_flags&cfMakeFileInvisible?"true":"false",s.xattr_name?"false":"true",verified,live_fd>=0?"true":"false");printf("\n");close(fd);
  if(live_fd>=0){close(live_fd);live_fd=-1;if(directory?rmdir(dst):unlink(dst))return 2;}
 }
 return ferror(stdin)?2:0;
}
