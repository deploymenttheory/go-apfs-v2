// Qualification only: unchanged Apple unpack-xattr and intent-policy functions.
#include <copyfile.h>
#include <sys/types.h>
#include <sys/xattr.h>
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
static int sandboxed,write_error,actions[3],calls,live_fd=-1;
static int _xpc_runtime_is_app_sandboxed(void){return sandboxed;}
// Each model represents an independently captured process context. Reinitialize
// the unchanged function's cached table for each controlled process model.
static void model_once(dispatch_once_t *token,void (^block)(void)){(void)token;block();}
#undef dispatch_once
#define dispatch_once model_once
#include "xattr-policy-source.h"
#undef dispatch_once
struct _copyfile_state {
 unsigned copyIntent,flags; int dst_fd,err; const char *src,*dst;
 char *xattr_name; void *ctx; off_t totalCopied;
 copyfile_callback_t statuscb;
};
typedef struct {uint32_t length;char name[512];} attr_entry_t;
#define XATTR_ROOT_INSTALLED_NAME "com.apple.root.installed"
#define copyfile_warn(...) ((void)0)
static void event(const char *kind,const char *name,int code,long long copied){
 if(calls++)printf(",");printf("{\"Kind\":\"%s\",\"Name\":\"%s\",\"Code\":%d,\"Copied\":%lld}",kind,name,code,copied);
}
static int model_set(int fd,const char *name,const void *data,size_t size,uint32_t position,int flags){
 if(fd!=10 || position || flags)exit(3);
 int rc;
 if(live_fd>=0)rc=fsetxattr(live_fd,name,data,size,0,0);
 else {errno=write_error;rc=write_error?-1:0;}
 int saved=errno;event("write",name,rc?errno:0,0);errno=saved;return rc;
}
static int callback(int what,int when,copyfile_state_t s,const char *src,const char *dst,void *ctx){
 if(what!=COPYFILE_COPY_XATTR || s->src!=src || s->dst!=dst || s->ctx!=ctx)exit(3);
 int i=when==COPYFILE_START?0:when==COPYFILE_ERR?1:2;
 event(i==0?"start":i==1?"error":"finish",s->xattr_name,actions[i],s->totalCopied);
 return actions[i];
}
#define fsetxattr model_set
#include "xattr-restore-source.h"
#undef fsetxattr
int main(int argc,char **argv){
 if(argc==2){live_fd=open(argv[1],O_CREAT|O_RDWR|O_TRUNC,0600);if(live_fd<0)return 2;}
 unsigned intent;int length,cb;long long initial;char name[512];
 while(scanf("%511s %u %d %d %d %d %d %d %d %lld",name,&intent,&sandboxed,&write_error,&cb,&actions[0],&actions[1],&actions[2],&length,&initial)==10){
  if(length<0 || length>256)return 2;
  unsigned char value[256];for(int i=0;i<length;i++)value[i]=(unsigned char)i;
  if(live_fd>=0){(void)fremovexattr(live_fd,name,0);errno=0;}
  struct _copyfile_state s={.copyIntent=intent,.dst_fd=10,.totalCopied=initial,.statuscb=cb?callback:NULL};
  attr_entry_t a={.length=(uint32_t)length};strcpy(a.name,name);
  calls=0;errno=0;printf("{\"Events\":[");int rc=copyfile_unpack_xattr(&s,&a,value);int saved=errno;
  printf("],\"Code\":%d,\"StateError\":%d,\"Errno\":%d,\"Copied\":%lld,\"CallbackCleared\":%s",rc,s.err,saved,(long long)s.totalCopied,s.xattr_name?"false":"true");
  if(live_fd>=0){unsigned char out[256];ssize_t n=fgetxattr(live_fd,name,out,sizeof(out),0,0);printf(",\"Stored\":\"");if(n>=0){for(ssize_t i=0;i<n;i++)printf("%02x",out[i]);}printf("\",\"Present\":%s",n>=0?"true":"false");}
  printf("}\n");
 }
 if(live_fd>=0 && close(live_fd))return 2;return ferror(stdin)?2:0;
}
