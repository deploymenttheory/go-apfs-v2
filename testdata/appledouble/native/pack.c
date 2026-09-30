// Qualification only. The included Apple function bodies remain unchanged.
#include <copyfile.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/acl.h>
#include <libkern/OSByteOrder.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define ADH_MAGIC 0x00051607
#define ADH_VERSION 0x00020000
#define ADH_MACOSX "Mac OS X        "
#define AD_FINDERINFO 9
#define AD_RESOURCE 2
#define ATTR_HDR_MAGIC 0x41545452
#define ATTR_MAX_HDR_SIZE (65536+18)
#define XATTR_MAXATTRLEN (16*1024*1024)
#define XATTR_QUARANTINE_NAME "com.apple.quarantine"
#define copyfile_debug(...) ((void)0)
#define copyfile_warn(...) ((void)0)
#include "unpack-layout-source.h"
struct _copyfile_state {
 unsigned copyIntent, flags; int src_fd,dst_fd,err;
 void *fsec,*qinfo,*ctx; const char *src,*dst; char *xattr_name;
 off_t totalCopied; copyfile_callback_t statuscb;
};
static int scenario,list_error,query_kind,query_error,read_kind,read_delta,write_fail,write_short,callback_on,actions[4],acl_present,q_present,intent,filtered,stat_code;
static long long ordinary_size,fork_size;
static int events,writes,output_fd;
static void event(const char *kind,const char *name,long long count,long long offset,int code,long long copied){
 if(events++)printf(",");printf("{\"Kind\":\"%s\",\"Name\":\"%s\",\"Count\":%lld,\"Offset\":%lld,\"Code\":%d,\"Copied\":%lld}",kind,name?name:"",count,offset,code,copied);
}
static int native_kind(const char *name){return strcmp(name,XATTR_FINDERINFO_NAME)==0?2:strcmp(name,XATTR_RESOURCEFORK_NAME)==0?3:1;}
static const char *names(size_t *length){
 static const char ordinary[]="user.z\0user.a\0";
 static const char finder[]="com.apple.FinderInfo\0";
 static const char fork[]="com.apple.ResourceFork\0";
 static const char all[]="user.z\0com.apple.ResourceFork\0com.apple.FinderInfo\0user.a\0";
 static const char quarantine[]="com.apple.quarantine\0";
 static const char filter[]="skip#N\0user.a\0";
 const char *b="";*length=0;
 switch(scenario){
 case 1:case 7:b=ordinary;*length=sizeof(ordinary)-1;break;
 case 2:b=finder;*length=sizeof(finder)-1;break;
 case 3:b=fork;*length=sizeof(fork)-1;break;
 case 4:b=all;*length=sizeof(all)-1;break;
 case 6:b=quarantine;*length=sizeof(quarantine)-1;break;
 case 8:b=filter;*length=sizeof(filter)-1;break;
 }
 return b;
}
static ssize_t model_list(int fd,char *b,size_t capacity,int flags){
 if(fd!=10||flags)exit(3);size_t n;const char *v=names(&n);
 event("list","",capacity,0,list_error,0);
 if(list_error){errno=list_error;return -1;}if(n>capacity)exit(3);memcpy(b,v,n);return (ssize_t)n;
}
static ssize_t model_get(int fd,const char *name,void *b,size_t capacity,uint32_t pos,int flags){
 if(fd!=10||pos||flags)exit(3);int k=native_kind(name);long long n=k==2?32:k==3?fork_size:ordinary_size;
 if(!b){int e=query_kind==k?query_error:0;event("size",name,n,0,e,0);if(e){errno=e;return -1;}return (ssize_t)n;}
 if(read_kind==k)n+=read_delta;
 if(n<0){event("read",name,capacity,0,EIO,0);errno=EIO;return -1;}
 if((unsigned long long)n>capacity){event("read",name,capacity,0,ERANGE,0);errno=ERANGE;return -1;}
 unsigned char *p=b;for(long long i=0;i<n;i++)p[i]=(unsigned char)('A'+i%7);
 event("read",name,capacity,0,(int)n,0);return (ssize_t)n;
}
static ssize_t model_write(int fd,const void *b,size_t n,off_t offset){
 if(fd!=11)exit(3);writes++;int e=writes==write_fail?EIO:0;size_t wanted=n;
 if(writes==write_short&&n)n--;
 event("write","",wanted,offset,e? -1:(int)n,0);
 if(e){errno=e;return -1;}return pwrite(output_fd,b,n,offset);
}
static int model_property(void *fsec,filesec_property_t property,void *value){
 (void)fsec;if(property!=FILESEC_ACL)exit(3);event("acl-probe","",0,0,acl_present>0?0:ENOENT,0);
 if(acl_present<=0){errno=ENOENT;return -1;}*(acl_t*)value=(acl_t)(uintptr_t)1;return 0;
}
static int model_free(void *value){(void)value;return 0;}
static int model_intent(const char *name,unsigned which){event("intent",name,which,0,filtered&&strcmp(name,"skip#N")==0?0:1,0);return !(filtered&&strcmp(name,"skip#N")==0);}
static int callback(int what,int when,copyfile_state_t s,const char *src,const char *dst,void *ctx){
 if(what!=COPYFILE_COPY_XATTR||src!=s->src||dst!=s->dst||ctx!=s->ctx)exit(3);
 int i=when==COPYFILE_START?0:when==COPYFILE_PROGRESS?1:when==COPYFILE_FINISH?2:3;
 const char *kind=i==0?"start":i==1?"progress":i==2?"finish":"error";
 event(kind,s->xattr_name,0,0,actions[i],s->totalCopied);return actions[i];
}
static int copyfile_pack_acl(copyfile_state_t s,void **b,ssize_t *n){(void)s;*n=4;*b=malloc(4);memcpy(*b,"acl",4);event("acl","",4,0,0,0);return 0;}
static int copyfile_pack_quarantine(copyfile_state_t s,void **b,ssize_t *n){(void)s;*n=4;*b=malloc(4);memcpy(*b,"q/01",4);event("quarantine","",4,0,0,0);return 0;}
static int copyfile_stat(copyfile_state_t s){(void)s;event("stat","",0,0,stat_code,0);return stat_code;}
#include "pack-sort-source.h"
#define flistxattr model_list
#define fgetxattr model_get
#define pwrite model_write
#define filesec_get_property model_property
#define acl_free model_free
#define xattr_preserve_for_intent model_intent
#include "pack-source.h"
#undef pwrite
int main(int argc,char **argv){
 if(argc!=2)return 2;int index=0;
 while(scanf("%d %lld %lld %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",&scenario,&ordinary_size,&fork_size,&list_error,&query_kind,&query_error,&read_kind,&read_delta,&write_fail,&write_short,&callback_on,&actions[0],&actions[1],&actions[2],&actions[3],&acl_present,&q_present,&intent,&filtered,&stat_code)==20){
  char path[2048];snprintf(path,sizeof(path),"%s/%d.ad",argv[1],index++);output_fd=open(path,O_CREAT|O_TRUNC|O_RDWR,0600);if(output_fd<0)return 2;
  struct _copyfile_state s={.src_fd=10,.dst_fd=11,.flags=COPYFILE_XATTR|(acl_present?COPYFILE_ACL:0),.totalCopied=77,.copyIntent=(unsigned)intent,.qinfo=q_present?&q_present:NULL,.statuscb=callback_on?callback:NULL};
  events=writes=0;errno=0;printf("{\"Events\":[");int rc=copyfile_pack(&s);printf("],\"Code\":%d,\"StateError\":%d,\"Copied\":%lld,\"CallbackCleared\":%s}\n",rc,s.err,(long long)s.totalCopied,s.xattr_name?"false":"true");if(close(output_fd))return 2;
 }
 return ferror(stdin)?2:0;
}
