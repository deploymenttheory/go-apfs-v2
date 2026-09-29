// Test-only complete copyfile_security oracle, controlled faults and live calls.
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
#include "acl-chmod-source.h"
extern int __fchmod_extended(int,uid_t,gid_t,int,kauth_filesec_t);
static void fail(const char *s){perror(s);exit(2);}
static void hex(const void *data,size_t n){const unsigned char *p=data;printf("\"");for(size_t i=0;i<n;i++)printf("%02x",p[i]);printf("\"");}
static void *unhex(const char *s,size_t *n){*n=strlen(s)/2;if(strlen(s)%2||*n>3116)fail("hex size");unsigned char *p=calloc(*n+1,1);if(!p)fail("hex allocate");for(size_t i=0;i<*n;i++){unsigned v;if(sscanf(s+2*i,"%2x",&v)!=1)fail("hex parse");p[i]=(unsigned char)v;}return p;}
static acl_t load_acl(const char *path){if(!strcmp(path,"-"))return NULL;FILE *f=fopen(path,"rb");unsigned char b[3117];if(!f)fail("ACL open");size_t n=fread(b,1,sizeof(b),f);if(ferror(f)||fclose(f)||n<44||n>3116)fail("ACL input");acl_t a=acl_copy_int(b);if(!a)fail("ACL import");return a;}
static acl_t get_acl(filesec_t f){acl_t a=NULL;if(filesec_get_property(f,FILESEC_ACL,&a)&&errno!=ENOENT)fail("get ACL");return a;}
static void print_acl(acl_t a){if(!a){printf("null");return;}ssize_t n=acl_size(a);unsigned char b[3116];if(n<44||n>3116||acl_copy_ext(b,a,n)!=n)fail("export ACL");hex(b,(size_t)n);}
static void print_properties(filesec_t f){
 uid_t uid;gid_t gid;mode_t mode;unsigned char uuid[16];void *raw=NULL;size_t n=0;
 printf("{\"UID\":");if(!filesec_get_property(f,FILESEC_OWNER,&uid))printf("%u",uid);else if(errno==ENOENT)printf("null");else fail("UID");
 printf(",\"GID\":");if(!filesec_get_property(f,FILESEC_GROUP,&gid))printf("%u",gid);else if(errno==ENOENT)printf("null");else fail("GID");
 printf(",\"Mode\":");if(!filesec_get_property(f,FILESEC_MODE,&mode))printf("%u",mode);else if(errno==ENOENT)printf("null");else fail("mode");
 printf(",\"OwnerUUID\":");if(!filesec_get_property(f,FILESEC_UUID,uuid))hex(uuid,16);else if(errno==ENOENT)printf("null");else fail("owner");
 printf(",\"GroupUUID\":");if(!filesec_get_property(f,FILESEC_GRPUUID,uuid))hex(uuid,16);else if(errno==ENOENT)printf("null");else fail("group");
 printf(",\"RawSecurity\":");if(!filesec_get_property(f,FILESEC_ACL_RAW,&raw)){if(filesec_get_property(f,FILESEC_ACL_ALLOCSIZE,&n)||n<44||n>3116)fail("raw size");hex(raw,n);}else if(errno==ENOENT)printf("null");else fail("raw");printf("}");
}
static int live,filter,fault,calls;static acl_t target_acl;
static int forced(int op){if(fault==1&&op==0)return EIO;if(fault==2&&op==1)return EPERM;if(fault==3)return EIO;if(fault==4&&op==2)return EACCES;if(fault==5){if(op==1||op==4)return ENOTSUP;if(op==3)return EPERM;}return 0;}
static void event(const char *name){if(calls++)printf(",");printf("{\"Operation\":\"%s\"",name);}
static int finish(int rc){int error=rc?errno:0;printf(",\"Code\":%d,\"Errno\":%d}",rc,error);errno=error;return rc;}
static int capture(int fd,struct stat *st,filesec_t f){event("capture");int e=forced(0),rc;if(live)rc=fstatx_np(fd,st,f);else if(e){errno=e;rc=-1;}else{memset(st,0,sizeof(*st));rc=target_acl?filesec_set_property(f,FILESEC_ACL,&target_acl):0;}int error=errno;printf(",\"ACL\":");acl_t a=rc?NULL:get_acl(f);print_acl(a);if(a)acl_free(a);errno=error;return finish(rc);}
static int print_arguments(void *unused,uid_t uid,gid_t gid,int mode,kauth_filesec_t security){(void)unused;printf(",\"UID\":%u,\"GID\":%u,\"Mode\":%d,\"SecurityArgument\":%d,\"Security\":",uid,gid,mode,security?1:0);if(security)hex(security,KAUTH_FILESEC_COPYSIZE(security));else printf("null");return 0;}
static int extended(int fd,filesec_t f){event("security");if(chmodx1(NULL,print_arguments,f))fail("argument capture");int e=forced(1),rc;if(live)rc=fchmodx_np(fd,f);else{errno=e;rc=e?-1:0;}return finish(rc);}
static int mode_write(int fd,mode_t mode){event("mode");printf(",\"Mode\":%u",mode);int e=forced(2),rc;if(live)rc=fchmod(fd,mode);else{errno=e;rc=e?-1:0;}return finish(rc);}
static int owner_write(int fd,uid_t uid,gid_t gid){event("ownership");printf(",\"UID\":%u,\"GID\":%u",uid,gid);int e=forced(3),rc;if(live)rc=fchown(fd,uid,gid);else{errno=e;rc=e?-1:0;}return finish(rc);}
static int acl_write(int fd,acl_t a){event("acl");printf(",\"ACL\":");print_acl(a);int e=forced(4),rc;if(live)rc=acl_set_fd(fd,a);else{errno=e;rc=e?-1:0;}return finish(rc);}
static int volume(int fd,struct statfs *s){memset(s,0,sizeof(*s));s->f_flags=((fd==11&&filter==3)||(fd==12&&filter==4))?MNT_NOSUID:0;return 0;}
struct _copyfile_state {copyfile_flags_t flags;filesec_t fsec;int src_fd,dst_fd;struct stat sb;unsigned internal_flags;const char *src,*dst;};
#define copyfile_debug(...) ((void)0)
#define copyfile_warn(...) ((void)0)
#define fstatx_np capture
#define fchmodx_np extended
#define fchmod mode_write
#define fchown owner_write
#define acl_set_fd acl_write
#define fstatfs volume
#include "acl-copy-source.h"
#undef fstatx_np
#undef fchmodx_np
#undef fchmod
#undef fchown
#undef acl_set_fd
#undef fstatfs
static void snapshot(int fd,struct stat *st){filesec_t f=filesec_init();if(!f||fstatx_np(fd,st,f))fail("snapshot");printf("{\"Properties\":");print_properties(f);printf(",\"UID\":%u,\"GID\":%u,\"Mode\":%u,\"Flags\":%u}",st->st_uid,st->st_gid,st->st_mode,st->st_flags);filesec_free(f);}
static int source_fd=-1,destination_fd=-1;
static void cleanup(void){if(destination_fd>=0){(void)fchflags(destination_fd,0);(void)fchmod(destination_fd,0700);(void)close(destination_fd);}if(source_fd>=0)(void)close(source_fd);}
static int create(const char *path,int directory,acl_t acl,mode_t mode,const char *payload){if(directory&&mkdir(path,0700))fail("mkdir");int fd=open(path,directory?O_RDONLY:(O_RDWR|O_CREAT|O_EXCL),0600);if(fd<0)fail("create");if(acl&&acl_set_fd(fd,acl))fail("initial ACL");if(fchown(fd,(uid_t)-1,getegid())||fchmod(fd,mode))fail("initial stat");int data=directory?openat(fd,"payload",O_RDWR|O_CREAT|O_EXCL,0600):fd;if(data<0||write(data,payload,6)!=6)fail("payload");if(directory&&close(data))fail("payload close");return fd;}
static void payload(int fd,int directory,const char *want){int data=directory?openat(fd,"payload",O_RDONLY):fd;char b[7];if(data<0||pread(data,b,sizeof(b),0)!=6||memcmp(b,want,6))fail("payload changed");if(directory&&close(data))fail("payload close");}
static int direct(int fd){
 char *line=NULL;size_t cap=0;while(getline(&line,&cap,stdin)>0){char op[24],encoded[6233];unsigned uid,gid,mode,kind;int signedmode;
 if(sscanf(line,"%23s",op)!=1)fail("direct operation");
 if(!strcmp(op,"security")){if(sscanf(line,"%*s %u %u %d %u %6232s",&uid,&gid,&signedmode,&kind,encoded)!=5||kind>1)fail("direct security");size_t n=0;kauth_filesec_t raw=NULL;if(kind){raw=unhex(encoded,&n);if(n<44||raw->fsec_magic!=KAUTH_FILESEC_MAGIC||KAUTH_FILESEC_COPYSIZE(raw)!=n)fail("direct record");}event(op);print_arguments(NULL,uid,gid,signedmode,raw);int rc=__fchmod_extended(fd,uid,gid,signedmode,raw),e=errno;free(raw);errno=e;finish(rc);}
 else if(!strcmp(op,"mode")){if(sscanf(line,"%*s %u",&mode)!=1)fail("direct mode");mode_write(fd,(mode_t)mode);}
 else if(!strcmp(op,"ownership")){if(sscanf(line,"%*s %u %u",&uid,&gid)!=2)fail("direct owner");owner_write(fd,uid,gid);}
 else if(!strcmp(op,"acl")){if(sscanf(line,"%*s %6232s",encoded)!=1)fail("direct ACL");size_t n;void *b=unhex(encoded,&n);if(n<44)fail("direct ACL extent");acl_t a=acl_copy_int(b);if(!a)fail("direct ACL import");acl_write(fd,a);acl_free(a);free(b);}
 else if(!strcmp(op,"capture")){struct stat st;filesec_t f=filesec_init();if(!f)fail("capture init");capture(fd,&st,f);filesec_free(f);}
 else fail("unknown direct operation");
 }free(line);return 0;
}
int main(int argc,char **argv){
 // model: flags filter sourceACL destinationACL presence fault
 // live: flags filter sourceACL destinationACL root kind targetFlags native|go|public
 if(argc!=8&&argc!=10)return 2;int model=!strcmp(argv[1],"model");if(!model&&strcmp(argv[1],"live"))return 2;
 unsigned flags=(unsigned)strtoul(argv[2],NULL,0);filter=atoi(argv[3]);acl_t src=load_acl(argv[4]),dst=load_acl(argv[5]);filesec_t f=filesec_init();if(!f)fail("state init");struct _copyfile_state state={.flags=flags,.fsec=f,.src_fd=11,.dst_fd=12,.sb={.st_uid=44,.st_gid=45,.st_mode=06711}};
 if(filter==1)state.internal_flags=cfForbidCopySuidBits;if(filter==2)state.internal_flags=cfAlwaysCopySuidBits|cfForbidCopySuidBits;
 struct stat sb,db,sa,da;int directory=0;
 if(model){unsigned presence=(unsigned)strtoul(argv[6],NULL,0);fault=atoi(argv[7]);uid_t uid=42;gid_t gid=43;mode_t mode=06755;unsigned char owner[16]={0x11},group[16]={0x22};if(src&&filesec_set_property(f,FILESEC_ACL,&src))fail("source ACL");if((presence&1)&&filesec_set_property(f,FILESEC_OWNER,&uid))fail("source UID");if((presence&2)&&filesec_set_property(f,FILESEC_GROUP,&gid))fail("source GID");if((presence&4)&&filesec_set_property(f,FILESEC_MODE,&mode))fail("source mode");if((presence&8)&&filesec_set_property(f,FILESEC_UUID,owner))fail("source UUID");if((presence&16)&&filesec_set_property(f,FILESEC_GRPUUID,group))fail("source group UUID");target_acl=dst;}
 else {live=1;directory=!strcmp(argv[7],"directory");if(!directory&&strcmp(argv[7],"file"))return 2;char s[4096],d[4096];if(snprintf(s,sizeof(s),"%s/source",argv[6])>=(int)sizeof(s)||snprintf(d,sizeof(d),"%s/target",argv[6])>=(int)sizeof(d))return 2;
 source_fd=create(s,directory,src,06755,"source");destination_fd=create(d,directory,dst,directory?0755:0644,"target");if(atexit(cleanup))fail("cleanup");struct statfs fs;if(fstatfs(destination_fd,&fs)||strcmp(fs.f_fstypename,"apfs"))fail("requires APFS");if(fstatx_np(source_fd,&state.sb,f)||fchflags(destination_fd,(unsigned)strtoul(argv[8],NULL,0)))fail("live baseline");state.src_fd=source_fd;state.dst_fd=destination_fd;}
 printf("{\"Source\":{\"Properties\":");print_properties(f);printf(",\"UID\":%u,\"GID\":%u,\"Mode\":%u}",state.sb.st_uid,state.sb.st_gid,state.sb.st_mode);
 if(!model){printf(",\"SourceBefore\":");snapshot(source_fd,&sb);printf(",\"Before\":");snapshot(destination_fd,&db);}
 printf(",\"Events\":[");errno=0;int rc;
 if(model||!strcmp(argv[9],"native"))rc=copyfile_security(&state);
 else if(!strcmp(argv[9],"go"))rc=direct(destination_fd);
 else if(!strcmp(argv[9],"public"))rc=fcopyfile(source_fd,destination_fd,NULL,flags);
 else return 2;
 int error=rc?errno:0;printf("],\"Code\":%d,\"Errno\":%d,\"Cache\":",rc,error);print_properties(f);
 if(!model){printf(",\"SourceAfter\":");snapshot(source_fd,&sa);printf(",\"After\":");snapshot(destination_fd,&da);payload(source_fd,directory,"source");payload(destination_fd,directory,"target");printf(",\"IdentityUnchanged\":%s,\"PayloadUnchanged\":true,\"Filesystem\":\"apfs\"",sb.st_dev==sa.st_dev&&sb.st_ino==sa.st_ino&&db.st_dev==da.st_dev&&db.st_ino==da.st_ino?"true":"false");}
 printf("}\n");if(src)acl_free(src);if(dst)acl_free(dst);filesec_free(f);return 0;
}
