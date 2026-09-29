// Complete unchanged fcopyfile acquisition oracle. The generated shared helper
// adds only the state.err field needed by fcopyfile; its operations are reused.
#define main baseline_security_copy_main
#include "source-copy-helper.h"
#undef main

static int source_error, stat_behavior, presence, copy_code, entered, go_requests;
static mode_t source_mode;
static acl_t source_acl;
static int source_data=-1,destination_data=-1;
static int payload_cleanups;
static void print_source(struct stat *st,filesec_t f){printf("{\"Properties\":");print_properties(f);printf(",\"UID\":%u,\"GID\":%u,\"Mode\":%u}",st->st_uid,st->st_gid,st->st_mode);}
static int read_security(int fd,struct stat *st,filesec_t f){
 event("read-security");int rc;
 if(live)rc=fstatx_np(fd,st,f);
 else{
  memset(st,0,sizeof(*st));st->st_uid=44;st->st_gid=45;st->st_mode=source_mode;
  uid_t uid=42;gid_t gid=43;mode_t mode=0106755;unsigned char owner[16]={0x11},group[16]={0x22};
  if(source_acl&&filesec_set_property(f,FILESEC_ACL,&source_acl))fail("source ACL");
  if((presence&1)&&filesec_set_property(f,FILESEC_OWNER,&uid))fail("source UID");
  if((presence&2)&&filesec_set_property(f,FILESEC_GROUP,&gid))fail("source GID");
  if((presence&4)&&filesec_set_property(f,FILESEC_MODE,&mode))fail("source mode");
  if((presence&8)&&filesec_set_property(f,FILESEC_UUID,owner))fail("source owner UUID");
  if((presence&16)&&filesec_set_property(f,FILESEC_GRPUUID,group))fail("source group UUID");
  errno=source_error;rc=source_error?-1:0;
 }
 int error=errno;printf(",\"Source\":");print_source(st,f);errno=error;return finish(rc);
}
static int read_stat(int fd,struct stat *st){
 if(fd!=source_fd){if(live)return fstat(fd,st);memset(st,0,sizeof(*st));st->st_mode=0100644;return 0;}
 event("read-stat");int rc;
 if(live)rc=fstat(fd,st);
 else if(stat_behavior==0){memset(st,0,sizeof(*st));st->st_uid=46;st->st_gid=47;st->st_mode=0106711;rc=0;}
 else {if(stat_behavior==2)memset(st,0,sizeof(*st));errno=EIO;rc=-1;}
 int error=errno;printf(",\"Stat\":{\"UID\":%u,\"GID\":%u,\"Mode\":%u}",st->st_uid,st->st_gid,st->st_mode);errno=error;return finish(rc);
}
static int wrapper_mode(int fd,mode_t mode){return live?fchmod(fd,mode):0;}
static int preamble(copyfile_state_t *s,copyfile_flags_t flags){if(!s||!*s){errno=EINVAL;return -1;}(*s)->flags=flags;return 0;}
static int quarantine(copyfile_state_t s){(void)s;return 0;}
static int internal(copyfile_state_t s,copyfile_flags_t flags){
 (void)flags;entered=1;event("acquired");printf(",\"Source\":");print_source(&s->sb,s->fsec);finish(0);
 copy_code=go_requests?direct(s->dst_fd):copyfile_security(s);
 return copy_code;
}
#define fcopyfile source_fcopyfile
#define fstatx_np read_security
#define fstat read_stat
#define fchmod wrapper_mode
#define copyfile_preamble preamble
#define copyfile_quarantine quarantine
#define copyfile_internal internal
#include "source-fcopyfile.h"
#undef fcopyfile
#undef fstatx_np
#undef fstat
#undef fchmod
#undef copyfile_preamble
#undef copyfile_quarantine
#undef copyfile_internal

static int source_create(const char *path,const char *kind,acl_t acl,mode_t mode,const char *data){
 if(strcmp(kind,"symlink")){int fd=create(path,!strcmp(kind,"directory"),acl,0700,data);if(!strcmp(kind,"directory")){int held=openat(fd,"payload",O_RDONLY);if(held<0)fail("hold payload");if(source_fd<0)source_data=held;else destination_data=held;}if(fchmod(fd,mode))fail("source mode");return fd;}
 if(symlink(data,path)||lchown(path,(uid_t)-1,getegid()))fail("create link");
 int fd=open(path,O_SYMLINK|O_EVTONLY);if(fd<0)fail("hold link");
 if(acl&&acl_set_fd(fd,acl))fail("link ACL");
 if(fchmod(fd,mode))fail("link mode");return fd;
}
static void source_payload(int fd,const char *path,const char *kind,const char *data){
 if(!strcmp(kind,"directory")){char b[7];int held=fd==source_fd?source_data:destination_data;if(pread(held,b,sizeof(b),0)!=6||memcmp(b,data,6))fail("directory payload");if(close(held))fail("payload close");return;}
 if(strcmp(kind,"symlink")){payload(fd,0,data);return;}
 // Darwin denies readlink for a zero-read-mode link. Metadata has already
 // been observed; grant read access on the held link only for payload cleanup.
 struct stat st;if(fstat(fd,&st))fail("link cleanup stat");if(!(st.st_mode&S_IRUSR)){if(fchmod(fd,0700))fail("link payload cleanup");payload_cleanups++;}
 char b[16];ssize_t n=readlink(path,b,sizeof(b));if(n!=6||memcmp(b,data,6))fail("link payload");
}
int main(int argc,char **argv){
 // model flags sourceACL destinationACL presence sourceError statBehavior mode
 // live flags sourceACL destinationACL directory kind mode native|go
 if(argc!=9)return 2;
 int model=!strcmp(argv[1],"model");if(!model&&strcmp(argv[1],"live"))return 2;
 unsigned flags=(unsigned)strtoul(argv[2],NULL,0);
 source_acl=load_acl(argv[3]);target_acl=load_acl(argv[4]);
 filesec_t f=filesec_init();if(!f)fail("state");
 struct _copyfile_state state={.flags=flags,.fsec=f,.src_fd=-2,.dst_fd=-2};
 struct stat sb,db,sa,da;char sp[4096],dp[4096];const char *kind=argv[6];
 if(model){source_fd=11;destination_fd=12;presence=atoi(argv[5]);source_error=atoi(argv[6]);stat_behavior=atoi(argv[7]);source_mode=(mode_t)strtoul(argv[8],NULL,0);}
 else{
  live=1;mode_t mode=(mode_t)strtoul(argv[7],NULL,0);go_requests=!strcmp(argv[8],"go");
  if(snprintf(sp,sizeof(sp),"%s/source",argv[5])>=(int)sizeof(sp)||snprintf(dp,sizeof(dp),"%s/target",argv[5])>=(int)sizeof(dp))return 2;
  source_fd=source_create(sp,kind,source_acl,mode,"source");destination_fd=source_create(dp,kind,target_acl,0644,"target");
  if(atexit(cleanup))fail("cleanup");struct statfs fs;if(fstatfs(source_fd,&fs)||strcmp(fs.f_fstypename,"apfs"))fail("requires APFS");
 }
 printf("{");
 if(!model){printf("\"SourceBefore\":");snapshot(source_fd,&sb);printf(",\"Before\":");snapshot(destination_fd,&db);printf(",");}
 printf("\"Events\":[");errno=0;int rc=source_fcopyfile(source_fd,destination_fd,&state,flags);int error=rc?errno:0;
 printf("],\"Code\":%d,\"Errno\":%d,\"Entered\":%s,\"CopyCode\":%d,\"Cache\":",rc,error,entered?"true":"false",copy_code);print_properties(f);
 printf(",\"FinalSource\":");print_source(&state.sb,f);
 if(!model){printf(",\"SourceAfter\":");snapshot(source_fd,&sa);printf(",\"After\":");snapshot(destination_fd,&da);source_payload(source_fd,sp,kind,"source");source_payload(destination_fd,dp,kind,"target");printf(",\"PayloadPermissionCleanups\":%d,\"IdentityUnchanged\":%s,\"PayloadUnchanged\":true",payload_cleanups,sb.st_dev==sa.st_dev&&sb.st_ino==sa.st_ino&&db.st_dev==da.st_dev&&db.st_ino==da.st_ino?"true":"false");}
 printf("}\n");if(source_acl)acl_free(source_acl);if(target_acl)acl_free(target_acl);filesec_free(f);return 0;
}
