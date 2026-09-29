// Test-only instrumentation around complete, unchanged pinned Apple functions.
// Model responses exercise races/refusals; live responses call the real kernel.
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/ioccom.h>
#include <sys/xattr.h>
#include <sys/acl.h>
#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "stat-fsctl.h"
#include "copyfile_private.h"
extern int ffsctl(int, unsigned long, void *, unsigned int);
static int live, calls, fault, cas_kind, cas_calls, src_policy, dst_policy;
static int source_fd=-1, target_fd=-1;
static uint32_t current_flags;
static void fail(const char *s) { perror(s); exit(2); }
static void event(const char *s) { if(calls++) printf(","); printf("{\"Operation\":\"%s\"",s); }
static int finish(int rc) { int e=rc?errno:0; printf(",\"Code\":%d,\"Errno\":%d}",rc,e); errno=e; return rc; }
static int forced(int which) { if(fault==which || fault==7) { errno=EACCES; return -1; } return 0; }
static int volume(int fd, struct statfs *s) {
 int source=fd==source_fd; event(source?"volume-source":"volume-destination");
 int rc;
 if(live) rc=fstatfs(fd,s);
 else { int p=source?src_policy:dst_policy; memset(s,0,sizeof(*s)); s->f_flags=p>0?MNT_NOSUID:0; errno=p<0?-p:0; rc=p<0?-1:0; }
 printf(",\"NoSetID\":%s",!rc&&(s->f_flags&MNT_NOSUID)?"true":"false"); return finish(rc);
}
static int times_write(int fd, struct attrlist *a, void *buf, size_t size, unsigned long opts) {
 struct timespec *t=buf;
 if(a->bitmapcount!=ATTR_BIT_MAP_COUNT || a->commonattr!=(ATTR_CMN_MODTIME|ATTR_CMN_ACCTIME) || a->volattr || a->dirattr || a->fileattr || a->forkattr || size!=2*sizeof(*t) || opts) fail("time request layout");
 event("times"); printf(",\"Times\":[%lld,%ld,%lld,%ld]",(long long)t[0].tv_sec,t[0].tv_nsec,(long long)t[1].tv_sec,t[1].tv_nsec);
 return finish(live?fsetattrlist(fd,a,buf,size,opts):forced(1));
}
static int owner_write(int fd,uid_t uid,gid_t gid) { event("ownership"); printf(",\"UID\":%u,\"GID\":%u",uid,gid); return finish(live?fchown(fd,uid,gid):forced(2)); }
static int mode_write(int fd,mode_t mode) { event("mode"); printf(",\"Mode\":%u",mode); return finish(live?fchmod(fd,mode):forced(3)); }
static int flags_read(int fd,struct stat *s) {
 event("read-flags"); int rc;
 if(live) rc=fstat(fd,s); else { memset(s,0,sizeof(*s)); s->st_flags=current_flags; rc=forced(4); }
 printf(",\"Actual\":%u",rc?0:s->st_flags); return finish(rc);
}
static int flags_cas(int fd,unsigned long request,void *buf,unsigned int opts) {
 struct fsioc_cas_bsdflags *c=buf;
 if(request!=FSIOC_CAS_BSDFLAGS || opts || c->actual_flags!=UINT32_MAX) fail("CAS request layout");
 event("compare-flags"); printf(",\"Expected\":%u,\"Flags\":%u",c->expected_flags,c->new_flags);
 int rc=0;
 if(live) rc=ffsctl(fd,request,buf,opts);
 else if(forced(5)) rc=-1;
 else if(cas_kind==1 || (cas_kind==2 && cas_calls<3)) { errno=EAGAIN; rc=-1; }
 else if(cas_kind==3) { errno=ENOTSUP; rc=-1; }
 else if(cas_kind==4 || (cas_kind==5 && cas_calls==0)) { current_flags^=UF_TRACKED|UF_DATAVAULT|SF_RESTRICTED; c->actual_flags=current_flags; }
 else { c->actual_flags=current_flags; if(current_flags==c->expected_flags) current_flags=c->new_flags; }
 cas_calls++; printf(",\"Actual\":%u",c->actual_flags); return finish(rc);
}
static int flags_write(int fd,unsigned flags) { event("flags"); printf(",\"Flags\":%u",flags); int rc=live?fchflags(fd,flags):forced(6); if(!rc)current_flags=flags; return finish(rc); }
struct _copyfile_state { int src_fd,dst_fd; struct stat sb; unsigned internal_flags; copyfile_flags_t flags; const char *dst; };
#define copyfile_debug(...) ((void)0)
#define fstatfs volume
#define fsetattrlist times_write
#define fchown owner_write
#define fchmod mode_write
#define fstat flags_read
#define ffsctl flags_cas
#define fchflags flags_write
#include "stat-source.h"
#undef fstatfs
#undef fsetattrlist
#undef fchown
#undef fchmod
#undef fstat
#undef ffsctl
#undef fchflags
static void hex(const void *data,size_t n) { const unsigned char *p=data; printf("\""); for(size_t i=0;i<n;i++)printf("%02x",p[i]);printf("\""); }
static void snapshot(int fd, struct stat *s) {
 if(fstat(fd,s))fail("snapshot");
 printf("{\"UID\":%u,\"GID\":%u,\"Mode\":%u,\"Flags\":%u,\"Times\":[%lld,%ld,%lld,%ld,%lld,%ld]",s->st_uid,s->st_gid,s->st_mode,s->st_flags,(long long)s->st_birthtimespec.tv_sec,s->st_birthtimespec.tv_nsec,(long long)s->st_mtimespec.tv_sec,s->st_mtimespec.tv_nsec,(long long)s->st_atimespec.tv_sec,s->st_atimespec.tv_nsec);
 acl_t a=acl_get_fd(fd); if(!a)fail("ACL capture"); unsigned char acl[3116]; ssize_t n=acl_size(a); if(n<0||n>3116||acl_copy_ext(acl,a,n)!=n)fail("ACL export"); printf(",\"ACL\":");hex(acl,(size_t)n);acl_free(a);
 char x[32]; n=fgetxattr(fd,"org.example.stat-copy",x,sizeof(x),0,0); if(n<0)fail("xattr capture"); printf(",\"Xattr\":");hex(x,(size_t)n);printf("}");
}
static void cleanup(void) { if(target_fd>=0){(void)fchflags(target_fd,0);(void)fchmod(target_fd,0700);close(target_fd);}if(source_fd>=0){(void)fchflags(source_fd,0);close(source_fd);} }
static int create(const char *root,const char *name,int dir,int source) {
 char path[4096]; if(snprintf(path,sizeof(path),"%s/%s",root,name)>=(int)sizeof(path))fail("path");
 if(dir&&mkdir(path,0700))fail("mkdir"); int fd=open(path,dir?O_RDONLY:O_RDWR|O_CREAT|O_EXCL,0600); if(fd<0)fail("open");
 int data=dir?openat(fd,"payload",O_RDWR|O_CREAT|O_EXCL,0600):fd;
 if(data<0||write(data,source?"source":"target",6)!=6)fail("payload"); if(dir)close(data);
 acl_t a=acl_from_text("!#acl 1\nuser:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:::allow:read\n"); if(!a||acl_set_fd(fd,a))fail("ACL init");acl_free(a);
 if(fsetxattr(fd,"org.example.stat-copy",source?"source":"target",6,0,0)||fchown(fd,(uid_t)-1,getegid())||fchmod(fd,source?06751:0740))fail("metadata init");
 struct attrlist al={.bitmapcount=ATTR_BIT_MAP_COUNT,.commonattr=ATTR_CMN_CRTIME|ATTR_CMN_MODTIME|ATTR_CMN_ACCTIME};
 struct timespec ts[3]={{1700000000,123456789},{source?1600000000:1650000000,987654321},{1500000000,456789123}};
 if(fsetattrlist(fd,&al,ts,sizeof(ts),0))fail("times init");return fd;
}
static void payload(int fd,int dir,const char *want) { int data=dir?openat(fd,"payload",O_RDONLY):fd; char b[7];if(data<0||pread(data,b,sizeof(b),0)!=6||memcmp(b,want,6))fail("payload changed");if(dir)close(data); }
static int direct(void) {
 char *line=NULL;size_t cap=0;
 while(getline(&line,&cap,stdin)>0){ char op[32];unsigned x,y;long long sec1,sec2;long ns1,ns2;
 if(sscanf(line,"%31s",op)!=1)fail("instruction");
 if(!strcmp(op,"volume-source")||!strcmp(op,"volume-destination")){struct statfs v;volume(!strcmp(op,"volume-source")?source_fd:target_fd,&v);}
 else if(!strcmp(op,"times")){if(sscanf(line,"%*s %lld %ld %lld %ld",&sec1,&ns1,&sec2,&ns2)!=4)fail("times protocol");struct attrlist a={.bitmapcount=ATTR_BIT_MAP_COUNT,.commonattr=ATTR_CMN_MODTIME|ATTR_CMN_ACCTIME};struct timespec ts[2]={{sec1,ns1},{sec2,ns2}};times_write(target_fd,&a,ts,sizeof(ts),0);}
 else if(!strcmp(op,"ownership")){if(sscanf(line,"%*s %u %u",&x,&y)!=2)fail("owner protocol");owner_write(target_fd,x,y);}
 else if(!strcmp(op,"mode")){if(sscanf(line,"%*s %u",&x)!=1)fail("mode protocol");mode_write(target_fd,(mode_t)x);}
 else if(!strcmp(op,"read-flags")){struct stat s;flags_read(target_fd,&s);}
 else if(!strcmp(op,"compare-flags")){if(sscanf(line,"%*s %u %u",&x,&y)!=2)fail("CAS protocol");struct fsioc_cas_bsdflags c={x,y,UINT32_MAX};flags_cas(target_fd,FSIOC_CAS_BSDFLAGS,&c,0);}
 else if(!strcmp(op,"flags")){if(sscanf(line,"%*s %u",&x)!=1)fail("flags protocol");flags_write(target_fd,x);}
 else fail("unknown instruction");
 }free(line);return 0;
}
int main(int argc,char **argv) {
 // model sourceFlags targetFlags options sourcePolicy targetPolicy fault cas
 // live sourceFlags targetFlags options root kind native|go|public
 if(argc!=9)return 2;live=!strcmp(argv[1],"live");if(!live&&strcmp(argv[1],"model"))return 2;
 uint32_t sf=(uint32_t)strtoul(argv[2],NULL,0),tf=(uint32_t)strtoul(argv[3],NULL,0);unsigned options=(unsigned)strtoul(argv[4],NULL,0);
 struct _copyfile_state state={.src_fd=11,.dst_fd=12,.sb={.st_uid=44,.st_gid=45,.st_mode=0106751,.st_flags=sf,.st_mtimespec={1600000000,987654321},.st_atimespec={1500000000,456789123}},.flags=COPYFILE_STAT};
 if(options&1)state.internal_flags|=cfAlwaysCopySuidBits;if(options&2)state.internal_flags|=cfForbidCopySuidBits;if(options&4)state.internal_flags|=cfMakeFileInvisible;if(options&8)state.flags|=COPYFILE_PRESERVE_DST_TRACKED;
 int dir=0;struct stat sb,db,sa,da;source_fd=11;target_fd=12;current_flags=tf;
 if(!live){src_policy=atoi(argv[5]);dst_policy=atoi(argv[6]);fault=atoi(argv[7]);cas_kind=atoi(argv[8]);}
 else {
 dir=!strcmp(argv[6],"directory");if(!dir&&strcmp(argv[6],"file"))return 2;
 // argv[7] is reserved to retain one argument layout for both modes.
 source_fd=create(argv[5],"source",dir,1);target_fd=create(argv[5],"target",dir,0);if(atexit(cleanup))fail("cleanup registration");
 struct statfs v;if(fstatfs(target_fd,&v)||strcmp(v.f_fstypename,"apfs"))fail("requires APFS");
 if(fchflags(source_fd,sf)||fchflags(target_fd,tf)||fstat(source_fd,&state.sb))fail("live flags");state.src_fd=source_fd;state.dst_fd=target_fd;
 }
 printf("{\"Source\":{\"UID\":%u,\"GID\":%u,\"Mode\":%u,\"Flags\":%u,\"Times\":[%lld,%ld,%lld,%ld]}",state.sb.st_uid,state.sb.st_gid,state.sb.st_mode,state.sb.st_flags,(long long)state.sb.st_mtimespec.tv_sec,state.sb.st_mtimespec.tv_nsec,(long long)state.sb.st_atimespec.tv_sec,state.sb.st_atimespec.tv_nsec);
 if(live){printf(",\"SourceBefore\":");snapshot(source_fd,&sb);printf(",\"Before\":");snapshot(target_fd,&db);}
 printf(",\"Events\":[");errno=0;int rc;
 if(!live||!strcmp(argv[8],"native"))rc=copyfile_stat(&state);
 else if(!strcmp(argv[8],"go"))rc=direct();
 else if(!strcmp(argv[8],"public"))rc=fcopyfile(source_fd,target_fd,NULL,COPYFILE_STAT|(options&8?COPYFILE_PRESERVE_DST_TRACKED:0));
 else return 2;
 int e=rc?errno:0;printf("],\"Code\":%d,\"Errno\":%d",rc,e);
 if(live){printf(",\"SourceAfter\":");snapshot(source_fd,&sa);printf(",\"After\":");snapshot(target_fd,&da);payload(source_fd,dir,"source");payload(target_fd,dir,"target");printf(",\"IdentityUnchanged\":%s,\"PayloadUnchanged\":true,\"Filesystem\":\"apfs\"",sb.st_dev==sa.st_dev&&sb.st_ino==sa.st_ino&&db.st_dev==da.st_dev&&db.st_ino==da.st_ino?"true":"false");}
 printf("}\n");return 0;
}
