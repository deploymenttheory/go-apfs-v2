#include <stdint.h>
#include <sys/acl.h>
#include <sys/kauth.h>
#include <arpa/inet.h>
extern ssize_t acl_copy_ext_native(void *,acl_t,ssize_t);
static uint32_t ace_rights[8];static unsigned ace_count;
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <membership.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Independent regular-file discretionary-access oracle. Each invocation owns
// one fixture and retains the initial descriptor before restrictions are applied.
static void fail(const char *what) { perror(what); exit(2); }
static void hex(const unsigned char *p,size_t n) { putchar('"');for(size_t i=0;i<n;i++)printf("%02x",p[i]);putchar('"'); }
static void ace(acl_t *acl,const uuid_t identity,int deny,uint32_t rights,int inherit) {
 acl_entry_t entry;acl_flagset_t flags;
 if(acl_create_entry(acl,&entry)||acl_set_tag_type(entry,deny?ACL_EXTENDED_DENY:ACL_EXTENDED_ALLOW)||acl_set_qualifier(entry,identity)||acl_set_permset_mask_np(entry,rights&0x001fffff))fail("ACE");
 ace_rights[ace_count++]=rights; if(inherit&&(acl_get_flagset_np(entry,&flags)||acl_add_flag_np(flags,ACL_ENTRY_ONLY_INHERIT)||acl_set_flagset_np(entry,flags)))fail("ACE flags");
}
int main(int argc,char **argv) {
 if(argc!=5)return 2;
 const char *scenario=argv[1],*operation=argv[2],*path=argv[3];
 int fd=open(path,O_CREAT|O_EXCL|O_RDWR,0600);if(fd<0)fail("create");
 if(write(fd,"logical data",12)!=12)fail("data");
 uuid_t identity,principal;if(mbr_uid_to_uuid(geteuid(),identity))fail("identity");memcpy(principal,identity,sizeof(principal));
 acl_t acl=acl_init(4);if(!acl)fail("ACL");
 mode_t mode=0600;uint32_t flags=0;
 if(!strncmp(scenario,"mode-",5))mode=(mode_t)strtoul(scenario+5,NULL,8);
 else if(!strcmp(scenario,"immutable"))flags=UF_IMMUTABLE;
 else if(!strcmp(scenario,"append"))flags=UF_APPEND;
 else if(!strncmp(scenario,"deny-",5)){
  uint32_t rights=0;
  if(!strcmp(scenario,"deny-read"))rights=ACL_READ_DATA;
  else if(!strcmp(scenario,"deny-write"))rights=ACL_WRITE_DATA;
  else if(!strcmp(scenario,"deny-readxattr"))rights=ACL_READ_EXTATTRIBUTES;
  else if(!strcmp(scenario,"deny-writexattr"))rights=ACL_WRITE_EXTATTRIBUTES;
  else if(!strcmp(scenario,"deny-writeattr"))rights=ACL_WRITE_ATTRIBUTES;
  else if(!strcmp(scenario,"deny-writesecurity"))rights=ACL_WRITE_SECURITY;
  else if(!strcmp(scenario,"deny-inherit-only"))rights=ACL_READ_DATA|ACL_WRITE_DATA;
  else if(!strcmp(scenario,"deny-generic-read"))rights=1U<<24;
  else if(!strncmp(scenario,"deny-wellknown-",15)){
   unsigned char prefix[]={0xab,0xcd,0xef,0xab,0xcd,0xef,0xab,0xcd,0xef,0xab,0xcd,0xef};memcpy(principal,prefix,12);
   uint32_t code=(uint32_t)strtoul(scenario+15,NULL,0);principal[12]=(unsigned char)(code>>24);principal[13]=(unsigned char)(code>>16);principal[14]=(unsigned char)(code>>8);principal[15]=(unsigned char)code;rights=6;
  }else return 2;
  ace(&acl,principal,1,rights,!strcmp(scenario,"deny-inherit-only"));
 }else if(!strcmp(scenario,"allow-all-before-deny")){mode=0;ace(&acl,identity,0,6,0);ace(&acl,identity,1,6,0);}
 else if(!strcmp(scenario,"allow-part-then-deny")){ace(&acl,identity,0,2,0);ace(&acl,identity,1,2,0);ace(&acl,identity,0,4,0);}
 else if(!strcmp(scenario,"split-allow")){mode=0;ace(&acl,identity,0,2,0);ace(&acl,identity,0,4,0);}
 else if(!strcmp(scenario,"generic-allow")){mode=0;ace(&acl,identity,0,1U<<21,0);}
 else if(strcmp(scenario,"ordinary"))return 2;
 ssize_t rawsize=acl_size(acl);if(rawsize<44)fail("raw ACL size");struct kauth_filesec *raw=calloc((size_t)rawsize,1);if(!raw||acl_copy_ext_native(raw,acl,rawsize)!=rawsize)fail("raw ACL");for(unsigned i=0;i<ace_count;i++)raw->fsec_acl.acl_ace[i].ace_rights=ace_rights[i];filesec_t sec=filesec_init();size_t allocation=(size_t)rawsize;if(!sec||filesec_set_property(sec,FILESEC_ACL_ALLOCSIZE,&allocation)||filesec_set_property(sec,FILESEC_ACL_RAW,&raw)||fchmodx_np(fd,sec))fail("install raw ACL");filesec_free(sec);if(fchmod(fd,mode)||fchflags(fd,flags))fail("fixture restrictions");
 ssize_t input_size=acl_size(acl);unsigned char *input_security=malloc((size_t)input_size);if(!input_security||acl_copy_ext(input_security,acl,input_size)!=input_size)fail("input ACL export");for(unsigned i=0;i<ace_count;i++){uint32_t value=htonl(ace_rights[i]);memcpy(input_security+44+24*i+20,&value,4);}struct stat before;struct statfs volume;if(fstat(fd,&before)||fstatfs(fd,&volume))fail("before");
 errno=0;acl_t captured=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);int capture_error=captured?0:errno;if(!captured&&errno!=ENOENT&&errno!=EACCES)fail("capture ACL");ssize_t size=captured?acl_size(captured):0;if((captured&&size<44)||size>8192)fail("ACL length");unsigned char *security=malloc(size?(size_t)size:1);if(!security||(captured&&acl_copy_ext(security,captured,size)!=size))fail("export ACL");
 errno=0;int rc;
 if(!strcmp(operation,"open-data")){int x=open(path,O_RDWR);rc=x<0?-1:0;int e=errno;if(x>=0&&close(x))fail("close data");errno=e;}
 else if(!strcmp(operation,"open-fork")){char fork[4096];if(snprintf(fork,sizeof(fork),"%s/..namedfork/rsrc",path)>=(int)sizeof(fork))return 2;int x=atoi(argv[4])==15?open(fork,O_CREAT|O_RDWR|O_NOFOLLOW,0600):openat(fd,"..namedfork/rsrc",O_CREAT|O_RDWR,0600);rc=x<0?-1:0;int e=errno;if(x>=0&&close(x))fail("close fork");errno=e;}
 else if(!strcmp(operation,"attribute"))rc=fsetxattr(fd,"com.apple.decmpfs","inactive",8,0,0);
 else if(!strcmp(operation,"truncate"))rc=ftruncate(fd,0);
 else if(!strcmp(operation,"chmod"))rc=fchmod(fd,0640);
 else if(!strcmp(operation,"times")){struct timeval times[2]={{1500000000,0},{1600000000,0}};rc=futimes(fd,times);}
 else if(!strcmp(operation,"flags"))rc=fchflags(fd,flags|UF_HIDDEN);
 else return 2;
 int error=rc<0?errno:0;
 printf("{\"scenario\":\"%s\",\"operation\":\"%s\",\"uid\":%u,\"gid\":%u,\"effective_uid\":%u,\"mode\":%u,\"flags\":%u,\"volume_flags\":%u,\"errno\":%d,\"user_uuid\":",scenario,operation,before.st_uid,before.st_gid,geteuid(),before.st_mode,before.st_flags,volume.f_flags,error);hex(identity,16);printf(",\"security\":");hex(security,(size_t)size);printf(",\"security_input\":");hex(input_security,(size_t)input_size);printf(",\"security_read_errno\":%d,\"groups\":[",capture_error);
 int count=getgroups(0,NULL);if(count<0)fail("groups");gid_t *groups=calloc((size_t)count+1,sizeof(*groups));if(!groups||getgroups(count,groups)!=count)fail("groups read");for(int i=0;i<count;i++)printf("%s%u",i?",":"",groups[i]);printf("]}\n");
 if(fchflags(fd,0)||fchmod(fd,0600))fail("cleanup restrictions");acl_t empty=acl_init(0);if(!empty||acl_set_fd_np(fd,empty,ACL_TYPE_EXTENDED)||close(fd)||unlink(path))fail("cleanup");
 free(groups);free(security);free(input_security);acl_free(acl);if(captured)acl_free(captured);acl_free(empty);return 0;
}
