// Test-only optional-filesec oracle: unchanged chmodx1 and real libSystem calls.
#include <sys/attr.h>
#include <sys/mount.h>
#define main filesec_reference_main
#include "filesec.c"
#undef main
#include "acl-chmod-source.h"
extern int __fchmod_extended(int,uid_t,gid_t,int,kauth_filesec_t);
_Static_assert(sizeof(mode_t)==2,"Darwin mode width");
_Static_assert(KAUTH_UID_NONE==0xffffff9bU&&KAUTH_GID_NONE==0xffffff9bU,"Darwin omitted ownership");
static void uuid_property(filesec_t sec,filesec_property_t prop,const char *text){
 if(!strcmp(text,"-"))return;if(strlen(text)!=32)fail("UUID length");unsigned char uuid[16];for(int i=0;i<16;i++){unsigned v;if(sscanf(text+2*i,"%2x",&v)!=1)fail("UUID hex");uuid[i]=(unsigned char)v;}if(filesec_set_property(sec,prop,uuid))fail("UUID property");
}
// argv: raw-security|-|remove, uid|-, gid|-, mode|-, owner-uuid|-, group-uuid|-
static filesec_t properties(char **argv){
 filesec_t sec=filesec_init();if(!sec)fail("properties allocation");
 if(!strcmp(argv[0],"remove")){if(filesec_set_property(sec,FILESEC_ACL,_FILESEC_REMOVE_ACL))fail("removal property");}
 else if(strcmp(argv[0],"-")){
  size_t n;unsigned char *b=load(argv[0],&n);if(n<44)fail("raw security length");struct kauth_filesec *s=(void *)b;
  if(s->fsec_magic!=KAUTH_FILESEC_MAGIC||(s->fsec_entrycount!=KAUTH_FILESEC_NOACL&&s->fsec_entrycount>128)||KAUTH_FILESEC_COPYSIZE(s)!=n)fail("raw security extent");
  if(filesec_set_property(sec,FILESEC_ACL_ALLOCSIZE,&n)||filesec_set_property(sec,FILESEC_ACL_RAW,&b))fail("raw properties");
 }
 if(strcmp(argv[1],"-")){uid_t uid=(uid_t)strtoul(argv[1],NULL,0);if(filesec_set_property(sec,FILESEC_OWNER,&uid))fail("UID property");}
 if(strcmp(argv[2],"-")){gid_t gid=(gid_t)strtoul(argv[2],NULL,0);if(filesec_set_property(sec,FILESEC_GROUP,&gid))fail("GID property");}
 if(strcmp(argv[3],"-")){mode_t mode=(mode_t)strtoul(argv[3],NULL,0);if(filesec_set_property(sec,FILESEC_MODE,&mode))fail("mode property");}
 uuid_property(sec,FILESEC_UUID,argv[4]);uuid_property(sec,FILESEC_GRPUUID,argv[5]);return sec;
}
static int capture_arguments(void *obj,uid_t uid,gid_t gid,int mode,kauth_filesec_t security){
 int kind=security==(kauth_filesec_t)_FILESEC_REMOVE_ACL?2:security?1:0;
 if(kind==1){size_t n=KAUTH_FILESEC_COPYSIZE(security);if(n<44||n>3116)fail("captured extent");save((const char *)obj,security,n);}
 printf("{\"UID\":%u,\"GID\":%u,\"Mode\":%d,\"SecurityArgument\":%d}\n",uid,gid,mode,kind);return 0;
}
static int direct_write(int fd){
 char *line=NULL;size_t cap=0;if(getline(&line,&cap,stdin)<1)fail("arguments EOF");unsigned uid,gid,kind;int mode;char encoded[6233];
 if(sscanf(line,"%u %u %d %u %6232s",&uid,&gid,&mode,&kind,encoded)!=5||mode < -1||mode>65535||kind>2)fail("argument fields");free(line);
 unsigned char *b=NULL;kauth_filesec_t security=NULL;
 if(kind==1){size_t n=strlen(encoded);if(n<88||n%2)fail("argument extent");b=calloc(n/2,1);if(!b)fail("argument allocation");for(size_t i=0;i<n;i+=2){unsigned v;if(sscanf(encoded+i,"%2x",&v)!=1)fail("argument hex");b[i/2]=(unsigned char)v;}security=(void *)b;if(security->fsec_magic!=KAUTH_FILESEC_MAGIC||(security->fsec_entrycount!=KAUTH_FILESEC_NOACL&&security->fsec_entrycount>128)||KAUTH_FILESEC_COPYSIZE(security)!=n/2)fail("argument record");}
 else {if(strcmp(encoded,"-"))fail("unexpected security bytes");if(kind==2)security=(kauth_filesec_t)_FILESEC_REMOVE_ACL;}
 errno=0;int rc=__fchmod_extended(fd,uid,gid,mode,security),error=errno;free(b);errno=error;return rc;
}
static int cleanup_fd=-1;
static void cleanup(void){if(cleanup_fd>=0){(void)fchflags(cleanup_fd,0);(void)fchmod(cleanup_fd,0700);(void)close(cleanup_fd);}}
static void attributes(int fd){struct attrlist a={.bitmapcount=ATTR_BIT_MAP_COUNT,.commonattr=0x01c38000};unsigned char b[3172]={0};if(fgetattrlist(fd,&a,b,sizeof(b),0))fail("attribute read");uint32_t n;memcpy(&n,b,4);if(n<56||n>sizeof(b))fail("attribute size");hex(b,n);}
int main(int argc,char **argv){
 if(argc==9&&!strcmp(argv[1],"pack")){filesec_t sec=properties(argv+3);if(chmodx1(argv[2],capture_arguments,sec))fail("argument capture");filesec_free(sec);return 0;}
 // path, kind, initial ACL count, flags, native|go, six property arguments
 if(argc!=12)return 2;int directory=!strcmp(argv[2],"directory"),initial=atoi(argv[3]);unsigned flags=(unsigned)strtoul(argv[4],NULL,0);
 if((!directory&&strcmp(argv[2],"file"))||initial < -1||initial>128||(flags&~(UF_IMMUTABLE|UF_APPEND)))return 2;
 if(directory&&mkdir(argv[1],0700))fail("mkdir");int fd=open(argv[1],directory?O_RDONLY:(O_CREAT|O_EXCL|O_RDWR),0600);if(fd<0)fail("target open");cleanup_fd=fd;if(atexit(cleanup))fail("cleanup");
 struct statfs fs;if(fstatfs(fd,&fs)||strcmp(fs.f_fstypename,"apfs"))fail("requires APFS");
 if(!directory&&write(fd,"payload",7)!=7)fail("payload setup");
 if(initial>=0){char text[16384]="!#acl 1 no_inherit\n";for(int i=0;i<initial;i++)strcat(text,"user:11234567-89AB-CDEF-0123-456789ABCDEF:::allow:read\n");acl_t acl=acl_from_text(text);if(!acl||acl_set_fd(fd,acl))fail("baseline ACL");acl_free(acl);}
 if(fchown(fd,(uid_t)-1,getegid())||fchmod(fd,0644)||fchflags(fd,flags))fail("baseline metadata");
 struct stat before,after;printf("{\"Before\":");snapshot(fd,&before);printf(",\"Attributes\":");attributes(fd);printf("}\n");fflush(stdout);
 int rc;if(!strcmp(argv[5],"native")){filesec_t sec=properties(argv+6);errno=0;rc=fchmodx_np(fd,sec);int error=errno;filesec_free(sec);errno=error;}else if(!strcmp(argv[5],"go"))rc=direct_write(fd);else return 2;
 int error=rc?errno:0;printf("{\"Code\":%d,\"Errno\":%d,\"After\":",rc,error);snapshot(fd,&after);printf(",\"Attributes\":");attributes(fd);
 if(!directory){char data[8]={0};if(pread(fd,data,sizeof(data),0)!=7||memcmp(data,"payload",7))fail("payload changed");}
 printf(",\"IdentityUnchanged\":%s,\"PayloadUnchanged\":true,\"Filesystem\":\"%s\"}\n",before.st_dev==after.st_dev&&before.st_ino==after.st_ino?"true":"false",fs.f_fstypename);return 0;
}
