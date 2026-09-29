// Test-only oracle: unchanged Libc request construction and real extended chmod.
#include <sys/attr.h>
#include <sys/mount.h>
#define main filesec_reference_main
#include "filesec.c"
#undef main
#include "acl-chmod-source.h"
extern int __fchmod_extended(int,uid_t,gid_t,int,kauth_filesec_t);
_Static_assert(sizeof(mode_t)==2,"Darwin mode width");
static struct attrlist chmod_attrs={.bitmapcount=ATTR_BIT_MAP_COUNT,.commonattr=0x01c38000};
static int cleanup_fd=-1;
static void cleanup(void){if(cleanup_fd>=0){(void)fchflags(cleanup_fd,0);(void)fchmod(cleanup_fd,0700);(void)close(cleanup_fd);}}
static void read_attributes(int fd){
    unsigned char b[56+44+128*24]={0};if(fgetattrlist(fd,&chmod_attrs,b,sizeof(b),0))fail("attribute readback");uint32_t n;memcpy(&n,b,4);if(n<56||n>sizeof(b))fail("attribute length");hex(b,n);
}
static int capture_request(void *obj,uid_t uid,gid_t gid,int mode,kauth_filesec_t s){
    if(!s||s==(kauth_filesec_t)_FILESEC_REMOVE_ACL)fail("missing full security request");
    size_t size=KAUTH_FILESEC_COPYSIZE(s);if(size<44||size>44+128*24)fail("request size");
    save((const char *)obj,s,size);printf("{\"UID\":%u,\"GID\":%u,\"Mode\":%d}\n",uid,gid,mode);return 0;
}
static int write_request(int fd){
    char *line=NULL;size_t capacity=0;ssize_t n=getline(&line,&capacity,stdin);if(n<1)fail("request EOF");if(line[0]=='-'){free(line);return 0;}
    unsigned uid,gid,mode;char encoded[6233];if(sscanf(line,"%u %u %u %6232s",&uid,&gid,&mode,encoded)!=4||mode>65535)fail("request fields");free(line);
    size_t length=strlen(encoded);if(length<88||length%2)fail("request length");unsigned char *b=calloc(length/2,1);if(!b)fail("request allocation");
    for(size_t i=0;i<length;i+=2){unsigned v;if(sscanf(encoded+i,"%2x",&v)!=1)fail("request hex");b[i/2]=(unsigned char)v;}
    struct kauth_filesec *s=(void *)b;if(s->fsec_magic!=KAUTH_FILESEC_MAGIC||(s->fsec_entrycount!=KAUTH_FILESEC_NOACL&&s->fsec_entrycount>128)||KAUTH_FILESEC_COPYSIZE(s)!=length/2)fail("request extent");
    errno=0;int rc=__fchmod_extended(fd,uid,gid,(int)mode,s),error=errno;free(b);errno=error;return rc;
}
int main(int argc,char **argv){
    if(argc==7&&!strcmp(argv[1],"pack")){
        size_t size;unsigned char *b=load(argv[2],&size);if(size<44)fail("pack source");struct kauth_filesec *s=(void *)b;
        if(s->fsec_magic!=KAUTH_FILESEC_MAGIC||(s->fsec_entrycount!=KAUTH_FILESEC_NOACL&&s->fsec_entrycount>128)||KAUTH_FILESEC_COPYSIZE(s)!=size)fail("pack extent");
        uid_t uid=(uid_t)strtoul(argv[4],NULL,0);gid_t gid=(gid_t)strtoul(argv[5],NULL,0);mode_t mode=(mode_t)strtoul(argv[6],NULL,0);
        filesec_t sec=filesec_init();if(!sec)fail("pack filesec");
        if(filesec_set_property(sec,FILESEC_OWNER,&uid)||filesec_set_property(sec,FILESEC_GROUP,&gid)||filesec_set_property(sec,FILESEC_MODE,&mode)||filesec_set_property(sec,FILESEC_UUID,&s->fsec_owner)||filesec_set_property(sec,FILESEC_GRPUUID,&s->fsec_group)||filesec_set_property(sec,FILESEC_ACL_ALLOCSIZE,&size)||filesec_set_property(sec,FILESEC_ACL_RAW,&b))fail("pack properties");
        if(chmodx1(argv[3],capture_request,sec))fail("pack callback");filesec_free(sec);return 0;
    }
    if(argc!=8)return 2;const char *path=argv[1];int directory=!strcmp(argv[2],"directory"),initial=atoi(argv[7]);if(initial < -1||initial>128)return 2;
    mode_t mode=(mode_t)strtoul(argv[3],NULL,8);unsigned flags=(unsigned)strtoul(argv[4],NULL,0);if(flags&~(UF_IMMUTABLE|UF_APPEND))return 2;
    if(directory&&mkdir(path,0700))fail("mkdir");int fd=open(path,directory?O_RDONLY:(O_CREAT|O_EXCL|O_RDWR),0600);if(fd<0)fail("open destination");cleanup_fd=fd;if(atexit(cleanup))fail("cleanup registration");
    struct statfs fs;if(fstatfs(fd,&fs)||strcmp(fs.f_fstypename,"apfs"))fail("requires APFS");
    char text[16384]="!#acl 1\n";if(initial==0)strcpy(text,"!#acl 1 no_inherit\n");for(int i=0;i<initial;i++)strcat(text,"user:11234567-89AB-CDEF-0123-456789ABCDEF:::allow:read\n");
    acl_t baseline=acl_from_text(text);if(!baseline||fchown(fd,(uid_t)-1,getegid())||acl_set_fd(fd,baseline)||fchmod(fd,mode)||fchflags(fd,flags))fail("baseline setup");acl_free(baseline);
    struct stat before,after;printf("{\"Before\":");snapshot(fd,&before);printf(",\"Attributes\":");read_attributes(fd);printf("}\n");fflush(stdout);
    int rc;
    if(!strcmp(argv[6],"native")){
        size_t n;unsigned char *input=load(argv[5],&n);struct _copyfile_state state={.dst_fd=fd,.fsec=filesec_init(),.dst=path};if(!state.fsec)fail("source state");struct stat st;if(fstatx_np(fd,&st,state.fsec))fail("source capture");errno=0;rc=n?copyfile_unpack_acl(&state,(uint32_t)n,input):0;int error=errno;filesec_free(state.fsec);free(input);errno=error;
    }else if(!strcmp(argv[6],"go"))rc=write_request(fd);else return 2;
    int error=rc?errno:0;printf("{\"Code\":%d,\"Errno\":%d,\"After\":",rc,error);snapshot(fd,&after);printf(",\"Attributes\":");read_attributes(fd);
    printf(",\"IdentityUnchanged\":%s}\n",before.st_dev==after.st_dev&&before.st_ino==after.st_ino?"true":"false");return 0;
}
