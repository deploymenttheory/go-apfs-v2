// Test-only attribute ABI oracle; production code never links native helpers.
#include <sys/attr.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <stddef.h>
#define main filesec_reference_main
#include "filesec.c"
#undef main
#ifndef lmin
#define lmin(a,b) ((a)<(b)?(a):(b))
#endif
#include "acl-attributes-source.h"
#define SECURITY_MASK (ATTR_CMN_OWNERID|ATTR_CMN_GRPID|ATTR_CMN_ACCESSMASK|ATTR_CMN_EXTENDED_SECURITY|ATTR_CMN_UUID|ATTR_CMN_GRPUUID)
struct fields {uint32_t uid,gid,mode;struct attrreference security;guid_t owner,group;};
struct response {uint32_t length;struct fields fields;};
_Static_assert(SECURITY_MASK==0x01c38000,"attribute mask");
_Static_assert(sizeof(struct fields)==52,"set header size");
_Static_assert(sizeof(struct response)==56,"get header size");
_Static_assert(offsetof(struct fields,security)==12,"security reference offset");
_Static_assert(offsetof(struct fields,owner)==20,"owner field offset");
_Static_assert(offsetof(struct fields,group)==36,"group field offset");
static struct attrlist attributes={.bitmapcount=ATTR_BIT_MAP_COUNT,.commonattr=SECURITY_MASK};
static char *build_record(struct kauth_filesec *s,size_t length,uint32_t uid,uint32_t gid,uint32_t mode,int reading,int absent,size_t *packed_size){
    size_t fixed=reading?56:52,total=fixed+((reading&&absent)?0:length);char *bytes=calloc(total,1);if(!bytes)fail("pack allocate");
    struct _attrlist_buf b={.base=bytes,.fixedcursor=bytes+(reading?4:0),.varcursor=bytes+fixed,.allocated=(ssize_t)total};
    if(reading)*(uint32_t *)bytes=(uint32_t)total;
    attrlist_pack_fixed(&b,&uid,4);attrlist_pack_fixed(&b,&gid,4);attrlist_pack_fixed(&b,&mode,4);
    struct kauth_filesec header={.fsec_magic=KAUTH_FILESEC_MAGIC};
    if(reading&&absent)attrlist_pack_variable(&b,NULL,0);
    else attrlist_pack_variable2(&b,&header,offsetof(struct kauth_filesec,fsec_acl),&s->fsec_acl,(ssize_t)length-36);
    attrlist_pack_fixed(&b,&s->fsec_owner,16);attrlist_pack_fixed(&b,&s->fsec_group,16);
    if(b.fixedcursor!=bytes+fixed||b.varcursor!=bytes+total)fail("packed cursor");*packed_size=total;return bytes;
}
static void pack_record(const char *path,struct kauth_filesec *s,size_t length,uint32_t uid,uint32_t gid,uint32_t mode,int reading,int absent){
    size_t size;char *bytes=build_record(s,length,uid,gid,mode,reading,absent,&size);save(path,bytes,size);free(bytes);
}
static int native_attributes(int fd,const char *path){
    size_t size;unsigned char *text=load(path,&size);if(!size){free(text);return 0;}
    acl_t acl=acl_from_text((char *)text);free(text);if(!acl)return 0;
    union{uint64_t alignment;unsigned char bytes[56+44+128*24];}buffer={0};
    if(fgetattrlist(fd,&attributes,buffer.bytes,sizeof(buffer.bytes),0))fail("native attributes capture");
    struct response *r=(void *)buffer.bytes;ssize_t length=acl_size(acl);if(length<44)fail("native ACL size");
    struct kauth_filesec *s=calloc((size_t)length,1);if(!s)fail("native ACL allocate");if(acl_copy_ext_native(s,acl,length)!=length)fail("native ACL export");
    s->fsec_owner=r->fields.owner;s->fsec_group=r->fields.group;
    char *request=build_record(s,(size_t)length,r->fields.uid,r->fields.gid,r->fields.mode,0,0,&size);
    errno=0;int rc=fsetattrlist(fd,&attributes,request,size,0),error=errno;free(request);free(s);acl_free(acl);errno=error;return rc;
}
static int cleanup_fd=-1;
static void cleanup(void){if(cleanup_fd>=0){(void)fchflags(cleanup_fd,0);(void)fchmod(cleanup_fd,0700);(void)close(cleanup_fd);}}
static void read_attributes(int fd){
    unsigned char data[56+44+128*24]={0};if(fgetattrlist(fd,&attributes,data,sizeof(data),0))fail("fgetattrlist");
    uint32_t length;memcpy(&length,data,4);if(length<56||length>sizeof(data))fail("attribute response length");hex(data,length);
}
static int write_attributes(int fd){
    char *line=NULL;size_t cap=0;ssize_t n=getline(&line,&cap,stdin);if(n<1)fail("attribute request missing");if(line[n-1]=='\n')line[--n]=0;
    if(!strcmp(line,"-")){free(line);return 0;}if(n<192||n>6336||n%2)fail("attribute request size");
    unsigned char *b=calloc((size_t)n/2,1);if(!b)fail("attribute request allocate");for(ssize_t i=0;i<n;i+=2){unsigned v;if(sscanf(line+i,"%2x",&v)!=1)fail("attribute request hex");b[i/2]=(unsigned char)v;}
    free(line);errno=0;int rc=fsetattrlist(fd,&attributes,b,(size_t)n/2,0),error=errno;free(b);errno=error;return rc;
}
int main(int argc,char **argv){
    if(argc==9&&!strcmp(argv[1],"pack")){
        size_t n;unsigned char *b=load(argv[2],&n);if(n<44)fail("pack source size");struct kauth_filesec *s=(void *)b;
        if(s->fsec_magic!=KAUTH_FILESEC_MAGIC||(s->fsec_entrycount!=KAUTH_FILESEC_NOACL&&s->fsec_entrycount>128))fail("pack source fields");
        size_t length=KAUTH_FILESEC_COPYSIZE(s);if(n!=length)fail("pack source extent");int absent=atoi(argv[8]);
        if(absent){if(s->fsec_entrycount!=KAUTH_FILESEC_NOACL)fail("absent source");s->fsec_flags=0;}
        uint32_t uid=(uint32_t)strtoul(argv[5],NULL,0),gid=(uint32_t)strtoul(argv[6],NULL,0),mode=(uint32_t)strtoul(argv[7],NULL,0);
        pack_record(argv[3],s,length,uid,gid,mode,1,absent);pack_record(argv[4],s,length,uid,gid,mode,0,0);
        printf("{\"Security\":");hex(s,length);printf(",\"UID\":%u,\"GID\":%u,\"Mode\":%u}\n",uid,gid,mode);free(b);return 0;
    }
    if(argc!=8)return 2;const char *path=argv[1];int directory=!strcmp(argv[2],"directory"),initial=atoi(argv[7]);
    if(initial < -1 || initial > 128)return 2; mode_t mode=(mode_t)strtoul(argv[3],NULL,8);unsigned flags=(unsigned)strtoul(argv[4],NULL,0);
    if(flags&~(UF_IMMUTABLE|UF_APPEND))return 2;
    if(directory&&mkdir(path,0700))fail("create directory");int fd=open(path,directory?O_RDONLY:(O_CREAT|O_EXCL|O_RDWR),0600);if(fd<0)fail("destination open");cleanup_fd=fd;if(atexit(cleanup))fail("cleanup registration");
    struct statfs filesystem;if(fstatfs(fd,&filesystem)||strcmp(filesystem.f_fstypename,"apfs"))fail("requires APFS destination");
    char text[16384]="!#acl 1\n";if(initial==0)strcpy(text,"!#acl 1 no_inherit\n");
    for(int i=0;i<initial;i++)strcat(text,"user:11234567-89AB-CDEF-0123-456789ABCDEF:::allow:read\n");
    acl_t acl=acl_from_text(text);if(!acl||fchown(fd,(uid_t)-1,getegid())||acl_set_fd(fd,acl)||fchmod(fd,mode)||fchflags(fd,flags))fail("baseline setup");acl_free(acl);
    struct stat before,after;printf("{\"Before\":");snapshot(fd,&before);printf(",\"Attributes\":");read_attributes(fd);printf("}\n");fflush(stdout);
    int rc;
    if(!strcmp(argv[6],"reference")){
        size_t n;unsigned char *input=load(argv[5],&n);struct _copyfile_state state={.dst_fd=fd,.fsec=filesec_init(),.dst=path};if(!state.fsec)fail("reference source state");
        struct stat st;if(fstatx_np(fd,&st,state.fsec))fail("reference capture");rc=n?copyfile_unpack_acl(&state,(uint32_t)n,input):0;int e=errno;filesec_free(state.fsec);free(input);errno=e;
    }else if(!strcmp(argv[6],"native"))rc=native_attributes(fd,argv[5]);else if(!strcmp(argv[6],"go"))rc=write_attributes(fd);else return 2;
    int error=rc?errno:0;printf("{\"Code\":%d,\"Errno\":%d,\"After\":",rc,error);snapshot(fd,&after);printf(",\"Attributes\":");read_attributes(fd);
    printf(",\"IdentityUnchanged\":%s}\n",before.st_dev==after.st_dev&&before.st_ino==after.st_ino?"true":"false");return 0;
}
