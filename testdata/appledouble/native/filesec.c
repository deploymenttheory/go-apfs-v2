// Native security-record/application oracle. Test-only, never linked into Go.
#include <sys/types.h>
#include <sys/acl.h>
#include <sys/kauth.h>
#include <sys/stat.h>
#include <copyfile.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

_Static_assert(KAUTH_FILESEC_SIZE(0) == 44, "security header size");
_Static_assert(offsetof(struct kauth_filesec, fsec_owner) == 4, "owner UUID");
_Static_assert(offsetof(struct kauth_filesec, fsec_group) == 20, "group UUID");
_Static_assert(sizeof(struct kauth_ace) == 24, "ACE size");
// A local state object for the extracted static application function. This is
// not the private copyfile ABI and is never passed to the system copyfile API.
struct _copyfile_state {int dst_fd; filesec_t fsec; unsigned internal_flags; const char *dst;};
#define cfSetDestinationPerms (1 << 12)
#define copyfile_debug(...) ((void)0)
#define copyfile_warn(...) ((void)0)
#include "filesec-source.h"

static void fail(const char *why) {perror(why);exit(2);}
static unsigned char *load(const char *path, size_t *size) {
    FILE *f=fopen(path,"rb");if (!f) fail("input open");
    struct stat st;if (fstat(fileno(f),&st)||st.st_size<0||st.st_size>1048576) fail("input size");
    *size=(size_t)st.st_size;unsigned char *p=calloc(*size+1,1);if (!p) fail("allocate");
    if (fread(p,1,*size,f)!=*size||fclose(f)) fail("input read");return p;
}
static void save(const char *path, const void *p,size_t size) {
    FILE *f=fopen(path,"wb");if (!f) fail("output open");
    if (fwrite(p,1,size,f)!=size||fclose(f)) fail("output write");
}
static void hex(const void *data,size_t n) {
    const unsigned char *p=data;printf("\"");for(size_t i=0;i<n;i++)printf("%02x",p[i]);printf("\"");
}
static void snapshot(int fd,struct stat *st) {
    filesec_t sec=filesec_init();if (!sec) fail("filesec init");
    if (fstatx_np(fd,st,sec)) fail("destination stat");
    acl_t acl=NULL;errno=0;
    if (filesec_get_property(sec,FILESEC_ACL,&acl)) {if(errno!=ENOENT)fail("read ACL");acl=(acl_t)_FILESEC_REMOVE_ACL;}
    ssize_t n=acl_size(acl);if(n<44)fail("ACL size");
    struct kauth_filesec *record=calloc((size_t)n,1);if(!record)fail("allocate ACL");
    if(acl_copy_ext_native(record,acl,n)!=n)fail("export ACL");
    if(filesec_get_property(sec,FILESEC_UUID,&record->fsec_owner)&&errno!=ENOENT)fail("owner UUID");
    if(filesec_get_property(sec,FILESEC_GRPUUID,&record->fsec_group)&&errno!=ENOENT)fail("group UUID");
    printf("{\"Security\":");hex(record,(size_t)n);
    printf(",\"UID\":%u,\"GID\":%u,\"Mode\":%u,\"Flags\":%u}",st->st_uid,st->st_gid,st->st_mode,st->st_flags);
    if(acl!=(acl_t)_FILESEC_REMOVE_ACL)acl_free(acl);free(record);filesec_free(sec);
}
static int apply_packet(int fd) {
    char *line=NULL;size_t capacity=0;ssize_t n=getline(&line,&capacity,stdin);
    if(n<1)fail("Go request missing");if(line[n-1]=='\n')line[--n]=0;
    if(!strcmp(line,"-")){free(line);return 0;}
    if(n<88||n>6232||n%2)fail("Go request size");
    unsigned char *p=calloc((size_t)n/2,1);if(!p)fail("Go request allocate");
    for(ssize_t i=0;i<n;i+=2){unsigned v;if(sscanf(line+i,"%2x",&v)!=1)fail("Go request hex");p[i/2]=(unsigned char)v;}
    free(line);struct kauth_filesec *record=(void *)p;
    if(record->fsec_magic!=KAUTH_FILESEC_MAGIC||record->fsec_entrycount>128||KAUTH_FILESEC_SIZE(record->fsec_entrycount)!=(size_t)n/2)fail("Go record validation");
    acl_t acl=acl_copy_int_native(record);if(!acl)fail("Go ACL import");
    filesec_t sec=filesec_init();if(!sec)fail("Go filesec init");struct stat st;
    if(fstatx_np(fd,&st,sec)||filesec_set_property(sec,FILESEC_ACL,&acl)||
       filesec_set_property(sec,FILESEC_UUID,&record->fsec_owner)||
       filesec_set_property(sec,FILESEC_GRPUUID,&record->fsec_group))fail("Go security request");
    errno=0;int rc=fchmodx_np(fd,sec),error=errno;
    filesec_free(sec);acl_free(acl);free(p);errno=error;return rc;
}
int main(int argc,char **argv) {
    if(argc==4&&!strcmp(argv[1],"convert")) {
        size_t n;unsigned char *p=load(argv[2],&n);
        if(n<44)fail("short security record");struct kauth_filesec *s=(void *)p;
        uint32_t count=ntohl(s->fsec_entrycount);
        if(ntohl(s->fsec_magic)!=KAUTH_FILESEC_MAGIC || (count!=KAUTH_FILESEC_NOACL&&(count>128||n<KAUTH_FILESEC_SIZE(count))))fail("unsafe security record");
        // Independent public libSystem conversion of every present ACL.
        if(count!=KAUTH_FILESEC_NOACL) {
            acl_t a=acl_copy_int(p);if(!a)fail("portable ACL import");
            ssize_t size=acl_size(a);void *native=malloc((size_t)size);if(!native)fail("native allocate");
            if(acl_copy_ext_native(native,a,size)!=size)fail("native export");
            kauth_filesec_acl_setendian(KAUTH_ENDIAN_HOST,s,NULL);
            if(memcmp((char *)native+36,p+36,(size_t)size-36))fail("native conversion differs");
            acl_free(a);free(native);
        }else kauth_filesec_acl_setendian(KAUTH_ENDIAN_HOST,s,NULL);
        save(argv[3],p,n);printf("{\"Owner\":");hex(&s->fsec_owner,16);printf(",\"Group\":");hex(&s->fsec_group,16);printf("}\n");free(p);return 0;
    }
    if(argc!=7)return 2;
    const char *path=argv[1];int directory=!strcmp(argv[2],"directory");
    if(!directory&&strcmp(argv[2],"file"))return 2;
    mode_t mode=(mode_t)strtoul(argv[3],NULL,8);unsigned flags=(unsigned)strtoul(argv[4],NULL,0);
    if(flags&~(UF_IMMUTABLE|UF_APPEND|UF_HIDDEN|UF_NODUMP))return 2;
    if(directory&&mkdir(path,0700))fail("create directory");
    int fd=open(path,directory?O_RDONLY:(O_CREAT|O_EXCL|O_RDWR),0600);if(fd<0)fail("create destination");
    // Use our effective group so setup does not silently strip the set-GID bit.
    if(fchown(fd,(uid_t)-1,getegid()))fail("fixture group");
    acl_t baseline=acl_from_text("!#acl 1\nuser:11234567-89AB-CDEF-0123-456789ABCDEF:::allow:read\n");
    if(!baseline||acl_set_fd(fd,baseline))fail("baseline ACL");acl_free(baseline);
    if(fchmod(fd,mode)||fchflags(fd,flags))fail("baseline metadata");
    struct stat before,after;printf("{\"Before\":");snapshot(fd,&before);printf("}\n");fflush(stdout);
    int rc;errno=0;
    if(!strcmp(argv[6],"native")) {
        size_t n;unsigned char *text=load(argv[5],&n);
        struct _copyfile_state state={.dst_fd=fd,.fsec=filesec_init(),.dst=path};if(!state.fsec)fail("state allocation");
        struct stat st;if(fstatx_np(fd,&st,state.fsec))fail("state capture");
        rc=n?copyfile_unpack_acl(&state,(uint32_t)n,text):0;
        int e=errno;filesec_free(state.fsec);free(text);errno=e;
    }else if(!strcmp(argv[6],"go"))rc=apply_packet(fd);
    else return 2;
    int error=rc?errno:0;
    printf("{\"Code\":%d,\"Errno\":%d,\"After\":",rc,error);snapshot(fd,&after);
    printf(",\"IdentityUnchanged\":%s}\n",before.st_dev==after.st_dev&&before.st_ino==after.st_ino?"true":"false");
    // Always remove test restrictions, including after a measured write refusal.
    if(fchflags(fd,0)||fchmod(fd,0700)||close(fd))fail("cleanup restrictions");
    return 0;
}
