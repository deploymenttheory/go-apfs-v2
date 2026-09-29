// Test-only tracing of unchanged Apple ACL-stage functions and real SDK calls.
#include <sys/types.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <copyfile.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int trace_capture(int,struct stat *,filesec_t);
static int trace_write(int,filesec_t);
static int trace_property(filesec_t,filesec_property_t,const void *);
// Reuse the existing native helpers and source extraction, not another codec.
#define fstatx_np trace_capture
#define fchmodx_np trace_write
#define filesec_set_property trace_property
#define main filesec_reference_main
#include "filesec.c"
#undef main
#undef filesec_set_property
#undef fchmodx_np
#undef fstatx_np

static int tracing, event_count, request_count, applied;
static const char *events[16];
static char *requests[2];
static filesec_t source_security;
static int cleanup_fd=-1,cleanup_plain;
static void restore_cleanup(void){if(cleanup_fd>=0){if(!cleanup_plain){(void)fchflags(cleanup_fd,0);(void)fchmod(cleanup_fd,0700);}(void)close(cleanup_fd);}}
static void event(const char *name){if(event_count>=16)fail("event overflow");events[event_count++]=name;}
static int trace_capture(int fd,struct stat *st,filesec_t sec){if(tracing)event("capture");return fstatx_np(fd,st,sec);}
static void security_json(FILE *out,filesec_t sec){
    acl_t acl=NULL;errno=0;
    if(filesec_get_property(sec,FILESEC_ACL,&acl)){if(errno!=ENOENT)fail("request ACL");acl=(acl_t)_FILESEC_REMOVE_ACL;}
    ssize_t n=acl_size(acl);if(n<44)fail("request size");struct kauth_filesec *p=calloc((size_t)n,1);if(!p)fail("allocate request");
    if(acl_copy_ext_native(p,acl,n)!=n)fail("request export");
    if(filesec_get_property(sec,FILESEC_UUID,&p->fsec_owner)&&errno!=ENOENT)fail("request owner UUID");
    if(filesec_get_property(sec,FILESEC_GRPUUID,&p->fsec_group)&&errno!=ENOENT)fail("request group UUID");
    uid_t uid;gid_t gid;mode_t mode;
    if(filesec_get_property(sec,FILESEC_OWNER,&uid)||filesec_get_property(sec,FILESEC_GROUP,&gid)||filesec_get_property(sec,FILESEC_MODE,&mode))fail("request metadata");
    fprintf(out,"{\"Security\":\"");for(ssize_t i=0;i<n;i++)fprintf(out,"%02x",((unsigned char *)p)[i]);
    fprintf(out,"\",\"UID\":%u,\"GID\":%u,\"Mode\":%u}",uid,gid,mode);
    free(p);if(acl!=(acl_t)_FILESEC_REMOVE_ACL)acl_free(acl);
}
static int trace_write(int fd,filesec_t sec){
    if(tracing){event("write");if(request_count>=2)fail("unbounded retry");size_t size=0;FILE *out=open_memstream(&requests[request_count++],&size);if(!out)fail("request stream");security_json(out,sec);if(fclose(out))fail("request stream close");}
    errno=0;int rc=fchmodx_np(fd,sec);if(tracing&&!rc)applied=1;return rc;
}
static int trace_property(filesec_t sec,filesec_property_t prop,const void *value){
    if(tracing&&sec==source_security&&!value){
        switch(prop){case FILESEC_ACL:event("clear-acl");break;case FILESEC_UUID:event("clear-owner");break;case FILESEC_GRPUUID:event("clear-group");break;default:fail("unexpected source reset");}
    }
    return filesec_set_property(sec,prop,value);
}
static int source_mask(void){
    int mask=0,present=0;filesec_property_t props[]={FILESEC_ACL,FILESEC_UUID,FILESEC_GRPUUID};
    for(int i=0;i<3;i++){if(filesec_query_property(source_security,props[i],&present))fail("source property query");if(present)mask|=1<<i;}
    return mask;
}
static int write_request(int fd,const char *line){
    unsigned uid,gid,mode;char encoded[6233];
    if(sscanf(line,"W %u %u %u %6232s",&uid,&gid,&mode,encoded)!=4||mode>0177777)fail("request fields");
    size_t n=strlen(encoded);if(n<88||n%2)fail("request length");unsigned char *bytes=calloc(n/2,1);if(!bytes)fail("request allocate");
    for(size_t i=0;i<n;i+=2){unsigned v;if(sscanf(encoded+i,"%2x",&v)!=1)fail("request hex");bytes[i/2]=(unsigned char)v;}
    struct kauth_filesec *p=(void *)bytes;
    if(p->fsec_magic!=KAUTH_FILESEC_MAGIC||p->fsec_entrycount>128||KAUTH_FILESEC_SIZE(p->fsec_entrycount)!=n/2)fail("request record");
    acl_t acl=acl_copy_int_native(p);if(!acl)fail("request import");filesec_t sec=filesec_init();if(!sec)fail("request filesec");
    uid_t owner=uid;gid_t group=gid;mode_t permissions=(mode_t)mode;
    if(filesec_set_property(sec,FILESEC_ACL,&acl)||filesec_set_property(sec,FILESEC_UUID,&p->fsec_owner)||filesec_set_property(sec,FILESEC_GRPUUID,&p->fsec_group)||filesec_set_property(sec,FILESEC_OWNER,&owner)||filesec_set_property(sec,FILESEC_GROUP,&group)||filesec_set_property(sec,FILESEC_MODE,&permissions))fail("request properties");
    int rc=trace_write(fd,sec),error=errno;filesec_free(sec);acl_free(acl);free(bytes);errno=error;return rc;
}
int main(int argc,char **argv){
    if(argc!=8)return 2;const char *path=argv[1];int directory=!strcmp(argv[2],"directory"),plain=!strcmp(argv[7],"plain");
    mode_t mode=(mode_t)strtoul(argv[3],NULL,8);unsigned flags=(unsigned)strtoul(argv[4],NULL,0);
    if(flags&~(UF_IMMUTABLE|UF_APPEND|UF_HIDDEN|UF_NODUMP))return 2;
    if(directory&&mkdir(path,0700))fail("directory create");int fd=open(path,directory?O_RDONLY:(O_CREAT|O_EXCL|O_RDWR),0600);if(fd<0)fail("destination open");
    cleanup_fd=fd;cleanup_plain=plain;if(atexit(restore_cleanup))fail("cleanup handler");
    struct statfs filesystem;if(fstatfs(fd,&filesystem))fail("filesystem identity");
    if(strcmp(filesystem.f_fstypename,plain?"msdos":"apfs"))fail("unexpected filesystem");
    acl_t baseline=acl_from_text("!#acl 1\nuser:11234567-89AB-CDEF-0123-456789ABCDEF:::allow:read\n");if(!baseline)fail("baseline parse");
    if(!plain&&(fchown(fd,(uid_t)-1,getegid())||acl_set_fd(fd,baseline)||fchmod(fd,mode)||fchflags(fd,flags)))fail("baseline metadata");
    source_security=filesec_init();if(!source_security)fail("source state");uid_t uid=123;gid_t gid=456;mode_t source_mode=0640;unsigned char owner[16]={17},group[16]={34};
    if(filesec_set_property(source_security,FILESEC_ACL,&baseline)||filesec_set_property(source_security,FILESEC_UUID,owner)||filesec_set_property(source_security,FILESEC_GRPUUID,group)||filesec_set_property(source_security,FILESEC_OWNER,&uid)||filesec_set_property(source_security,FILESEC_GROUP,&gid)||filesec_set_property(source_security,FILESEC_MODE,&source_mode))fail("source properties");acl_free(baseline);
    if(source_mask()!=7)fail("source setup");
    struct stat before,after;printf("{\"Before\":");snapshot(fd,&before);printf("}\n");fflush(stdout);
    struct _copyfile_state state={.dst_fd=fd,.fsec=source_security,.dst=path};int rc=0,error=0;
    tracing=1;
    if(!strcmp(argv[6],"native")){
        size_t n;unsigned char *text=load(argv[5],&n);errno=0;rc=n?copyfile_unpack_acl(&state,(uint32_t)n,text):0;error=rc?errno:0;free(text);
        if(!!(state.internal_flags&cfSetDestinationPerms)!=applied)fail("native applied state");
    }else if(!strcmp(argv[6],"go")){
        char *line=NULL;size_t capacity=0;
        for(;;){ssize_t n=getline(&line,&capacity,stdin);if(n<1)fail("protocol EOF");
            if(line[0]=='D')break;
            if(line[0]=='C'){struct stat st;printf("{\"Captured\":");snapshot(fd,&st);printf("}\n");}
            else if(line[0]=='W'){rc=write_request(fd,line);error=rc?errno:0;printf("{\"Errno\":%d}\n",error);}
            else if(line[0]=='R'){int reset=copyfile_unset_acl(&state);int e=reset?errno:0;printf("{\"Errno\":%d}\n",e);if(reset){rc=-1;error=e;}}
            else fail("unknown protocol command");fflush(stdout);
        }free(line);
    }else return 2;
    tracing=0;uid_t final_uid;gid_t final_gid;mode_t final_mode;
    if(filesec_get_property(source_security,FILESEC_OWNER,&final_uid)||filesec_get_property(source_security,FILESEC_GROUP,&final_gid)||filesec_get_property(source_security,FILESEC_MODE,&final_mode))fail("source numeric readback");
    printf("{\"Filesystem\":\"%s\",\"Code\":%d,\"Errno\":%d,\"Applied\":%s,\"After\":",filesystem.f_fstypename,rc,error,applied?"true":"false");snapshot(fd,&after);
    printf(",\"IdentityUnchanged\":%s,\"SourceMask\":%d,\"SourceMetadataUnchanged\":%s,\"Events\":[",before.st_dev==after.st_dev&&before.st_ino==after.st_ino?"true":"false",source_mask(),final_uid==uid&&final_gid==gid&&final_mode==source_mode?"true":"false");
    for(int i=0;i<event_count;i++)printf("%s\"%s\"",i?",":"",events[i]);printf("],\"Requests\":[");
    for(int i=0;i<request_count;i++){printf("%s%s",i?",":"",requests[i]);free(requests[i]);}printf("]}\n");
    filesec_free(source_security);if((!plain&&(fchflags(fd,0)||fchmod(fd,0700)))||close(fd))fail("cleanup");cleanup_fd=-1;return 0;
}
