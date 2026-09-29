// Test-only non-owner oracle. Targets come from a disposable SDK-written image.
#include <sys/types.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int counted_capture(int,struct stat *,filesec_t);
static int counted_write(int,filesec_t);
static int counted_property(filesec_t,filesec_property_t,const void *);
#define fstatx_np counted_capture
#define fchmodx_np counted_write
#define filesec_set_property counted_property
#define main filesec_reference_main
#include "filesec.c"
#undef main
#undef fchmodx_np
#undef fstatx_np
#undef filesec_set_property
extern int __fchmod_extended(int,uid_t,gid_t,int,kauth_filesec_t);
static int counting,captures,writes,resets;
static filesec_t source_security;
static int counted_property(filesec_t sec,filesec_property_t prop,const void *value){if(counting&&sec==source_security&&prop==FILESEC_ACL&&!value)resets++;return filesec_set_property(sec,prop,value);}
static int counted_capture(int fd,struct stat *st,filesec_t sec){if(counting)captures++;return fstatx_np(fd,st,sec);}
static int counted_write(int fd,filesec_t sec){if(counting)writes++;return fchmodx_np(fd,sec);}
static void numeric_snapshot(const struct stat *st){printf("{\"Security\":\"\",\"UID\":%u,\"GID\":%u,\"Mode\":%u,\"Flags\":%u}",st->st_uid,st->st_gid,st->st_mode,st->st_flags);}
static void observe(int fd,struct stat *st){
    if(fstat(fd,st))fail("plain stat");struct stat extended;filesec_t sec=filesec_init();if(!sec)fail("observe state");errno=0;int rc=fstatx_np(fd,&extended,sec),error=rc?errno:0;filesec_free(sec);
    printf("{\"Metadata\":");if(!error)snapshot(fd,&extended);else numeric_snapshot(st);
    struct attrlist attrs={.bitmapcount=ATTR_BIT_MAP_COUNT,.commonattr=0x01c38000};unsigned char b[3172]={0};errno=0;rc=fgetattrlist(fd,&attrs,b,sizeof(b),0);int ae=rc?errno:0;
    printf(",\"SecurityErrno\":%d,\"AttributeErrno\":%d,\"Attributes\":",error,ae);
    if(ae)printf("null");else {uint32_t n;memcpy(&n,b,4);if(n<56||n>sizeof(b))fail("attribute length");hex(b,n);}printf("}");
}
static int direct_write(int fd,const char *line){
    unsigned uid,gid,mode;char encoded[6233];if(sscanf(line,"W %u %u %u %6232s",&uid,&gid,&mode,encoded)!=4||mode>65535)fail("write fields");size_t n=strlen(encoded);if(n<88||n%2)fail("write length");
    unsigned char *b=calloc(n/2,1);if(!b)fail("write allocation");for(size_t i=0;i<n;i+=2){unsigned v;if(sscanf(encoded+i,"%2x",&v)!=1)fail("write hex");b[i/2]=(unsigned char)v;}
    struct kauth_filesec *s=(void *)b;if(s->fsec_magic!=KAUTH_FILESEC_MAGIC||s->fsec_entrycount>128||KAUTH_FILESEC_SIZE(s->fsec_entrycount)!=n/2)fail("write extent");
    writes++;errno=0;int rc=__fchmod_extended(fd,uid,gid,(int)mode,s),error=errno;free(b);errno=error;return rc;
}
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"identity")){
        if(getuid()==0||getuid()!=geteuid()||getgid()!=getegid()||getuid()==60000||getgid()==60000)fail("requires ordinary non-root actor");int n=getgroups(0,NULL);if(n<0)fail("group count");gid_t *groups=calloc((size_t)n+1,sizeof(gid_t));if(!groups||getgroups(n,groups)!=n)fail("group list");
        printf("{\"UID\":%u,\"GID\":%u,\"Groups\":[",getuid(),getgid());for(int i=0;i<n;i++){if(groups[i]==60000)fail("foreign group belongs to actor");printf("%s%u",i?",":"",groups[i]);}printf("]}\n");free(groups);return 0;
    }
    if(argc==4&&!strcmp(argv[1],"seed")){
        size_t n;unsigned char *text=load(argv[2],&n);acl_t acl=acl_from_text((char *)text);if(!acl)fail("seed ACL parse");ssize_t size=acl_size(acl);if(size<44||size>3116)fail("seed size");void *b=calloc((size_t)size,1);if(!b)fail("seed allocation");if(acl_copy_ext(b,acl,size)!=size)fail("seed export");save(argv[3],b,(size_t)size);hex(b,(size_t)size);printf("\n");free(text);free(b);acl_free(acl);return 0;
    }
    if(argc!=7)return 2;
    int fd=open(argv[1],O_RDONLY|O_NOFOLLOW);if(fd<0)fail("held destination open");
    struct statfs fs;if(fstatfs(fd,&fs)||strcmp(fs.f_fstypename,argv[6])||(fs.f_flags&(MNT_IGNORE_OWNERSHIP|MNT_RDONLY)))fail("requires expected ownership-enforcing filesystem");
    struct stat before,after;if(fstat(fd,&before))fail("baseline stat");uid_t uid=(uid_t)strtoul(argv[4],NULL,0);gid_t gid=(gid_t)strtoul(argv[5],NULL,0);if(before.st_uid!=uid||before.st_gid!=gid||getuid()==0)fail("owner/group setup mismatch");
    printf("{\"Before\":");observe(fd,&before);printf("}\n");fflush(stdout);
    filesec_t source=filesec_init();if(!source)fail("source state");source_security=source;struct _copyfile_state state={.dst_fd=fd,.fsec=source,.dst=argv[1]};int rc=0,error=0,applied=0;
    counting=1;
    if(!strcmp(argv[3],"native")){
        size_t n;unsigned char *text=load(argv[2],&n);errno=0;rc=n?copyfile_unpack_acl(&state,(uint32_t)n,text):0;error=rc?errno:0;applied=!!(state.internal_flags&cfSetDestinationPerms);free(text);
    }else if(!strcmp(argv[3],"go")){
        char *line=NULL;size_t cap=0;for(;;){if(getline(&line,&cap,stdin)<1)fail("protocol EOF");if(line[0]=='D')break;
            if(line[0]=='C'){
                filesec_t sec=filesec_init();if(!sec)fail("capture state");struct stat st;errno=0;int result=counted_capture(fd,&st,sec);error=result?errno:0;rc=result;filesec_free(sec);
                printf("{\"Errno\":%d,\"Captured\":",error);if(!error){counting=0;snapshot(fd,&st);counting=1;}else printf("null");printf("}\n");
            }else if(line[0]=='W'){rc=direct_write(fd,line);error=rc?errno:0;if(!rc)applied=1;printf("{\"Errno\":%d}\n",error);}
            else if(line[0]=='R'){rc=copyfile_unset_acl(&state);error=rc?errno:0;printf("{\"Errno\":%d}\n",error);}
            else fail("unknown command");fflush(stdout);
        }free(line);
    }else return 2;
    counting=0;printf("{\"Code\":%d,\"Errno\":%d,\"Applied\":%s,\"Captures\":%d,\"Writes\":%d,\"Resets\":%d,\"After\":",rc,error,applied?"true":"false",captures,writes,resets);observe(fd,&after);
    printf(",\"IdentityUnchanged\":%s}\n",before.st_dev==after.st_dev&&before.st_ino==after.st_ino?"true":"false");filesec_free(source);if(close(fd))fail("close");return 0;
}
