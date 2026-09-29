// Test-only held-object comparison for image ACL restoration.
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/acl.h>
static const char *observation_path;
static int capture_security(int fd,struct stat *st,filesec_t security) {
    return fd<0?lstatx_np(observation_path,st,security):fstatx_np(fd,st,security);
}
#define fstatx_np capture_security
#define main filesec_reference_main
#include "filesec.c"
#undef main
#undef fstatx_np

static void attributes(int fd) {
    struct attrlist request={.bitmapcount=ATTR_BIT_MAP_COUNT,.commonattr=0x01c38000};
    unsigned char data[56+44+128*24]={0};
    int rc=fd<0?getattrlist(observation_path,&request,data,sizeof(data),FSOPT_NOFOLLOW):fgetattrlist(fd,&request,data,sizeof(data),0);
    if(rc)fail("attribute observation");uint32_t size;memcpy(&size,data,4);if(size<56||size>sizeof(data))fail("attribute extent");hex(data,size);
}
int main(int argc,char **argv) {
    if(argc!=6)return 2;
    int apply=!strcmp(argv[1],"apply");if(!apply&&strcmp(argv[1],"observe"))return 2;
    observation_path=argv[2];
    struct statfs filesystem;if(statfs(argv[5],&filesystem)||strcmp(filesystem.f_fstypename,argv[4])||(filesystem.f_flags&MNT_IGNORE_OWNERSHIP)||(apply&&(filesystem.f_flags&MNT_RDONLY)))fail("filesystem identity/ownership");
    int fd=-1,temporary=0;struct stat original;
    if(apply){
        if(lstat(argv[2],&original))fail("setup stat");
        // Acquire a held descriptor before restoring the exact zero mode,
        // matching copyfile's held-destination lifecycle. The owner performs
        // setup; no privilege, authorization failure or native write is faked.
        temporary=!(original.st_mode&S_IRUSR);
        if(temporary&&lchmod(argv[2],(original.st_mode&07777)|S_IRUSR))fail("held descriptor setup");
        fd=open(argv[2],O_EVTONLY|O_SYMLINK);if(fd<0)fail("held entry open");
        if(temporary&&fchmod(fd,original.st_mode&07777))fail("exact baseline mode");
    }
    struct stat before,after;printf("{\"Before\":");snapshot(fd,&before);printf(",\"BeforeAttributes\":");attributes(fd);
    if(apply&&(before.st_ino!=original.st_ino||before.st_dev!=original.st_dev||before.st_mode!=original.st_mode))fail("setup identity/mode changed");
    int code=0,error=0;struct _copyfile_state state={.dst_fd=fd,.dst=argv[2],.fsec=filesec_init()};if(!state.fsec)fail("source cache");
    if(apply){size_t size;unsigned char *text=load(argv[3],&size);errno=0;code=size?copyfile_unpack_acl(&state,(uint32_t)size,text):0;error=code?errno:0;free(text);}
    printf(",\"TemporaryReadSetup\":%s,\"Code\":%d,\"Errno\":%d,\"Applied\":%s,\"After\":",temporary?"true":"false",code,error,(state.internal_flags&cfSetDestinationPerms)?"true":"false");snapshot(fd,&after);printf(",\"AfterAttributes\":");attributes(fd);
    printf(",\"Inode\":%llu,\"SameIdentity\":%s}\n",(unsigned long long)after.st_ino,before.st_dev==after.st_dev&&before.st_ino==after.st_ino?"true":"false");
    filesec_free(state.fsec);if(fd>=0&&close(fd))fail("close");return 0;
}
