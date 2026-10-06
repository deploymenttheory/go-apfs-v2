// Native resource-fork acquisition across kernel versions. Test-owned files only.
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what) { perror(what); exit(2); }
static void path(char *out,size_t capacity,const char *base,const char *suffix) {
    int n=snprintf(out,capacity,"%s%s",base,suffix);if(n<0||(size_t)n>=capacity)die("path bounds");
}
int main(int argc,char **argv) {
    if(argc!=5)return 2;
    const char *method=argv[1],*state=argv[2],*directory=argv[4];int writable=!strcmp(argv[3],"write");
    char original[4096],moved[4096],target[4096];path(original,sizeof(original),directory,"/file");path(moved,sizeof(moved),directory,"/moved");
    int data=open(original,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(data<0)die("create");
    if(write(data,"DATA",4)!=4)die("data bytes");
    if(strcmp(state,"empty")&&fsetxattr(data,"com.apple.ResourceFork","ORIGINAL",8,0,0))die("fork bytes");
    struct stat before;if(fstat(data,&before))die("initial identity");
    const char *current=original;
    if(!strcmp(state,"renamed")||!strcmp(state,"replaced")||!strcmp(state,"unlinked")) {
        if(rename(original,moved))die("rename");current=moved;
    }
    if(!strcmp(state,"replaced")||!strcmp(state,"unlinked")) {
        int shadow=open(original,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(shadow<0)die("shadow");
        if(write(shadow,"SHADOW",6)!=6||close(shadow))die("shadow bytes");
    }
    if(!strcmp(state,"unlinked")&&unlink(moved))die("unlink");
    int flags=(writable?O_RDWR|O_CREAT:O_RDONLY)|O_CLOEXEC;
    int fork=-1,preflight=0;errno=0;
    if(!strcmp(method,"openat"))fork=openat(data,"..namedfork/rsrc",flags,0600);
    else if(!strcmp(method,"openfrom")) {
        // Apple's xnu-11417.140.69 bsd/sys/fcntl.h, private F_OPENFROM ABI.
        struct {unsigned int flags;mode_t mode;const char *name;} request={(unsigned int)flags,0600,"..namedfork/rsrc"};
        fork=fcntl(data,56,&request);
    } else {
        if(!strcmp(method,"path"))path(target,sizeof(target),current,"/..namedfork/rsrc");
        else if(!strcmp(method,"getpath")) {
            char held[4096];if(fcntl(data,F_GETPATH,held))preflight=errno;
            else path(target,sizeof(target),held,"/..namedfork/rsrc");
        } else if(!strcmp(method,"devfd")) {
            if(snprintf(target,sizeof(target),"/dev/fd/%d/..namedfork/rsrc",data)<0)die("devfd path");
        } else if(!strcmp(method,"volfs")) {
            struct statfs volume;if(fstatfs(data,&volume))die("volume");
            if(snprintf(target,sizeof(target),"/.vol/%u/%llu/..namedfork/rsrc",(unsigned)volume.f_fsid.val[0],(unsigned long long)before.st_ino)<0)die("volume path");
        } else return 2;
        if(!preflight){errno=0;fork=open(target,flags,0600);}
    }
    int open_error=fork<0?(preflight?preflight:errno):0,identity=0,read_bytes=-1,read_error=0,write_bytes=-1,write_error=0;
    unsigned char bytes[16]={0};
    if(fork>=0) {
        struct stat after;if(fstat(fork,&after))die("fork identity");identity=before.st_dev==after.st_dev&&before.st_ino==after.st_ino;
        errno=0;read_bytes=(int)pread(fork,bytes,sizeof(bytes),0);if(read_bytes<0)read_error=errno;
        if(writable&&identity){errno=0;write_bytes=(int)pwrite(fork,"NEW",3,0);if(write_bytes<0)write_error=errno;}
        if(close(fork))die("fork close");
    }
    char payload[8]={0};if(pread(data,payload,sizeof(payload),0)!=4||memcmp(payload,"DATA",4))die("data corruption");
    unsigned char retained[32]={0};errno=0;int retained_size=(int)fgetxattr(data,"com.apple.ResourceFork",retained,sizeof(retained),0,0),retained_error=retained_size<0?errno:0;
    int shadow_unchanged=1;
    if(!strcmp(state,"replaced")||!strcmp(state,"unlinked")) {
        int shadow=open(original,O_RDONLY|O_CLOEXEC);if(shadow<0)die("shadow read");
        char check[8]={0};shadow_unchanged=read(shadow,check,sizeof(check))==6&&!memcmp(check,"SHADOW",6);
        errno=0;if(fgetxattr(shadow,"com.apple.ResourceFork",NULL,0,0,0)>=0||errno!=ENOATTR)shadow_unchanged=0;
        if(close(shadow))die("shadow close");
    }
    printf("{\"open_errno\":%d,\"preflight_errno\":%d,\"identity\":%s,\"read_bytes\":%d,\"read_errno\":%d,\"read_hex\":\"",open_error,preflight,identity?"true":"false",read_bytes,read_error);
    for(int i=0;i<read_bytes;i++)printf("%02x",bytes[i]);
    printf("\",\"write_bytes\":%d,\"write_errno\":%d,\"retained_size\":%d,\"retained_errno\":%d,\"retained_hex\":\"",write_bytes,write_error,retained_size,retained_error);
    for(int i=0;i<retained_size;i++)printf("%02x",retained[i]);
    printf("\",\"data_unchanged\":true,\"shadow_unchanged\":%s}\n",shadow_unchanged?"true":"false");
    if(close(data))die("data close");return 0;
}
