// Qualification only: independent SDK ABI constants and descriptor readback.
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

struct held_cas_flags { uint32_t expected_flags, new_flags, actual_flags; };
extern int __fchmod_extended(int, uid_t, gid_t, int, void *);
_Static_assert(sizeof(struct stat)==144,"stat extent");
_Static_assert(sizeof(struct timespec)==16,"timespec extent");
_Static_assert(sizeof(struct attrlist)==24,"attrlist extent");
_Static_assert(offsetof(struct stat,st_ino)==8,"inode offset");
_Static_assert(offsetof(struct stat,st_atimespec)==32,"atime offset");
_Static_assert(offsetof(struct stat,st_flags)==116,"flags offset");
_Static_assert(_IOWR('A',20,struct held_cas_flags)==0xc00c4114,"CAS request");

static void hex(const void *buffer,size_t size) {
    const unsigned char *p=buffer;
    putchar('"');for(size_t i=0;i<size;i++)printf("%02x",p[i]);putchar('"');
}
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    int fd=open(argv[1],O_RDONLY|O_SYMLINK|O_NONBLOCK);
    if(fd<0){perror("open");return 1;}
    filesec_t sec=filesec_init();struct stat st;
    if(!sec||fstatx_np(fd,&st,sec)){perror("fstatx_np");return 1;}
    printf("{\"uid\":%u,\"gid\":%u,\"mode\":%u,\"flags\":%u,\"times\":[%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld],\"properties\":{",
        st.st_uid,st.st_gid,st.st_mode,st.st_flags,
        st.st_birthtimespec.tv_sec,st.st_birthtimespec.tv_nsec,
        st.st_mtimespec.tv_sec,st.st_mtimespec.tv_nsec,
        st.st_ctimespec.tv_sec,st.st_ctimespec.tv_nsec,
        st.st_atimespec.tv_sec,st.st_atimespec.tv_nsec);
    const filesec_property_t keys[]={FILESEC_OWNER,FILESEC_GROUP,FILESEC_MODE,FILESEC_UUID,FILESEC_GRPUUID,FILESEC_ACL_RAW};
    for(size_t i=0;i<sizeof(keys)/sizeof(keys[0]);i++){
        union { uint32_t number;uint16_t mode;unsigned char uuid[16];void *raw; } value={0};
        if(i)putchar(',');printf("\"%d\":",keys[i]);errno=0;
        if(filesec_get_property(sec,keys[i],&value)){
            if(errno!=ENOENT){perror("filesec_get_property");return 1;}printf("null");continue;
        }
        if(keys[i]==FILESEC_ACL_RAW){size_t size=0;if(filesec_get_property(sec,FILESEC_ACL_ALLOCSIZE,&size)||!value.raw||size<44||size>3116)return 1;hex(value.raw,size);}
        else hex(&value,keys[i]==FILESEC_MODE?2:(keys[i]==FILESEC_OWNER||keys[i]==FILESEC_GROUP?4:16));
    }
    printf("}}\n");filesec_free(sec);return close(fd)?1:0;
}
