// Qualification only: distinguish no-follow link acquisition from failed data
// transfer. All paths are owned disposable fixtures; referents are read back.
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
 char root[]="/private/tmp/appledouble-link-write-XXXXXX";
 if(!mkdtemp(root))return 2;
 char target[256],link[256];
 if(snprintf(target,sizeof(target),"%s/target",root)>=(int)sizeof(target)||
    snprintf(link,sizeof(link),"%s/link",root)>=(int)sizeof(link))return 3;
 printf("{\"Cases\":[");
 for(int dangling=0;dangling<2;dangling++){
  int target_fd=-1;
  if(!dangling){target_fd=open(target,O_CREAT|O_EXCL|O_RDWR,0600);if(target_fd<0||write(target_fd,"TARGET",6)!=6||close(target_fd))return 4;}
  if(symlink("target",link))return 5;
  struct stat before,held,after;if(lstat(link,&before))return 6;
  errno=0;int fd=open(link,O_SYMLINK|O_WRONLY);int open_error=fd<0?errno:0;
  int stat_result=fd<0?-1:fstat(fd,&held);int access=fd<0?-1:fcntl(fd,F_GETFL);
  errno=0;ssize_t count=fd<0?-1:pwrite(fd,"changed",7,0);int write_error=count<0?errno:0;
  if(lstat(link,&after))return 7;
  int identity=stat_result==0&&before.st_dev==held.st_dev&&before.st_ino==held.st_ino&&before.st_mode==held.st_mode&&before.st_dev==after.st_dev&&before.st_ino==after.st_ino&&before.st_mode==after.st_mode;
  int unchanged=0;
  if(!dangling){target_fd=open(target,O_RDONLY);char bytes[7]={0};if(target_fd<0||read(target_fd,bytes,7)!=6||close(target_fd))return 8;unchanged=!memcmp(bytes,"TARGET",6);}
  else{struct stat missing;errno=0;unchanged=lstat(target,&missing)<0&&errno==ENOENT;}
  int close_error=0;if(fd>=0&&close(fd))close_error=errno;
  if(dangling)putchar(',');
  printf("{\"Dangling\":%s,\"OpenErrno\":%d,\"HeldMode\":%u,\"AccessMode\":%d,\"WriteCount\":%lld,\"WriteErrno\":%d,\"CloseErrno\":%d,\"IdentityPreserved\":%s,\"ReferentUnchanged\":%s}",dangling?"true":"false",open_error,stat_result==0?(unsigned)held.st_mode:0,access<0?-1:access&O_ACCMODE,(long long)count,write_error,close_error,identity?"true":"false",unchanged?"true":"false");
  if(unlink(link)||(!dangling&&unlink(target)))return 9;
 }
 if(rmdir(root))return 10;
 puts("],\"CleanupVerified\":true}");return 0;
}
