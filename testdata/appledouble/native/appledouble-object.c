// Independent live fcopyfile facade oracle; qualification only.
#include <copyfile.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(COPYFILE_ACL == 1, "ACL flag");
_Static_assert(COPYFILE_STAT == 2, "stat flag");
_Static_assert(COPYFILE_PACK == (1U<<22), "pack flag");
_Static_assert(COPYFILE_UNPACK == (1U<<23), "unpack flag");
static void hex(const void *p,size_t n){const unsigned char *b=p;putchar('"');for(size_t i=0;i<n;i++)printf("%02x",b[i]);putchar('"');}
static int inspect(const char *path){
 int fd=open(path,O_RDONLY|O_SYMLINK|O_NONBLOCK);if(fd<0)return 1;
 struct stat st;if(fstat(fd,&st))return 1;
 ssize_t count=flistxattr(fd,NULL,0,0);if(count<0||count>1048576)return 1;
 char *names=malloc((size_t)count+1);if(!names)return 1;
 if(flistxattr(fd,names,(size_t)count,0)!=count)return 1;
 printf("{\"mode\":%u,\"flags\":%u,\"mtime\":%lld,\"mtime_nano\":%ld,\"attrs\":[",st.st_mode,st.st_flags,(long long)st.st_mtimespec.tv_sec,st.st_mtimespec.tv_nsec);
 int comma=0;for(ssize_t at=0;at<count;){const char *name=names+at;size_t len=strnlen(name,(size_t)(count-at));if(len==(size_t)(count-at))return 1;at+=(ssize_t)len+1;
  ssize_t size=fgetxattr(fd,name,NULL,0,0,0);if(size<0||size>32*1024*1024)return 1;
  void *value=malloc((size_t)size+1);if(!value)return 1;
  if(fgetxattr(fd,name,value,(size_t)size,0,0)!=size)return 1;
  if(comma++)putchar(',');printf("{\"name\":");hex(name,len);printf(",\"value\":");hex(value,(size_t)size);putchar('}');free(value);
 }
 printf("],\"acl\":");acl_t acl=acl_get_fd(fd);if(!acl){if(errno!=ENOENT)return 1;printf("null");}else{ssize_t size=acl_size(acl);if(size<0||size>4096)return 1;void *b=malloc((size_t)size);if(!b)return 1;ssize_t n=acl_copy_ext(b,acl,size);if(n<0)return 1;hex(b,(size_t)n);free(b);acl_free(acl);}
 puts("}");free(names);return close(fd)?1:0;
}
int main(int argc,char **argv){
 if(argc==3&&!strcmp(argv[1],"inspect"))return inspect(argv[2]);
 if(argc==6&&!strncmp(argv[1],"path-",5)){
  copyfile_flags_t flags=(!strcmp(argv[1],"path-pack")?COPYFILE_PACK:COPYFILE_UNPACK)|COPYFILE_XATTR;
  if(atoi(argv[4]))flags|=COPYFILE_ACL;if(atoi(argv[5]))flags|=COPYFILE_STAT;
  errno=0;int result=copyfile(argv[2],argv[3],NULL,flags),saved=errno;
  printf("{\"code\":%d,\"errno\":%d}\n",result,saved);return 0;
 }
 int inherited=argc==4&&!strncmp(argv[1],"fd-",3);
 if(!inherited&&argc!=6)return 2;
 int source=inherited?3:open(argv[2],O_RDONLY|O_SYMLINK|O_NONBLOCK);if(source<0)return 1;
 int packing=!strcmp(argv[1],inherited?"fd-pack":"pack");
 int destination=inherited?4:open(argv[3],(packing?O_RDWR:O_RDONLY)|O_SYMLINK|O_NONBLOCK);if(destination<0)return 1;
 copyfile_flags_t flags=(packing?COPYFILE_PACK:COPYFILE_UNPACK)|COPYFILE_XATTR;
 if(atoi(argv[inherited?2:4]))flags|=COPYFILE_ACL;if(atoi(argv[inherited?3:5]))flags|=COPYFILE_STAT;
 errno=0;int result=fcopyfile(source,destination,NULL,flags),saved=errno;
 printf("{\"code\":%d,\"errno\":%d,\"uid\":%u,\"euid\":%u}\n",result,saved,getuid(),geteuid());
 close(source);close(destination);return 0;
}
