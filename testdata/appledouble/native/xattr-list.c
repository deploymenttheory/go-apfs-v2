// Qualification only: direct libSystem listing, independent of the Go wrapper.
#include <sys/types.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc,char **argv){
 if(argc!=3)return 2;
 int fd=open(argv[1],O_RDONLY|O_CLOEXEC|(strcmp(argv[2],"link")==0?O_SYMLINK:0));
 if(fd<0){perror("oracle open");return 2;}
 ssize_t size=flistxattr(fd,NULL,0,0),got=-1;
 int error=size<0?errno:0;unsigned char *names=NULL;
 if(!error){
  if(size>1024*1024){fprintf(stderr,"oracle list too large\n");close(fd);return 2;}
  names=calloc((size_t)(size?size:1),1);if(!names){perror("oracle allocation");close(fd);return 2;}
  got=flistxattr(fd,(char *)names,(size_t)(size?size:1),0);
  if(got<0)error=errno;
  if(!error&&got!=size){fprintf(stderr,"oracle namespace changed\n");free(names);close(fd);return 2;}
 }
 printf("{\"Size\":%zd,\"Read\":%zd,\"Error\":%d,\"NamesHex\":\"",size,got,error);
 if(!error)for(ssize_t i=0;i<got;i++)printf("%02x",names[i]);
 printf("\"}\n");free(names);close(fd);return 0;
}
