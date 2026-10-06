/* Independent native O_CREAT|O_EXCL admission and equivalent-entry ordering. */
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/attr.h>
#include <sys/acl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void must(int bad,const char *why){if(bad){perror(why);exit(2);}}
static void unhex(const char *text,char *out){size_t n=strlen(text);must(n%2||n>8192,"hex length");for(size_t i=0;i<n;i+=2){unsigned value;must(sscanf(text+i,"%2x",&value)!=1||value==0,"hex byte");out[i/2]=(char)value;}out[n/2]=0;}
static int create(int dir,const char *name,int *opened){errno=0;int file=openat(dir,name,O_CREAT|O_EXCL|O_RDWR,0600);int error=file<0?errno:0;*opened=file>=0;if(file>=0){struct stat value;must(fstat(file,&value)||!S_ISREG(value.st_mode)||value.st_size!=0,"created file");must(close(file),"close created");}return error;}
int main(int argc,char **argv){
 if(argc!=3||getuid()==0)return 2;
 int root=open(argv[1],O_RDONLY|O_DIRECTORY);must(root<0,"root");struct statfs fs;must(fstatfs(root,&fs),"filesystem");
 struct attrlist attrs={.bitmapcount=ATTR_BIT_MAP_COUNT,.volattr=ATTR_VOL_INFO|ATTR_VOL_CAPABILITIES};struct{unsigned length;vol_capabilities_attr_t value;}caps;must(fgetattrlist(root,&attrs,&caps,sizeof(caps),0),"capabilities");
 FILE *input=fopen(argv[2],"r");must(!input,"preflight input");char *line=NULL;size_t capacity=0;unsigned count=0;
 printf("{\"filesystem\":\"%s\",\"uid\":%u,\"gid\":%u,\"mount_flags\":%u,\"case_sensitive\":%s,\"capability_valid\":%s,\"cases\":[",fs.f_fstypename,getuid(),getgid(),fs.f_flags,caps.value.capabilities[0]&VOL_CAP_FMT_CASE_SENSITIVE?"true":"false",caps.value.valid[0]&VOL_CAP_FMT_CASE_SENSITIVE?"true":"false");
 while(getline(&line,&capacity,input)>=0){
  line[strcspn(line,"\n")]=0;char *id=strtok(line,"\t"),*kind=strtok(NULL,"\t"),*first=strtok(NULL,"\t"),*second=strtok(NULL,"\t");must(!id||!kind||!first||strtok(NULL,"\t"),"preflight fields");
  int collision=!strcmp(kind,"collision");must((strcmp(kind,"rejected")&&strcmp(kind,"collision"))||(collision&&!second),"preflight operation");
  char one[4097],two[4097]={0};unhex(first,one);if(second)unhex(second,two);
  char directory[32];snprintf(directory,sizeof(directory),"preflight-%u",count);must(mkdirat(root,directory,0700),"create case directory");int dir=openat(root,directory,O_RDONLY|O_DIRECTORY);must(dir<0,"case directory");
  acl_t empty=acl_init(0);must(!empty,"ACL init");must(acl_set_fd_np(dir,empty,ACL_TYPE_EXTENDED),"clear directory ACL");acl_free(empty);
  int opened=0,other=0;int first_error=create(dir,one,&opened),second_error=0;if(collision)second_error=create(dir,two,&other);
  if(other)must(unlinkat(dir,two,0),"remove second");if(opened)must(unlinkat(dir,one,0),"remove first");must(close(dir),"close directory");must(unlinkat(root,directory,AT_REMOVEDIR),"remove directory");
  printf("%s{\"id\":\"%s\",\"kind\":\"%s\",\"first_errno\":%d,\"second_errno\":%d,\"first_created\":%s,\"second_created\":%s}",count?",":"",id,kind,first_error,second_error,opened?"true":"false",other?"true":"false");count++;
 }
 must(ferror(input),"preflight read");free(line);must(fclose(input),"close input");must(close(root),"close root");printf("],\"count\":%u,\"cleanup_complete\":true}\n",count);return 0;
}
