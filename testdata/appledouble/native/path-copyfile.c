// Qualification only: exercise the installed public copyfile operation on
// disposable files, including its own creation/cleanup and state ownership.
#include <copyfile.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct notice {int what,stage;long long copied;};
static struct notice notices[256];static unsigned notice_count;static int quit;
static int callback(int what,int stage,copyfile_state_t state,const char *src,const char *dst,void *context){
 (void)src;(void)dst;(void)context;
 if(notice_count>=256)exit(20);
 off_t copied=0;if(copyfile_state_get(state,COPYFILE_STATE_COPIED,&copied))exit(21);
 notices[notice_count++]=(struct notice){what,stage,copied};
 return quit?COPYFILE_QUIT:COPYFILE_CONTINUE;
}
static int set_acl(const char *path){
 struct stat st;if(lstat(path,&st))return errno==ENOENT?0:-1;
 int fd=open(path,O_RDONLY|O_SYMLINK);if(fd<0)return -1;
 acl_t a=acl_init(1);acl_entry_t e;acl_permset_t p;uuid_t id={1};
 if(!a||acl_create_entry(&a,&e)||acl_set_tag_type(e,ACL_EXTENDED_ALLOW)||acl_set_qualifier(e,id)||acl_get_permset(e,&p)||acl_add_perm(p,ACL_READ_DATA)||acl_set_permset(e,p))return -1;
 int result=acl_set_fd(fd,a);acl_free(a);close(fd);return result;
}
static void snapshot(const char *path){
 struct stat st;if(lstat(path,&st)){printf("{\"Exists\":false,\"Errno\":%d}",errno);return;}
 filesec_t fs=filesec_init();int count=-1;if(!fs)exit(22);
 if(lstatx_np(path,&st,fs)==0){acl_t a=NULL;if(filesec_get_property(fs,FILESEC_ACL,&a)==0){count=0;acl_entry_t e;int next=ACL_FIRST_ENTRY;while(acl_get_entry(a,next,&e)==0){count++;next=ACL_NEXT_ENTRY;}acl_free(a);}}
 filesec_free(fs);
 unsigned char value[128];ssize_t n=getxattr(path,"com.example.path",value,sizeof(value),0,XATTR_NOFOLLOW);
 int xe=n<0?errno:0;
 printf("{\"Exists\":true,\"Mode\":%u,\"Size\":%lld,\"ACLCount\":%d,\"XattrErrno\":%d,\"XattrHex\":\"",(unsigned)st.st_mode,(long long)(S_ISDIR(st.st_mode)?0:st.st_size),count,xe);
 if(n>0)for(ssize_t i=0;i<n;i++)printf("%02x",value[i]);
 printf("\"}");
}
int main(int argc,char **argv){
 if(argc!=9)return 2;
 const char *src=argv[1],*dst=argv[2],*target=argv[3];int route=atoi(argv[4]),selected=atoi(argv[5]);quit=atoi(argv[6]);
 copyfile_flags_t flags=route?COPYFILE_UNPACK:COPYFILE_PACK;
 flags|=COPYFILE_XATTR;
 if(selected&1)flags|=COPYFILE_STAT;
 if(selected&2)flags|=COPYFILE_EXCL;
 if(selected&4)flags|=COPYFILE_NOFOLLOW;
 if(selected&8)flags|=COPYFILE_UNLINK;
 if(selected&16)flags|=COPYFILE_MOVE;
 if(selected&32){flags|=COPYFILE_ACL;if(set_acl(dst))return 3;}
 if(!route&&strcmp(src,"/dev/null")){
  struct stat initial;if(lstat(src,&initial))return 4;
  int fd=open(src,O_RDONLY|O_SYMLINK);if(fd<0)return 4;
  if(fchmod(fd,initial.st_mode|S_IWUSR)||fsetxattr(fd,"com.example.path","source",6,0,0)||fchmod(fd,initial.st_mode))return 4;
  close(fd);
 }
 int source_mode=atoi(argv[7]),mask=atoi(argv[8]);
 if(source_mode){int fd=open(src,O_RDONLY|O_SYMLINK);if(fd<0||fchmod(fd,(mode_t)source_mode))return 8;close(fd);}
 if(mask>=0)umask((mode_t)mask);
 copyfile_state_t state=NULL;int owned=(selected&64)!=0;
 if(owned||quit){state=copyfile_state_alloc();if(!state)return 5;if(copyfile_state_set(state,COPYFILE_STATE_STATUS_CB,callback))return 6;}
 printf("{\"Before\":");snapshot(dst);printf(",\"Code\":");
 errno=0;int result=copyfile(src,dst,state,flags),saved=errno;
 printf("%d,\"Errno\":%d,\"Notices\":[",result,saved);
 for(unsigned i=0;i<notice_count;i++){if(i)putchar(',');printf("{\"What\":%d,\"Stage\":%d,\"Copied\":%lld}",notices[i].what,notices[i].stage,notices[i].copied);}
 int source_open=0,destination_open=0,free_result=0,free_error=0,source_closed=0,destination_closed=0;
 if(state){
  int source_fd=-1,destination_fd=-1;
  if(copyfile_state_get(state,COPYFILE_STATE_SRC_FD,&source_fd)||copyfile_state_get(state,COPYFILE_STATE_DST_FD,&destination_fd))return 7;
  source_open=source_fd>=0&&fcntl(source_fd,F_GETFD)>=0;destination_open=destination_fd>=0&&fcntl(destination_fd,F_GETFD)>=0;
  if((selected&128)&&source_fd>=0)close(source_fd);
  if((selected&256)&&destination_fd>=0)close(destination_fd);
  errno=0;free_result=copyfile_state_free(state);free_error=errno;
  source_closed=source_fd>=0&&fcntl(source_fd,F_GETFD)<0&&errno==EBADF;destination_closed=destination_fd>=0&&fcntl(destination_fd,F_GETFD)<0&&errno==EBADF;
 }
 printf("],\"SourceOpenBeforeFree\":%s,\"DestinationOpenBeforeFree\":%s,\"SourceClosedAfterFree\":%s,\"DestinationClosedAfterFree\":%s,\"FreeCode\":%d,\"FreeErrno\":%d,\"After\":",source_open?"true":"false",destination_open?"true":"false",source_closed?"true":"false",destination_closed?"true":"false",free_result,free_error);
 snapshot(dst);printf(",\"Source\":");snapshot(src);printf(",\"Target\":");snapshot(target);puts("}");return 0;
}
