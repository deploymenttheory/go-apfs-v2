// Research-only native pathname limits and policy oracle.
// Independent syscalls; no expected errno or production Go policy is compiled here.
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/attr.h>
#include <sys/acl.h>
#include <sys/resource.h>
// xnu-11417.140.69 bsd/sys/resource_private.h, retained full source.
#define IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS 13
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
static int root;
static mode_t query_mode=0700;
static void must(int bad,const char *s){if(bad){perror(s);exit(2);}}
static void hex(const char *s){putchar('"');for(size_t i=0;i<strlen(s);i++)printf("%02x",(unsigned char)s[i]);putchar('"');}
static unsigned char root_security[65536], leaf_security[65536];
static size_t root_security_size,leaf_security_size;
static int leaf_security_captured;
static void hexbytes(const unsigned char *raw,size_t size){putchar('"');for(size_t i=0;i<size;i++)printf("%02x",raw[i]);putchar('"');}
static size_t capture_acl(int fd,unsigned char *raw){errno=0;acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);if(!acl){must(errno!=ENOENT,"capture native ACL");return 0;}ssize_t size=acl_size(acl);must(size<0||size>65536,"native ACL size");must(acl_copy_ext(raw,acl,size)!=size,"export native ACL");acl_free(acl);return (size_t)size;}
static void verify_leaf_acl(int fd){unsigned char raw[65536];size_t size=capture_acl(fd,raw);if(!leaf_security_captured){leaf_security_captured=1;memcpy(leaf_security,raw,size);leaf_security_size=size;}else must(size!=leaf_security_size||memcmp(raw,leaf_security,size),"leaf ACL protocol changed");}
static int first=1;
static void lookup(const char *id,const char *created,const char *queried){
 errno=0;int file=openat(root,created,O_CREAT|O_EXCL|O_RDWR,0600);int ce=file<0?errno:0;
 struct stat before={0},after={0};if(file>=0){must(fstat(file,&before),"created stat");verify_leaf_acl(file);}
 must(fchmod(root,query_mode),"query directory mode");
 errno=0;int probe=openat(root,queried,O_RDONLY);int qe=probe<0?errno:0;
 if(probe>=0)must(fstat(probe,&after),"lookup stat");
 printf("%s{\"id\":\"%s\",\"created\":",first?"":",",id);first=0;hex(created);printf(",\"queried\":");hex(queried);
 printf(",\"directory_mode\":%u,\"create_errno\":%d,\"lookup_errno\":%d,\"same_inode\":%s}",query_mode,ce,qe,file>=0&&probe>=0&&before.st_dev==after.st_dev&&before.st_ino==after.st_ino?"true":"false");
 must(fchmod(root,0700),"restore query mode");
 if(probe>=0)must(close(probe),"close lookup");if(file>=0){must(close(file),"close created");must(unlinkat(root,created,0),"remove created");}
}
static void expansioncase(int length,const char *suffix,mode_t mode){
 int file=openat(root,"file",O_CREAT|O_EXCL|O_RDWR,0600);must(file<0,"expansion control");verify_leaf_acl(file);must(close(file),"close expansion control");
 char target[2048];int prefix=length-4;for(int i=0;i<prefix;i++)target[i]=(i%2==0?'.':'/');if(prefix%2)target[prefix-1]='/';memcpy(target+prefix,"file",5);
 errno=0;int created=symlinkat(target,root,"expand"),create_error=created?errno:0;
 char name[64];snprintf(name,sizeof(name),"expand%s",suffix);must(fchmod(root,mode),"expansion mode");errno=0;int result=openat(root,name,O_RDONLY),error=result<0?errno:0;must(fchmod(root,0700),"restore expansion mode");
 printf("%s{\"id\":\"expansion-%d-%s-%o\",\"target\":",first?"":",",length,*suffix?(strlen(suffix)==1?"slash":"child"):"plain",mode);first=0;hex(target);printf(",\"queried\":");hex(name);printf(",\"directory_mode\":%u,\"create_errno\":%d,\"lookup_errno\":%d}",mode,create_error,error);
 if(result>=0)must(close(result),"close expansion");if(!created)must(unlinkat(root,"expand",0),"remove expansion link");must(unlinkat(root,"file",0),"remove expansion file");
}
static void linkcase(int count){
 int file=openat(root,"file",O_CREAT|O_EXCL|O_RDWR,0600);must(file<0,"link control file");verify_leaf_acl(file);must(close(file),"close link control");
 for(int i=count-1;i>=0;i--){char from[32],target[32];snprintf(from,sizeof(from),"link%d",i);if(i+1==count)strcpy(target,"file");else snprintf(target,sizeof(target),"link%d",i+1);must(symlinkat(target,root,from),"symlink");}
 errno=0;int result=openat(root,"link0",O_RDONLY);int error=result<0?errno:0;
 printf("%s{\"id\":\"symlinks-%d\",\"create_errno\":0,\"lookup_errno\":%d}",first?"":",",count,error);first=0;
 if(result>=0)must(close(result),"close symlink");for(int i=0;i<count;i++){char name[32];snprintf(name,sizeof(name),"link%d",i);must(unlinkat(root,name,0),"remove link");}must(unlinkat(root,"file",0),"remove link control");
}
int main(int argc,char **argv){
 if(argc!=2)return 2;char dir[PATH_MAX];must(snprintf(dir,sizeof(dir),"%s/pathname-lookup-XXXXXX",argv[1])>=(int)sizeof(dir),"fixture path");must(!mkdtemp(dir),"mkdtemp");root=open(dir,O_RDONLY|O_DIRECTORY);must(root<0,"open root");
 gid_t groups[128];int ngroups=getgroups(128,groups);must(ngroups<0,"capture effective groups");
 errno=0;int process=getiopolicy_np(IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS,IOPOL_SCOPE_PROCESS),process_error=process<0?errno:0;
 errno=0;int thread=getiopolicy_np(IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS,IOPOL_SCOPE_THREAD),thread_error=thread<0?errno:0;
 if(process!=0||thread!=0||process_error||thread_error){fprintf(stderr,"ordinary path policy not established\n");return 2;}
 acl_t empty=acl_init(0);must(!empty,"empty fixture ACL");must(acl_set_fd_np(root,empty,ACL_TYPE_EXTENDED),"clear fixture ACL");acl_free(empty);
 errno=0;acl_t observed=acl_get_fd_np(root,ACL_TYPE_EXTENDED);int acl_error=observed?0:errno;must(!observed&&acl_error!=ENOENT,"observe fixture ACL");
 if(observed){acl_entry_t entry;must(acl_get_entry(observed,ACL_FIRST_ENTRY,&entry)!=-1,"fixture ACL unexpectedly nonempty");acl_free(observed);}
 root_security_size=capture_acl(root,root_security);
 struct statfs fs;must(fstatfs(root,&fs),"statfs");struct attrlist attrs={0};attrs.bitmapcount=ATTR_BIT_MAP_COUNT;attrs.volattr=ATTR_VOL_INFO|ATTR_VOL_CAPABILITIES;
 struct __attribute__((packed)){uint32_t length;vol_capabilities_attr_t value;} caps;errno=0;int caprc=fgetattrlist(root,&attrs,&caps,sizeof(caps),0),caperr=caprc?errno:0;
 printf("{\"fixture_acl_observed_empty\":true,\"actor_uid\":%u,\"actor_gid\":%u,\"filesystem\":\"%s\",\"mount_flags\":%u,\"name_max\":%ld,\"path_max\":%ld,\"capability_errno\":%d,\"capabilities\":[%u,%u,%u,%u],\"valid\":[%u,%u,%u,%u],\"cases\":[",geteuid(),getegid(),fs.f_fstypename,fs.f_flags,fpathconf(root,_PC_NAME_MAX),fpathconf(root,_PC_PATH_MAX),caperr,caps.value.capabilities[0],caps.value.capabilities[1],caps.value.capabilities[2],caps.value.capabilities[3],caps.value.valid[0],caps.value.valid[1],caps.value.valid[2],caps.value.valid[3]);
 lookup("empty-input","file","");lookup("embedded-nul-c-string","file","file\0suffix");
 char path[4096];
 for(int n=1022;n<=1025;n++){int prefix=n-4;for(int i=0;i<prefix;i++)path[i]=(i%2==0?'.':'/');if(prefix%2)path[prefix-1]='/';memcpy(path+prefix,"file",5);char id[40];snprintf(id,sizeof(id),"relative-components-%d",n);lookup(id,"file",path);}
 for(int n=31;n<=33;n++)linkcase(n);
 query_mode=0600;
 lookup("no-search-empty","file","");lookup("no-search-short","file","file");
 char longname[257];memset(longname,'x',256);longname[256]=0;lookup("no-search-component-256","file",longname);
 for(int n=1023;n<=1024;n++){int prefix=n-4;for(int i=0;i<prefix;i++)path[i]=(i%2==0?'.':'/');if(prefix%2)path[prefix-1]='/';memcpy(path+prefix,"file",5);char id[50];snprintf(id,sizeof(id),"no-search-path-%d",n);lookup(id,"file",path);}
 query_mode=0700;
 for(int n=1022;n<=1024;n++){expansioncase(n,"",0700);expansioncase(n,"/",0700);expansioncase(n,"/x",0700);expansioncase(n,"/",0600);}
 errno=0;int set_process=setiopolicy_np(IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS,IOPOL_SCOPE_PROCESS,1),set_process_error=set_process?errno:0;
 errno=0;int set_thread=setiopolicy_np(IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS,IOPOL_SCOPE_THREAD,1),set_thread_error=set_thread?errno:0;
 printf("],\"root_security\":");hexbytes(root_security,root_security_size);printf(",\"leaf_security\":");hexbytes(leaf_security,leaf_security_size);
 printf(",\"groups\":[");for(int i=0;i<ngroups;i++)printf("%s%u",i?",":"",groups[i]);printf("]");
 must(close(root),"close root");must(rmdir(dir),"remove fixture");
 printf(",\"long_path_process\":%d,\"long_path_process_errno\":%d,\"long_path_thread\":%d,\"long_path_thread_errno\":%d,\"set_long_path_process_errno\":%d,\"set_long_path_thread_errno\":%d,\"cleanup_complete\":true}\n",process,process_error,thread,thread_error,set_process_error,set_thread_error);return 0;
}
