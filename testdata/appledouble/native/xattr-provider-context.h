// Qualification-only native provider context. Values are observed from the held
// descriptor, its filesystem, and the actual current process.
#ifndef APPLEDOUBLE_XATTR_PROVIDER_CONTEXT_H
#define APPLEDOUBLE_XATTR_PROVIDER_CONTEXT_H
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/acl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
extern bool _xpc_runtime_is_app_sandboxed(void);
static void provider_context_json(int fd){
 struct stat st;struct statfs volume;filesec_t security=filesec_init();if(!security||fstatx_np(fd,&st,security)||fstatfs(fd,&volume))exit(40);
 int flags=fcntl(fd,F_GETFL);if(flags<0)exit(41);
 acl_t acl=NULL;errno=0;int ae=filesec_get_property(security,FILESEC_ACL,&acl)<0?errno:0;ssize_t size=0;unsigned char *raw=NULL;
 if(acl){size=acl_size(acl);if(size<0||size>1024*1024)exit(42);raw=malloc(size?(size_t)size:1);if(!raw||acl_copy_ext(raw,acl,size)!=size)exit(43);acl_free(acl);}
 printf("{\"Device\":%llu,\"Inode\":%llu,\"UID\":%u,\"GID\":%u,\"Mode\":%u,\"Flags\":%u,\"ProcessUID\":%u,\"ProcessEUID\":%u,\"ProcessGID\":%u,\"ProcessEGID\":%u,\"Sandboxed\":%s,\"FileSystem\":\"%s\",\"MountFlags\":%llu,\"OpenFlags\":%d,\"ACLErrno\":%d,\"ACLHex\":\"",(unsigned long long)st.st_dev,(unsigned long long)st.st_ino,st.st_uid,st.st_gid,st.st_mode,st.st_flags,getuid(),geteuid(),getgid(),getegid(),_xpc_runtime_is_app_sandboxed()?"true":"false",volume.f_fstypename,(unsigned long long)volume.f_flags,flags,ae);
 for(ssize_t i=0;i<size;i++)printf("%02x",raw[i]);printf("\"}");free(raw);filesec_free(security);
}
#endif
