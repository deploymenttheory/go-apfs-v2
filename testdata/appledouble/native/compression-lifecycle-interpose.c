// Test-only native operation tracing. Every observation/fault is restricted to
// the disposable target descriptor and armed only during native compression.
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/attr.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static _Atomic int armed, fault_count, attribute_count, mode_count;
static _Atomic int fork_descriptor = -1;
static dev_t target_device;
static ino_t target_inode;
void afsc_probe_arm(void) {
    struct stat state;const char *path=getenv("APFS_NATIVE_FAULT_TARGET");
    if(!path||stat(path,&state)){perror("arm target identity");exit(2);}
    target_device=state.st_dev;target_inode=state.st_ino;
    atomic_store(&fork_descriptor,-1);atomic_store(&fault_count,0);atomic_store(&attribute_count,0);atomic_store(&mode_count,0);atomic_store(&armed,1);
}
void afsc_probe_disarm(void) { atomic_store(&armed,0); }
static int target_fd(int fd) {
    if(!atomic_load(&armed))return 0;
    // F_GETPATH may return either hard-link name after a metadata update. Pin
    // the test-owned inode, then use only the fork suffix for classification.
    int saved=errno,result=0;struct stat state;
    if(!fstat(fd,&state)&&state.st_dev==target_device&&state.st_ino==target_inode){
        result=fd==atomic_load(&fork_descriptor)?2:1;char path[4096];
        if(!fcntl(fd,F_GETPATH,path)){
            const char *suffix="/..namedfork/rsrc";size_t n=strlen(path),s=strlen(suffix);
            if(n>=s&&!strcmp(path+n-s,suffix)){result=2;atomic_store(&fork_descriptor,fd);}
        }
    }
    errno=saved;return result;
}
static int fail(const char *operation) {
    const char *stage=getenv("APFS_NATIVE_FAULT_STAGE");
if(!stage)return 0;
if(!strcmp(stage,"attribute-mode")||!strcmp(stage,"attribute-restore-mode")){
    int inject=0;
    if(!strcmp(operation,"attribute"))inject=atomic_fetch_add(&attribute_count,1)==0;
    if(!strcmp(operation,"fchmod"))inject=atomic_fetch_add(&mode_count,1)==(!strcmp(stage,"attribute-restore-mode")?1:0);
    if(inject)errno=EACCES;
    return inject;
}
if(strcmp(stage,operation))return 0;

    const char *limit=getenv("APFS_NATIVE_FAULT_COUNT");
    int n=atomic_fetch_add(&fault_count,1)+1, count=limit?atoi(limit):1;
    const char *skip_value=getenv("APFS_NATIVE_FAULT_SKIP");int skip=skip_value?atoi(skip_value):0;
    if(n<=skip||(count>=0&&n-skip>count))return 0;
    const char *error=getenv("APFS_NATIVE_FAULT_ERRNO");
    errno=error?atoi(error):EACCES;
    return 1;
}
static void observation(const char *operation,int fork,long long argument,long long result,int error,int injected) {
    fprintf(stderr,"{\"operation\":\"%s\",\"fork\":%s,\"argument\":%lld,\"result\":%lld,\"errno\":%d,\"injected\":%s}\n",operation,fork==2?"true":"false",argument,result,result<0?error:0,injected?"true":"false");
    errno=error;
}
#define BASIC(name,decl,call,arg) static int probe_##name decl { \
    int match=target_fd(fd);if(!match)return call; \
    int fault=fail(#name),result=fault?-1:call,error=errno; \
    observation(#name,match,arg,result,error,fault);return result; }
BASIC(fstatfs,(int fd,struct statfs *state),fstatfs(fd,state),result?0:state->f_flags)
BASIC(fchmod,(int fd,mode_t mode),fchmod(fd,mode),mode)
BASIC(fchflags,(int fd,unsigned flags),fchflags(fd,flags),flags)
BASIC(ftruncate,(int fd,off_t size),ftruncate(fd,size),size)
BASIC(fsync,(int fd),fsync(fd),0)
static int probe_close(int fd) {
    int match=target_fd(fd);if(!match)return close(fd);
    int fault=fail("close"),result=fault?-1:close(fd),error=errno;
    if(!result&&fd==atomic_load(&fork_descriptor))atomic_store(&fork_descriptor,-1);
    observation("close",match,0,result,error,fault);return result;
}

BASIC(futimes,(int fd,const struct timeval times[2]),futimes(fd,times),times?times[1].tv_sec:-1)
static int probe_fsetxattr(int fd,const char *name,const void *value,size_t size,uint32_t position,int options) {
    int match=target_fd(fd);if(!match)return fsetxattr(fd,name,value,size,position,options);
    const char *operation=!strcmp(name,"com.apple.decmpfs")?"attribute":"other-attribute";
    int fault=fail(operation),result=fault?-1:fsetxattr(fd,name,value,size,position,options),error=errno;
    observation(operation,match,(long long)size,result,error,fault);return result;
}
static int probe_fremovexattr(int fd,const char *name,int options) {
    int match=target_fd(fd);if(!match)return fremovexattr(fd,name,options);
    const char *operation=!strcmp(name,"com.apple.decmpfs")?"remove-attribute":"remove-other";
    int fault=fail(operation),result=fault?-1:fremovexattr(fd,name,options),error=errno;
    observation(operation,match,0,result,error,fault);return result;
}
static ssize_t probe_fgetxattr(int fd,const char *name,void *value,size_t size,uint32_t position,int options) {
    int match=target_fd(fd);if(!match)return fgetxattr(fd,name,value,size,position,options);
    const char *operation=!strcmp(name,"com.apple.decmpfs")?"get-attribute":!strcmp(name,"com.apple.ResourceFork")?"get-fork":"get-other";
    int fault=fail(operation);ssize_t result=fault?-1:fgetxattr(fd,name,value,size,position,options);int error=errno;
    observation(operation,match,(long long)size,result,error,fault);return result;
}
static ssize_t probe_write(int fd,const void *buffer,size_t size) {
    int match=target_fd(fd);if(!match)return write(fd,buffer,size);
    int fault=fail("write");ssize_t result=fault?-1:write(fd,buffer,size);int error=errno;
    observation("write",match,(long long)size,result,error,fault);return result;
}
static ssize_t probe_pwrite(int fd,const void *buffer,size_t size,off_t offset) {
    int match=target_fd(fd);if(!match)return pwrite(fd,buffer,size,offset);
    int short_fault=fail("pwrite-short"),fault=short_fault?0:fail("pwrite");ssize_t result=short_fault?pwrite(fd,buffer,size/2,offset):fault?-1:pwrite(fd,buffer,size,offset);int error=errno;
    observation("pwrite",match,(long long)offset,result,error,fault||short_fault);return result;
}
static int probe_ffsctl(int fd,unsigned long request,void *data,unsigned options) {
    int match=target_fd(fd);if(!match)return ffsctl(fd,request,data,options);
    uint32_t before[3]={0};if(request==0xc00c4114)memcpy(before,data,sizeof(before));
    int fault=fail("ffsctl"),result,error;
    if(!fault&&request==0xc00c4114&&fail("cas-mismatch")){
        // Simulate a real competing metadata update before the atomic compare.
        // The actual inode changes, and native code must re-read it on retry.
        uint32_t flags=before[0]^UF_HIDDEN;
        if(fchflags(fd,flags)){perror("inject competing flags");exit(2);}
        ((uint32_t *)data)[2]=flags;fault=1;result=0;error=0;
    }else{result=fault?-1:ffsctl(fd,request,data,options);error=errno;}
    observation("ffsctl",match,(long long)request,result,error,fault);
    if(request==0xc00c4114){uint32_t after[3];memcpy(after,data,sizeof(after));fprintf(stderr,"{\"operation\":\"cas-flags\",\"expected\":%u,\"replacement\":%u,\"initial_actual\":%u,\"actual\":%u}\n",before[0],before[1],before[2],after[2]);}
    errno=error;return result;
}
#define INTERPOSE(name) \
    __attribute__((used,section("__DATA,__interpose"))) static const struct { const void *replacement; const void *original; } pair_##name = { (const void *)probe_##name, (const void *)name }
INTERPOSE(fstatfs);INTERPOSE(fchmod);INTERPOSE(fchflags);INTERPOSE(ftruncate);
INTERPOSE(fsync);INTERPOSE(close);INTERPOSE(fsetxattr);INTERPOSE(fremovexattr);
INTERPOSE(write);INTERPOSE(pwrite);INTERPOSE(ffsctl);
INTERPOSE(futimes);
INTERPOSE(fgetxattr);
