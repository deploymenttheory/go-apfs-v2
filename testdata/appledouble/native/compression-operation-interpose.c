// Additional acquisition/read observations, confined to the armed test inode.
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
static int compression_trace_fprintf(FILE *,const char *,...) __attribute__((format(printf,2,3)));
#define fprintf compression_trace_fprintf
#include "compression-lifecycle-interpose.c"
#include <stdarg.h>

static int path_state(const char *path,struct stat *state) {
    if(!stat(path,state))return 0;
    const char *suffix="/..namedfork/rsrc";size_t n=strlen(path),s=strlen(suffix);
    if(n<s||strcmp(path+n-s,suffix)||n-s>=4096)return -1;
    char parent[4096];memcpy(parent,path,n-s);parent[n-s]=0;return stat(parent,state);
}
static int target_path(const char *path) {
    if(!atomic_load(&armed))return 0;
    int saved=errno,match=0;struct stat state;
    if(!path_state(path,&state)&&state.st_dev==target_device&&state.st_ino==target_inode) {
        const char *suffix="/..namedfork/rsrc";size_t n=strlen(path),s=strlen(suffix);
        match=n>=s&&!strcmp(path+n-s,suffix)?2:1;
    }
    errno=saved;return match;
}
static int probe_open(const char *path,int flags,...) {
    mode_t mode=0;if(flags&O_CREAT){va_list args;va_start(args,flags);mode=(mode_t)va_arg(args,int);va_end(args);}
    int match=target_path(path);if(!match)return open(path,flags,mode);
    struct stat before,after;if(path_state(path,&before))return -1;
    int fault=fail(match==2?"open-fork":"open-data"),result=fault?-1:open(path,flags,mode),error=errno;
    observation("open",match,flags,result<0?-1:0,error,fault);
    if(result>=0){
        if(fstat(result,&after)){perror("acquisition observation");exit(2);}
        fprintf(stderr,"{\"operation\":\"opened-state\",\"fork\":%s,\"before_flags\":%u,\"after_flags\":%u,\"size\":%lld,\"modify_unchanged\":%s}\n",match==2?"true":"false",before.st_flags,after.st_flags,(long long)after.st_size,before.st_mtimespec.tv_sec==after.st_mtimespec.tv_sec&&before.st_mtimespec.tv_nsec==after.st_mtimespec.tv_nsec?"true":"false");
        if(match==2)atomic_store(&fork_descriptor,result);
    }
    errno=error;return result;
}
static int probe_fstat(int fd,struct stat *state) {
    int match=target_fd(fd);if(!match)return fstat(fd,state);
    int fault=fail("fstat"),result=fault?-1:fstat(fd,state),error=errno;
    observation("fstat",match,result<0?0:state->st_size,result,error,fault);
    if(!result)fprintf(stderr,"{\"operation\":\"stat-state\",\"flags\":%u,\"mode\":%u,\"links\":%u,\"modify_sec\":%lld,\"modify_nsec\":%ld,\"access_sec\":%lld,\"access_nsec\":%ld}\n",state->st_flags,state->st_mode,state->st_nlink,(long long)state->st_mtimespec.tv_sec,state->st_mtimespec.tv_nsec,(long long)state->st_atimespec.tv_sec,state->st_atimespec.tv_nsec);
    errno=error;return result;
}
static int probe_openat(int dirfd,const char *path,int flags,...) {
    mode_t mode=0;if(flags&O_CREAT){va_list args;va_start(args,flags);mode=(mode_t)va_arg(args,int);va_end(args);}
    int match=target_path(path);
    if(!match&&target_fd(dirfd)&&(!strcmp(path,"..namedfork/rsrc")||!strcmp(path,"./..namedfork/rsrc")))match=2;
    if(!match)return openat(dirfd,path,flags,mode);
    int fault=fail(match==2?"open-fork":"open-data"),result=fault?-1:openat(dirfd,path,flags,mode),error=errno;
    observation("openat",match,flags,result<0?-1:0,error,fault);
    if(result>=0&&match==2)atomic_store(&fork_descriptor,result);
    errno=error;return result;
}
static int probe_dup(int fd) {
    int match=target_fd(fd);if(!match)return dup(fd);
    int fault=fail("dup"),result=fault?-1:dup(fd),error=errno;
    observation("dup",match,0,result<0?-1:0,error,fault);return result;
}
static ssize_t probe_pread(int fd,void *buffer,size_t size,off_t offset) {
    int match=target_fd(fd);if(!match)return pread(fd,buffer,size,offset);
    int zero_fault=fail("pread-zero"),short_fault=zero_fault?0:fail("pread-short"),fault=(zero_fault||short_fault)?0:fail("pread");
    ssize_t result=zero_fault?0:short_fault?pread(fd,buffer,size/2,offset):fault?-1:pread(fd,buffer,size,offset);int error=errno;
    observation("pread",match,offset,result,error,fault||short_fault||zero_fault);return result;
}
INTERPOSE(open);INTERPOSE(openat);INTERPOSE(fstat);INTERPOSE(dup);INTERPOSE(pread);

#undef fprintf
static int compression_trace_fprintf(FILE *stream,const char *format,...) {
    char line[8192];va_list args;va_start(args,format);int n=vsnprintf(line,sizeof(line),format,args);va_end(args);
    if(n<0||n>=(int)sizeof(line)){perror("trace bounds");exit(2);}
    if(stream==stderr&&line[0]=='{')return fprintf(stream,"{\"thread\":\"%s\",%s",pthread_main_np()?"caller":"worker",line+1);
    return fprintf(stream,"%s",line);
}
