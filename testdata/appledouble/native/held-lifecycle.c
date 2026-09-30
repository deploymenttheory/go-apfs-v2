// Qualification only. fcopyfile-source.h contains the unchanged Apple body.
#include <copyfile.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

struct _copyfile_state { int src_fd,dst_fd,err; struct stat sb; void *fsec; copyfile_flags_t flags; };
static int source_mode,source_error,fallback_error,selected,cached,failures,stage_code,event_count,chmod_count;
static mode_t destination_mode;
static void event(const char *operation,unsigned value,int error){if(event_count++)putchar(',');printf("{\"Operation\":\"%s\",\"Value\":%u,\"Error\":%d}",operation,value,error);}
#define copyfile_debug(...) ((void)0)
#define copyfile_warn(...) ((void)0)
static int copyfile_preamble(copyfile_state_t *state,copyfile_flags_t flags){(*state)->flags=flags;return 0;}
static int model_statx(int fd,struct stat *st,void *fsec){(void)fsec;if(fd!=10)return -1;st->st_mode=(mode_t)source_mode;st->st_uid=501;st->st_gid=20;event("source-security",0,source_error);if(source_error){errno=source_error;return -1;}return 0;}
static int model_stat(int fd,struct stat *st){memset(st,0,sizeof(*st));st->st_uid=501;st->st_gid=20;if(fd==10){st->st_mode=(mode_t)source_mode;event("source-stat",0,fallback_error);if(fallback_error){errno=fallback_error;return -1;}}else{st->st_mode=destination_mode;event("destination-stat",0,0);}return 0;}
static int model_chmod(int fd,mode_t mode){if(fd!=11)return -1;int error=(failures&(chmod_count++?16:1))?EIO:0;event("mode",mode,error);if(error){errno=error;return -1;}destination_mode=(destination_mode&S_IFMT)|(mode&~S_IFMT);return 0;}
static int copyfile_quarantine(copyfile_state_t state){(void)state;int error=failures&2?EIO:0;event("quarantine",0,error);if(error){errno=error;return -1;}return 0;}
static int model_fcntl(int fd,int command,int value){if(command!=F_NOCACHE||value!=1)return -1;int error=failures&(fd==10?4:8)?EIO:0;event(fd==10?"source-cache":"destination-cache",1,error);if(error){errno=error;return -1;}return 0;}
static int copyfile_internal(copyfile_state_t state,copyfile_flags_t flags){(void)state;(void)flags;int error=stage_code<0?EIO:0;event("route",0,error);if(error)errno=error;return stage_code;}
static int model_free(copyfile_state_t state){(void)state;return 0;}
#define fcopyfile observed_fcopyfile
#define fstatx_np model_statx
#define fstat model_stat
#define fchmod model_chmod
#define fcntl model_fcntl
#define copyfile_state_free model_free
#include "fcopyfile-source.h"
int main(void){
 while(scanf("%d %d %d %d %d %d %d",&source_mode,&source_error,&fallback_error,&selected,&cached,&failures,&stage_code)==7){
  struct _copyfile_state state={.src_fd=cached?10:-2,.dst_fd=-2,.sb={.st_mode=(mode_t)source_mode,.st_uid=501,.st_gid=20}};
  copyfile_flags_t flags=(selected&1?COPYFILE_STAT:0)|(selected&2?COPYFILE_NOCACHE:0);
  event_count=chmod_count=0;destination_mode=S_IFREG|0400;errno=0;
  printf("{\"Events\":[");int result=observed_fcopyfile(10,11,&state,flags);printf("],\"Code\":%d,\"Errno\":%d,\"Mode\":%u}\n",result,errno,destination_mode);
 }
 return ferror(stdin)?1:0;
}
