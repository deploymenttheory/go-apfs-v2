// Qualification only. Complete unchanged Apple copyfile_internal is included
// below. Stage bodies are controlled responses, not claimed kernel behavior.
#include <copyfile.h>
#include <sys/xattr.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct _copyfile_state {
 int src_fd, dst_fd, err;
 const char *src, *dst;
 char *xattr_name;
 void *qinfo, *ctx;
 int (*statuscb)(int, int, copyfile_state_t, const char *, const char *, void *);
};
static int codes[8], cleanup, callback_value, calls, flag_reads;
// A symbolic provider flag, deliberately not presented as libquarantine's
// private ABI value. The coordinator qualifies get/OR/set order, while provider
// conversion remains a separate gate. No live libquarantine calls occur here.
#define QTN_FLAG_DO_NOT_TRANSLOCATE (1U << 28)
#define XATTR_QUARANTINE_NAME "com.apple.quarantine"
#define copyfile_debug(...) ((void)0)
#define copyfile_warn(...) ((void)0)
static void event(const char *name, int code) {
 if (calls++) printf(",");
 printf("{\"Operation\":\"%s\",\"Code\":%d}", name, code);
}
static int stage(copyfile_state_t s, int i, const char *name) {
 if (s->src_fd!=10 || s->dst_fd!=11) exit(3);
 event(name,codes[i]); if(codes[i]) errno=EACCES; return codes[i];
}
static int copyfile_pack(copyfile_state_t s) { return stage(s,0,"pack"); }
static int copyfile_unpack(copyfile_state_t s) { return stage(s,1,"unpack"); }
static int copyfile_xattr(copyfile_state_t s) { return stage(s,2,"xattrs"); }
static int copyfile_data(copyfile_state_t s, bool recursive) { if(recursive)exit(3);return stage(s,3,"data"); }
static int copyfile_security(copyfile_state_t s) { return stage(s,4,"security"); }
static int copyfile_stat(copyfile_state_t s) { return stage(s,5,"stat"); }
static uint32_t qtn_file_get_flags(void *q) { if(!q || flag_reads++)exit(3); return 0x81; }
static int qtn_file_set_flags(void *q, uint32_t flags) {
 if(!q || flag_reads!=1 || flags!=(0x81|QTN_FLAG_DO_NOT_TRANSLOCATE))exit(3);
 event("quarantine-run-in-place",codes[6]);if(codes[6])errno=EACCES;return codes[6];
}
static int qtn_file_apply_to_fd(void *q, int fd) {
 if(!q || fd!=11)exit(3);event("quarantine",codes[7]);if(codes[7])errno=EACCES;return codes[7];
}
static int remove_destination(const char *p) {
 if(strcmp(p,"destination"))exit(3);event("remove-destination",cleanup);if(cleanup)errno=EPERM;return cleanup;
}
static int callback(int what,int when,copyfile_state_t s,const char *src,const char *dst,void *ctx) {
 if(what!=COPYFILE_COPY_XATTR || when!=COPYFILE_ERR || s->ctx!=ctx || s->src!=src || s->dst!=dst || strcmp(s->xattr_name,XATTR_QUARANTINE_NAME))exit(3);
 if(calls++)printf(",");printf("{\"Operation\":\"callback\",\"Code\":%d,\"Xattr\":\"%s\"}",callback_value,s->xattr_name);return callback_value;
}
#define unlink remove_destination
#include "pipeline-source.h"
#undef unlink
int main(void) {
 int f,src,dst,path,q;
 while(scanf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",&f,&src,&dst,&path,&q,&callback_value,&codes[0],&codes[1],&codes[2],&codes[3],&codes[4],&codes[5],&codes[6],&codes[7],&cleanup)==15) {
  copyfile_flags_t flags=0;
  if(f&1)flags|=COPYFILE_ACL;if(f&2)flags|=COPYFILE_STAT;if(f&4)flags|=COPYFILE_XATTR;if(f&8)flags|=COPYFILE_DATA;
  if(f&16)flags|=COPYFILE_PACK;if(f&32)flags|=COPYFILE_UNPACK;if(f&64)flags|=COPYFILE_DATA_SPARSE;if(f&128)flags|=COPYFILE_RUN_IN_PLACE;
  struct _copyfile_state s={.src_fd=src?10:-1,.dst_fd=dst?11:-1,.src="source",.dst=path?"destination":NULL,.qinfo=q?&q:NULL,.statuscb=callback_value==-99?NULL:callback};
  errno=0;calls=0;flag_reads=0;printf("{\"Events\":[");
  int rc=copyfile_internal(&s,flags);
  printf("],\"Code\":%d,\"StateError\":%d,\"CallbackCleared\":%s}\n",rc,s.err,s.xattr_name?"false":"true");
 }
 return ferror(stdin)?2:0;
}
