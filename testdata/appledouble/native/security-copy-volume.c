// Test-only query-order oracle. Shared request and live-write instrumentation
// comes from security-copy.c; Apple function bodies are extracted unchanged.
#define main security_copy_baseline_main
#define copyfile_security baseline_copyfile_security
#define fd_volume_has_feature baseline_fd_volume_has_feature
#include "security-copy.c"
#undef main
#undef copyfile_security
#undef fd_volume_has_feature

static int source_policy, destination_policy;
static int policy_volume(int fd, struct statfs *s) {
 int source = live ? fd == source_fd : fd == 11;
 event(source ? "volume-source" : "volume-destination");
 int rc;
 if (live) rc = fstatfs(fd, s);
 else {
  int value = source ? source_policy : destination_policy;
  memset(s, 0, sizeof(*s));
  if (value < 0) { errno = -value; rc = -1; }
  else { s->f_flags = value ? MNT_NOSUID : 0; rc = 0; }
 }
 int error = errno;
 printf(",\"NoSetID\":%s", !rc && (s->f_flags & MNT_NOSUID) ? "true" : "false");
 errno = error;
 return finish(rc);
}
#define fstatfs policy_volume
#define fstatx_np capture
#define fchmodx_np extended
#define fchmod mode_write
#define fchown owner_write
#define acl_set_fd acl_write
#include "volume-copy-source.h"
#undef fstatfs
#undef fstatx_np
#undef fchmodx_np
#undef fchmod
#undef fchown
#undef acl_set_fd

// Replay Go's complete sequence, including actual volume queries. Every write
// still passes through the same live syscall instrumentation as the baseline.
static int policy_direct(int fd) {
 char *line = NULL; size_t cap = 0;
 while (getline(&line, &cap, stdin) > 0) {
  if (!strcmp(line, "volume-source\n") || !strcmp(line, "volume-destination\n")) {
   struct statfs s; (void)policy_volume(!strcmp(line, "volume-source\n") ? source_fd : destination_fd, &s);
  } else {
   // direct() consumes stdin to EOF, so give it exactly this one instruction.
   FILE *original = stdin;
   FILE *one = fmemopen(line, strlen(line), "r");
   if (!one) fail("instruction stream");
   stdin = one; (void)direct(fd); stdin = original;
   if (fclose(one)) fail("instruction close");
  }
 }
 free(line); return 0;
}

int main(int argc, char **argv) {
 // model flags filter sourceACL destinationACL presence fault sourcePolicy destinationPolicy
 // live flags filter sourceACL destinationACL root kind targetFlags native|go
 if (argc != 10 && argc != 11) return 2;
 int model = !strcmp(argv[1], "model");
 if (!model && strcmp(argv[1], "live")) return 2;
 unsigned flags = (unsigned)strtoul(argv[2], NULL, 0); filter = atoi(argv[3]);
 acl_t src = load_acl(argv[4]), dst = load_acl(argv[5]);
 filesec_t f = filesec_init(); if (!f) fail("state init");
 struct _copyfile_state state = {.flags=flags, .fsec=f, .src_fd=11, .dst_fd=12, .sb={.st_uid=44, .st_gid=45, .st_mode=06711}};
 if (filter == 1) state.internal_flags = cfForbidCopySuidBits;
 if (filter == 2) state.internal_flags = cfAlwaysCopySuidBits | cfForbidCopySuidBits;
 struct stat sb, db, sa, da; int directory = 0;
 if (model) {
  unsigned presence = (unsigned)strtoul(argv[6], NULL, 0); fault = atoi(argv[7]);
  source_policy = atoi(argv[8]); destination_policy = atoi(argv[9]);
  uid_t uid=42; gid_t gid=43; mode_t mode=06755; unsigned char owner[16]={0x11}, group[16]={0x22};
  if (src && filesec_set_property(f, FILESEC_ACL, &src)) fail("source ACL");
  if ((presence&1) && filesec_set_property(f, FILESEC_OWNER, &uid)) fail("source UID");
  if ((presence&2) && filesec_set_property(f, FILESEC_GROUP, &gid)) fail("source GID");
  if ((presence&4) && filesec_set_property(f, FILESEC_MODE, &mode)) fail("source mode");
  if ((presence&8) && filesec_set_property(f, FILESEC_UUID, owner)) fail("source UUID");
  if ((presence&16) && filesec_set_property(f, FILESEC_GRPUUID, group)) fail("source group UUID");
  target_acl = dst;
 } else {
  live=1; directory=!strcmp(argv[7], "directory");
  if (!directory && strcmp(argv[7], "file")) return 2;
  char s[4096], d[4096];
  if (snprintf(s,sizeof(s),"%s/source",argv[6]) >= (int)sizeof(s) || snprintf(d,sizeof(d),"%s/target",argc == 11 ? argv[10] : argv[6]) >= (int)sizeof(d)) return 2;
  source_fd=create(s,directory,src,06755,"source"); destination_fd=create(d,directory,dst,directory?0755:0644,"target");
  if (atexit(cleanup)) fail("cleanup");
  struct statfs fs;
  if (fstatfs(source_fd,&fs) || strcmp(fs.f_fstypename,"apfs")) fail("requires source APFS");
  if (fstatfs(destination_fd,&fs) || strcmp(fs.f_fstypename,"apfs")) fail("requires destination APFS");
  if (fstatx_np(source_fd,&state.sb,f) || fchflags(destination_fd,(unsigned)strtoul(argv[8],NULL,0))) fail("live baseline");
  state.src_fd=source_fd; state.dst_fd=destination_fd;
 }
 printf("{\"Source\":{\"Properties\":"); print_properties(f);
 printf(",\"UID\":%u,\"GID\":%u,\"Mode\":%u}",state.sb.st_uid,state.sb.st_gid,state.sb.st_mode);
 if (!model) { printf(",\"SourceBefore\":"); snapshot(source_fd,&sb); printf(",\"Before\":"); snapshot(destination_fd,&db); }
 printf(",\"Events\":["); errno=0;
 int rc = model || !strcmp(argv[9],"native") ? copyfile_security(&state) : policy_direct(destination_fd);
 int error=rc?errno:0;
 printf("],\"Code\":%d,\"Errno\":%d,\"Cache\":",rc,error); print_properties(f);
 if (!model) {
  printf(",\"SourceAfter\":"); snapshot(source_fd,&sa); printf(",\"After\":"); snapshot(destination_fd,&da);
  payload(source_fd,directory,"source"); payload(destination_fd,directory,"target");
  printf(",\"IdentityUnchanged\":%s,\"PayloadUnchanged\":true,\"Filesystem\":\"apfs\"",sb.st_dev==sa.st_dev&&sb.st_ino==sa.st_ino&&db.st_dev==da.st_dev&&db.st_ino==da.st_ino?"true":"false");
 }
 printf("}\n"); if(src) acl_free(src); if(dst) acl_free(dst); filesec_free(f); return 0;
}
