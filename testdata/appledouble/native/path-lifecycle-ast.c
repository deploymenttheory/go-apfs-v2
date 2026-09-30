// AST qualification only. This translation unit retains complete pinned Apple
// bodies and SDK declarations. Unimplemented declaration-only dependencies are
// NOT executed and this file does not establish native control-flow outcomes.
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/attr.h>
#include <sys/param.h>
#include <sys/paths.h>
#include <sys/xattr.h>
#include <copyfile.h>
#include <membership.h>
#include <fcntl.h>
#include <fts.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

typedef void *qtn_file_t;
typedef uint32_t xattr_operation_intent_t;
#define PROTECTION_CLASS_DEFAULT (-1)
#define XATTR_MAX_GET_RSRC_SIZE (1024*1024)
#define COPYFILE_DEBUG (1<<31)
#define COPYFILE_DEBUG_VAR "COPYFILE_DEBUG"
#define XATTR_QUARANTINE_NAME "com.apple.quarantine"
#define GET_PROT_CLASS(fd) fcntl((fd),F_GETPROTECTIONCLASS)
#define SET_PROT_CLASS(fd,c) fcntl((fd),F_SETPROTECTIONCLASS,(c))
#define copyfile_debug(...) ((void)0)
#define copyfile_warn(...) ((void)0)
extern uint32_t declaration_only_no_translocate_flag;
#define QTN_FLAG_DO_NOT_TRANSLOCATE declaration_only_no_translocate_flag

static int copyfile_open(copyfile_state_t);
static int copyfile_close(copyfile_state_t);
static int copyfile_preamble(copyfile_state_t *,copyfile_flags_t);
static int copyfile_internal(copyfile_state_t,copyfile_flags_t);
static filesec_t copyfile_fix_perms(copyfile_state_t,filesec_t *);
extern int copytree(copyfile_state_t);
extern int copyfile_clone(copyfile_state_t);
extern copyfile_flags_t copyfile_check(copyfile_state_t);
extern int copyfile_quarantine(copyfile_state_t);
extern int doesdecmpfs(int);
extern int copyfile_pack(copyfile_state_t);
extern int copyfile_unpack(copyfile_state_t);
extern int copyfile_xattr(copyfile_state_t);
extern int copyfile_data(copyfile_state_t,bool);
extern int copyfile_security(copyfile_state_t);
extern int copyfile_stat(copyfile_state_t);
extern uint32_t qtn_file_get_flags(qtn_file_t);
extern int qtn_file_set_flags(qtn_file_t,uint32_t);
extern int qtn_file_apply_to_fd(qtn_file_t,int);
extern void qtn_file_free(qtn_file_t);

#include "path-lifecycle-source.h"
