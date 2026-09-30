// Extend the independently retained account observer without changing its
// existing corpus/source hash. Both target architectures must pass these layouts.
#include <stddef.h>
#include "acl-identity.c"
_Static_assert(sizeof(struct passwd)==72 && offsetof(struct passwd,pw_uid)==16 && offsetof(struct passwd,pw_change)==24 && offsetof(struct passwd,pw_expire)==64,"passwd ABI");
_Static_assert(sizeof(struct group)==32 && offsetof(struct group,gr_gid)==16 && offsetof(struct group,gr_mem)==24,"group ABI");
