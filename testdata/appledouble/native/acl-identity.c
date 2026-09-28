// Independent source account observer for ACL tests; never linked into Go.
#include <sys/types.h>
#include <membership.h>
#include <uuid/uuid.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(uid_t) == 4 && sizeof(gid_t) == 4, "32-bit account IDs");
_Static_assert(sizeof(uuid_t) == 16, "principal UUID width");

static void hex(const void *data, size_t n) {
    const unsigned char *p = data;
    printf("\""); for (size_t i = 0; i < n; i++) printf("%02x", p[i]); printf("\"");
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    uuid_t uuid = {0};
    uint32_t id = 0;
    int group = 0, found = 0, account_error = 0, membership = 0;
    const char *name = "";
    if (!strcmp(argv[1], "reverse")) {
        if (strcmp(argv[2], "uuid")) return 2;
        if (uuid_parse(argv[3], uuid)) return 2;
        int kind = -1;
        membership = mbr_uuid_to_id(uuid, &id, &kind);
        if (!membership) {
            errno = 0;
            if (kind == ID_TYPE_UID) {
                struct passwd *p = getpwuid(id); account_error = errno;
                if (p) {found = 1; name = p->pw_name;}
            } else if (kind == ID_TYPE_GID) {
                group = 1;
                struct group *p = getgrgid(id); account_error = errno;
                if (p) {found = 1; name = p->gr_name;}
            } else return 2;
        }
    } else {
        if (!strcmp(argv[1], "group")) group = 1;
        else if (strcmp(argv[1], "user")) return 2;
        int numeric = !strcmp(argv[2], "id");
        if (!numeric && strcmp(argv[2], "name")) return 2;
        if (numeric) {
            char *end = NULL; errno = 0;
            unsigned long long number = strtoull(argv[3], &end, 10);
            if (errno || !*argv[3] || *end || number > UINT32_MAX) return 2;
            id = (uint32_t)number;
        }
        errno = 0;
        if (group) {
            struct group *p = numeric ? getgrgid(id) : getgrnam(argv[3]); account_error = errno;
            if (p) {found = 1;id = p->gr_gid;name = p->gr_name;membership = mbr_gid_to_uuid(id, uuid);}
        } else {
            struct passwd *p = numeric ? getpwuid(id) : getpwnam(argv[3]); account_error = errno;
            if (p) {found = 1;id = p->pw_uid;name = p->pw_name;membership = mbr_uid_to_uuid(id, uuid);}
        }
    }
    printf("{\"UUID\":");hex(uuid, sizeof(uuid));
    printf(",\"Name\":");hex(name, strlen(name));
    printf(",\"ID\":%u,\"Group\":%s,\"Found\":%s,\"AccountErrno\":%d,\"MembershipCode\":%d}\n",
           id, group ? "true" : "false", found ? "true" : "false", account_error, membership);
    return 0;
}
