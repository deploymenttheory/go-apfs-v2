// Native volume-capability oracle; qualification only, never a runtime backend.
#include <sys/attr.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
struct volume_result { uint32_t length; vol_capabilities_attr_t caps; };
_Static_assert(sizeof(struct volume_result) == 36, "volume reply size");
_Static_assert(offsetof(struct volume_result, caps.valid) == 20, "validity offset");
_Static_assert(VOL_CAPABILITIES_INTERFACES == 1, "interface index");
_Static_assert(VOL_CAP_INT_EXTENDED_SECURITY == 0x400, "ACL capability bit");
int replacement_volume_oracle(const char *path, const char *target) {
 int fd = open(path, O_RDONLY);
 if (fd < 0) return 3;
 struct attrlist request = {.bitmapcount=ATTR_BIT_MAP_COUNT, .volattr=ATTR_VOL_INFO|ATTR_VOL_CAPABILITIES};
 struct volume_result result = {0};
 int status = fgetattrlist(fd, &request, &result, sizeof result, 0);
 int saved = status < 0 ? errno : 0;
 struct stat source_stat, target_stat;
 if (fstat(fd, &source_stat) != 0) return 4;
 int output = open(target, O_CREAT|O_EXCL|O_RDWR, 0600);
 if (output < 0) return 5;
 struct attrlist birth_request = {.bitmapcount=ATTR_BIT_MAP_COUNT, .commonattr=ATTR_CMN_CRTIME};
 struct timespec birth = source_stat.st_birthtimespec;
 if (fsetattrlist(output, &birth_request, &birth, sizeof birth, 0) != 0 || fstat(output, &target_stat) != 0) return 6;
 if (close(output) != 0 || close(fd) != 0) return 7;
 printf("{\"status\":%d,\"errno\":%d,\"length\":%u,\"capabilities\":%u,\"valid\":%u,\"birth_seconds\":%jd,\"birth_nanoseconds\":%ld}\n", status, saved, result.length, result.caps.capabilities[VOL_CAPABILITIES_INTERFACES], result.caps.valid[VOL_CAPABILITIES_INTERFACES], (intmax_t)target_stat.st_birthtimespec.tv_sec, target_stat.st_birthtimespec.tv_nsec);
 return 0;
}
int main(int argc, char **argv) { return argc == 3 ? replacement_volume_oracle(argv[1], argv[2]) : 2; }
