/* Qualification only: independent minimal attributes and full stat controls. */
#include <sys/types.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
_Static_assert(sizeof(fsobj_type_t)==4,"vnode type width");
struct result { uint32_t size; fsobj_type_t type; };
_Static_assert(sizeof(struct result)==8 && offsetof(struct result,type)==4,"attribute result layout");
int main(int argc,char **argv){
 if(argc!=2)return 2;
 int parent=open(argv[1],O_RDONLY|O_DIRECTORY|O_CLOEXEC);
 if(parent<0)return 3;
 struct attrlist attrs={.bitmapcount=ATTR_BIT_MAP_COUNT,.commonattr=ATTR_CMN_OBJTYPE};
 struct result result={0};
 int r=getattrlistat(parent,"file",&attrs,&result,sizeof(result),FSOPT_NOFOLLOW);
 int query_error=r<0?errno:0;
 struct stat st;
 r=fstatat(parent,"file",&st,AT_SYMLINK_NOFOLLOW);
 int stat_error=r<0?errno:0;
 if(close(parent)<0)return 4;
 printf("{\"errno\":%d,\"vnode_type\":%u,\"size\":%u,\"stat_errno\":%d}\n",query_error,result.type,result.size,stat_error);
 return 0;
}
