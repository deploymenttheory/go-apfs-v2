// Qualification only: actual installed fcopyfile inside an entitled app bundle.
// Reuse the existing independent inspector; every operation checks libxpc's
// actual sandbox predicate rather than inferring state from its entitlements.
#define main object_inspector_main
#include "appledouble-object.c"
#undef main
#include <stdbool.h>
extern bool _xpc_runtime_is_app_sandboxed(void);
int main(int argc,char **argv){
 if(argc==3&&!strcmp(argv[1],"inspect"))return object_inspector_main(argc,argv);
 if(argc!=6||!_xpc_runtime_is_app_sandboxed())return 40;
 int source=open(argv[2],O_RDONLY|O_SYMLINK|O_NONBLOCK);
 if(source<0){printf("{\"code\":-1,\"errno\":%d,\"stage\":\"open-source\",\"sandboxed\":true}\n",errno);return 0;}
 int packing=!strcmp(argv[1],"pack");
 int destination=open(argv[3],(packing?O_RDWR:O_RDONLY)|O_SYMLINK|O_NONBLOCK);
 if(destination<0){int saved=errno;close(source);printf("{\"code\":-1,\"errno\":%d,\"stage\":\"open-destination\",\"sandboxed\":true}\n",saved);return 0;}
 copyfile_flags_t flags=(packing?COPYFILE_PACK:COPYFILE_UNPACK)|COPYFILE_XATTR;
 if(atoi(argv[4]))flags|=COPYFILE_ACL;if(atoi(argv[5]))flags|=COPYFILE_STAT;
 errno=0;int result=fcopyfile(source,destination,NULL,flags),saved=errno;
 printf("{\"code\":%d,\"errno\":%d,\"stage\":\"operation\",\"sandboxed\":true}\n",result,saved);
 close(source);close(destination);return 0;
}
