// Compile the complete unchanged Apple source with only symbol renaming and an
// explicit sandbox selector. Each process chooses one selector before dispatch_once.
#include <stdbool.h>
#include <dlfcn.h>
static bool selected_sandbox;
#define _xpc_runtime_is_app_sandboxed oracle_is_sandboxed
#define xattr_name_with_flags oracle_name_with_flags
#define xattr_name_without_flags oracle_name_without_flags
#define xattr_flags_from_name oracle_flags_from_name
#define xattr_intent_with_flags oracle_intent_with_flags
#define xattr_preserve_for_intent oracle_preserve_for_intent
#include "xattr_flags.c"
#undef xattr_preserve_for_intent
#undef _xpc_runtime_is_app_sandboxed
bool oracle_is_sandboxed(void){return selected_sandbox;}
static unsigned nibble(char c){if(c>='0'&&c<='9')return (unsigned)(c-'0');if(c>='a'&&c<='f')return (unsigned)(c-'a')+10;exit(2);}
int main(int argc,char **argv){
 if(argc!=2)return 2;
 int (*preserve)(const char *,unsigned)=oracle_preserve_for_intent;
 if(!strcmp(argv[1],"live")){
  void *xpc=dlopen("/usr/lib/system/libxpc.dylib",RTLD_NOW|RTLD_LOCAL);if(!xpc)return 1;
  bool (*query)(void)=dlsym(xpc,"_xpc_runtime_is_app_sandboxed");if(!query)return 1;
  selected_sandbox=query();preserve=dlsym(RTLD_DEFAULT,"xattr_preserve_for_intent");if(!preserve)return 1;
 }else selected_sandbox=atoi(argv[1])!=0;
 printf("sandbox %d\n",selected_sandbox);
 unsigned intent;char hexname[2049];
 while(scanf("%u %2048s",&intent,hexname)==2){
  char name[1025]={0};size_t n=!strcmp(hexname,"-")?0:strlen(hexname);if(n%2)return 2;
  for(size_t i=0;i<n;i+=2)name[i/2]=(char)((nibble(hexname[i])<<4)|nibble(hexname[i+1]));
  printf("%d\n",preserve(name,intent));
 }
 return ferror(stdin)?1:0;
}
