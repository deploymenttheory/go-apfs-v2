// Native qualification only: public xattr/stat APIs and AppleFSCompression's
// observed producer ABI. No production code links this framework.
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <string.h>
static void die(const char *what){perror(what);exit(2);}
static unsigned char *load(const char *path,size_t *size){FILE *f=fopen(path,"rb");if(!f)die("open input");if(fseek(f,0,SEEK_END))die("seek");long n=ftell(f);if(n<0||n>(128<<20))exit(2);rewind(f);unsigned char *b=malloc(n?n:1);if(!b)die("malloc");if(fread(b,1,n,f)!=(size_t)n)die("read");fclose(f);*size=n;return b;}
static void save(const char *path,const void *b,size_t n){FILE *f=fopen(path,"wb");if(!f)die("open output");if(fwrite(b,1,n,f)!=n)die("write");if(fclose(f))die("close");}
static void capture(const char *path,const char *prefix){
 const char *names[]={"com.apple.decmpfs","com.apple.ResourceFork"};const char *suffix[]={"attr","fork"};char out[4096];
 for(int i=0;i<2;i++){ssize_t n=getxattr(path,names[i],NULL,0,0,XATTR_SHOWCOMPRESSION);if(n<0){if(errno==ENOATTR)continue;die("getxattr size");}if(n>(128<<20))exit(2);void*b=malloc(n?n:1);if(getxattr(path,names[i],b,n,0,XATTR_SHOWCOMPRESSION)!=n)die("getxattr");snprintf(out,sizeof(out),"%s.%s",prefix,suffix[i]);save(out,b,n);free(b);}
 size_t n;void*b=load(path,&n);snprintf(out,sizeof(out),"%s.readback",prefix);save(out,b,n);free(b);
 struct stat st;if(lstat(path,&st))die("lstat");printf("{\"flags\":%u,\"size\":%lld}\n",st.st_flags,(long long)st.st_size);
}
int main(int argc,char **argv){
 if(argc<5)return 2;
 if(!strcmp(argv[1],"produce")){
  void *lib=dlopen("/System/Library/PrivateFrameworks/AppleFSCompression.framework/AppleFSCompression",RTLD_NOW);if(!lib)exit(2);
  void*(*create)(const void*,const void*,const void*,const void*,CFDictionaryRef)=dlsym(lib,"CreateCompressionQueue");
  bool(*compress)(void*,const char*,const char*)=dlsym(lib,"CompressFile");void(*finish)(void*)=dlsym(lib,"FinishCompressionAndCleanUp");if(!create||!compress||!finish)exit(2);
  CFMutableDictionaryRef opts=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);CFStringRef type=CFStringCreateWithCString(NULL,argv[2],kCFStringEncodingUTF8);
  CFDictionarySetValue(opts,CFSTR("CompressionTypes"),type);CFDictionarySetValue(opts,CFSTR("AllowStoringDataInXattr"),kCFBooleanTrue);
  void*q=create(NULL,NULL,NULL,NULL,opts);if(!q)exit(2);if(!compress(q,argv[3],NULL))die("native producer");finish(q);CFRelease(type);CFRelease(opts);dlclose(lib);capture(argv[3],argv[4]);return 0;
 }
 if(!strcmp(argv[1],"install")&&argc==6){
  int fd=open(argv[2],O_CREAT|O_EXCL|O_RDWR,0600);if(fd<0)die("create target");close(fd);size_t n;void*b=load(argv[3],&n);if(setxattr(argv[2],"com.apple.decmpfs",b,n,0,0))die("install header");free(b);
  if(strcmp(argv[4],"-")){b=load(argv[4],&n);if(setxattr(argv[2],"com.apple.ResourceFork",b,n,0,0))die("install fork");free(b);}
  if(chflags(argv[2],UF_COMPRESSED))die("set compressed flag");capture(argv[2],argv[5]);return 0;
 }
 return 2;
}
