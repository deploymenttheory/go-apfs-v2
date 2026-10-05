// Native research only. Bounded capture of compression metadata for large files;
// the Go driver separately checks every logical byte through the host kernel.
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
static void fail(const char *what) { perror(what); exit(2); }
static void capture(const char *path, const char *name, const char *prefix, const char *suffix) {
 ssize_t size=getxattr(path,name,NULL,0,0,XATTR_SHOWCOMPRESSION);
 if(size<0){if(errno==ENOATTR)return;fail("attribute size");}
 char output[4096];if(snprintf(output,sizeof(output),"%s.%s",prefix,suffix)>=(int)sizeof(output))exit(2);
 FILE *f=fopen(output,"wb");if(!f)fail("capture open");
 unsigned char buffer[65536];
 for(ssize_t at=0;at<size;){size_t n=(size_t)(size-at);if(n>sizeof(buffer))n=sizeof(buffer);
  ssize_t got=getxattr(path,name,buffer,n,(uint32_t)at,XATTR_SHOWCOMPRESSION);
  if(got!=(ssize_t)n)fail("attribute range");
  if(fwrite(buffer,1,n,f)!=n)fail("capture write");at+=(ssize_t)n;}
 if(fclose(f))fail("capture close");
}
int main(int argc,char **argv){
 if(argc!=4)return 2;
 void *lib=dlopen("/System/Library/PrivateFrameworks/AppleFSCompression.framework/AppleFSCompression",RTLD_NOW);if(!lib)return 2;
 void*(*create)(const void*,const void*,const void*,const void*,CFDictionaryRef)=dlsym(lib,"CreateCompressionQueue");
 bool(*compress)(void*,const char*,const char*)=dlsym(lib,"CompressFile");void(*finish)(void*)=dlsym(lib,"FinishCompressionAndCleanUp");if(!create||!compress||!finish)return 2;
 CFMutableDictionaryRef opts=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);CFStringRef type=CFStringCreateWithCString(NULL,argv[1],kCFStringEncodingUTF8);
 CFDictionarySetValue(opts,CFSTR("CompressionTypes"),type);
 CFDictionarySetValue(opts,CFSTR("AllowLargeResourceForks"),kCFBooleanTrue);
 CFDictionarySetValue(opts,CFSTR("AllowStoringDataInXattr"),kCFBooleanFalse);
 void*q=create(NULL,NULL,NULL,NULL,opts);if(!q)return 2;bool accepted=compress(q,argv[2],NULL);finish(q);CFRelease(type);CFRelease(opts);dlclose(lib);
 struct stat st;if(stat(argv[2],&st))fail("stat");
 capture(argv[2],"com.apple.decmpfs",argv[3],"attr");capture(argv[2],"com.apple.ResourceFork",argv[3],"fork");
 printf("{\"accepted\":%s,\"flags\":%u,\"size\":%lld}\n",accepted?"true":"false",st.st_flags,(long long)st.st_size);return 0;
}
