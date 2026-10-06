/* Native APFS character admission. This oracle performs actual O_CREAT calls;
 * missing-name lookup is deliberately recorded separately because ENOENT does
 * not prove that APFS would admit a name. No SDK implementation is linked. */
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/attr.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static void encode(uint32_t c,char b[8]){size_t n=0;b[n++]='x';if(c<128)b[n++]=(char)c;else if(c<0x800){b[n++]=(char)(0xc0|(c>>6));b[n++]=(char)(0x80|(c&63));}else if(c<0x10000){b[n++]=(char)(0xe0|(c>>12));b[n++]=(char)(0x80|((c>>6)&63));b[n++]=(char)(0x80|(c&63));}else{b[n++]=(char)(0xf0|(c>>18));b[n++]=(char)(0x80|((c>>12)&63));b[n++]=(char)(0x80|((c>>6)&63));b[n++]=(char)(0x80|(c&63));}b[n++]='y';b[n]=0;}
static int create(int dir,const char *name){errno=0;int f=openat(dir,name,O_CREAT|O_EXCL|O_RDWR,0600);if(f<0)return errno;struct stat s;if(fstat(f,&s)!=0||!S_ISREG(s.st_mode)||s.st_size!=0||close(f)!=0||unlinkat(dir,name,0)!=0){perror("create/close/unlink");exit(4);}errno=0;if(fstatat(dir,name,&s,0)==0||errno!=ENOENT){perror("post-unlink");exit(5);}return 0;}
static void hex(const unsigned char*b,size_t n){for(size_t i=0;i<n;i++)printf("%02x",b[i]);}
int main(int ac,char**av){if(ac!=3)return 2;int root=open(av[1],O_RDONLY|O_DIRECTORY);if(root<0)return 3;if(mkdirat(root,"admission",0700)!=0)return 6;int dir=openat(root,"admission",O_RDONLY|O_DIRECTORY);if(dir<0)return 7;struct statfs fs;if(fstatfs(dir,&fs)!=0)return 8;struct attrlist al={.bitmapcount=ATTR_BIT_MAP_COUNT,.volattr=ATTR_VOL_INFO|ATTR_VOL_CAPABILITIES};struct{uint32_t length;vol_capabilities_attr_t cap;} caps;if(fgetattrlist(dir,&al,&caps,sizeof(caps),0)!=0)return 9;
uint8_t *results=malloc(0x110000);if(!results)return 10;memset(results,255,0x110000);uint32_t counts[256]={0};struct timespec a,b;clock_gettime(CLOCK_MONOTONIC,&a);for(uint32_t c=1;c<=0x10ffff;c++){if(c==47||(c>=0xd800&&c<=0xdfff))continue;char name[8];encode(c,name);int e=create(dir,name);if(e<0||e>=255)return 11;results[c]=(uint8_t)e;counts[e]++;}clock_gettime(CLOCK_MONOTONIC,&b);FILE*out=fopen(av[2],"wb");if(!out||fwrite(results,1,0x110000,out)!=0x110000||fclose(out)!=0)return 12;free(results);
printf("{\"filesystem\":\"%s\",\"flags\":%u,\"case_sensitive\":%s,\"capabilities\":[%u,%u,%u,%u],\"valid\":[%u,%u,%u,%u],\"scalar_count\":1112062,\"seconds\":%.6f,\"counts\":{",fs.f_fstypename,fs.f_flags,(caps.cap.capabilities[0]&VOL_CAP_FMT_CASE_SENSITIVE)?"true":"false",caps.cap.capabilities[0],caps.cap.capabilities[1],caps.cap.capabilities[2],caps.cap.capabilities[3],caps.cap.valid[0],caps.cap.valid[1],caps.cap.valid[2],caps.cap.valid[3],(double)(b.tv_sec-a.tv_sec)+(double)(b.tv_nsec-a.tv_nsec)/1e9);int comma=0;for(int i=0;i<255;i++)if(counts[i]){printf("%s\"%d\":%u",comma?",":"",i,counts[i]);comma=1;}printf("},\"controls\":[");
static const unsigned char controls[][9]={{'x','A','y',0},{'x',0xc3,0xa9,'y',0},{'x',0xf0,0x9f,0x98,0x80,'y',0},{'x',0xef,0xbf,0xbd,'y',0},{'x',0xcd,0xb8,'y',0},{'x',0xef,0xb7,0x90,'y',0},{'x',0xf4,0x8f,0xbf,0xbf,'y',0},{'x',0x80,'y',0},{'x',0xc0,0xaf,'y',0},{'x',0xe0,0x80,0xaf,'y',0},{'x',0xed,0xa0,0x80,'y',0},{'x',0xf4,0x90,0x80,0x80,'y',0},{'x',0xc3,0},{'x',0,'z',0},{'x','/','y',0}};static const size_t sizes[]={3,4,6,5,4,5,6,3,4,5,5,6,2,3,3};
for(size_t i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++){struct stat s;errno=0;int lookup=fstatat(dir,(const char*)controls[i],&s,0);int le=lookup<0?errno:0;int ce=create(dir,(const char*)controls[i]);printf("%s{\"index\":%zu,\"bytes\":\"",i?",":"",i);hex(controls[i],sizes[i]);printf("\",\"native_length\":%zu,\"lookup_errno\":%d,\"create_errno\":%d}",strlen((const char*)controls[i]),le,ce);}printf("]}\n");if(close(dir)!=0||unlinkat(root,"admission",AT_REMOVEDIR)!=0||close(root)!=0)return 13;return 0;}
