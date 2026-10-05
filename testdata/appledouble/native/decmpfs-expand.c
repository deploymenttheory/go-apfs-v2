// Research-only container construction. Reuse one independently produced native
// compressed block, then have the macOS kernel validate the expanded file.
// These are kernel-accepted layout controls, not native producer observations.
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static void fail(const char *s) { perror(s); exit(2); }
static uint32_t le(const unsigned char *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static void putle(unsigned char *p,uint32_t n) { for(int i=0;i<4;i++)p[i]=(unsigned char)(n>>(8*i)); }
static void putbe(unsigned char *p,uint32_t n) { for(int i=0;i<4;i++)p[3-i]=(unsigned char)(n>>(8*i)); }
static void writeat(int fd,const void *p,size_t n,off_t at) { if(pwrite(fd,p,n,at)!=(ssize_t)n)fail("write fork"); }
int main(int argc,char **argv) {
 if(argc!=7)return 2;
 uint32_t kind=(uint32_t)strtoul(argv[1],NULL,10);
 uint64_t size=strtoull(argv[2],NULL,10);
 if((kind!=4&&kind!=8&&kind!=12&&kind!=14)||!size||size>((uint64_t)8<<30))return 2;
 int input=open(argv[3],O_RDONLY);if(input<0)fail("native fork");
 unsigned char prefix[272];size_t prefix_size=kind==4?272:8;if(pread(input,prefix,prefix_size,0)!=(ssize_t)prefix_size)fail("native prefix");
 uint32_t start=le(prefix),length;
 if(kind==4){start=260+le(prefix+264);length=le(prefix+268);}else length=le(prefix+4)-start;
 if(!length||length>65537)return 2;
 unsigned char block[65537];if(pread(input,block,length,start)!=(ssize_t)length)fail("native block");if(close(input))fail("close native fork");
 int fork=open(argv[4],O_CREAT|O_EXCL|O_RDWR,0600);if(fork<0)fail("new fork");
 uint32_t count=(uint32_t)((size+65535)/65536);
 uint64_t offset=kind==4?264+(uint64_t)count*8:((uint64_t)count+1)*4;
 unsigned char raw[65537];raw[0]=kind==8?6:255;
 for(size_t i=1;i<sizeof(raw);i++)raw[i]="ABCDEFGHIJKLMNOPQRSTUVWXYZ "[(i-1)%27];
 for(uint32_t i=0;i<count;i++) {
  uint32_t n=length;unsigned char *payload=block;
  if(i==count-1&&size%65536){n=(uint32_t)(size%65536)+1;payload=raw;}
  if(offset+n>UINT32_MAX)return 2;
  unsigned char entry[8];putle(entry,(uint32_t)(kind==4?offset-260:offset));putle(entry+4,n);
  writeat(fork,entry,kind==4?8:4,kind==4?264+(off_t)i*8:(off_t)i*4);
  writeat(fork,payload,n,(off_t)offset);offset+=n;
 }
 if(kind==4){
  const unsigned char trailer[50]={ [25]=28,[27]=50,[30]='c',[31]='m',[32]='p',[33]='f',[37]=10,[39]=1,[40]=255,[41]=255 };
  writeat(fork,trailer,sizeof(trailer),(off_t)offset);
  unsigned char header[264]={0};putbe(header,256);putbe(header+4,(uint32_t)offset);putbe(header+8,(uint32_t)(offset-256));putbe(header+12,50);putbe(header+256,(uint32_t)(offset-260));putle(header+260,count);writeat(fork,header,sizeof(header),0);offset+=50;
 }else{unsigned char end[4];putle(end,(uint32_t)offset);writeat(fork,end,4,(off_t)count*4);}
 int target=open(argv[5],O_CREAT|O_EXCL|O_RDWR,0600);if(target<0)fail("target");
 unsigned char buffer[65536];for(uint64_t at=0;at<offset;){size_t n=offset-at>sizeof(buffer)?sizeof(buffer):(size_t)(offset-at);if(pread(fork,buffer,n,(off_t)at)!=(ssize_t)n)fail("fork read");if(fsetxattr(target,"com.apple.ResourceFork",buffer,n,(uint32_t)at,0))fail("fork install");at+=n;}
 unsigned char attr[16]={'f','p','m','c'};putle(attr+4,kind);for(int i=0;i<8;i++)attr[8+i]=(unsigned char)(size>>(i*8));
 int attribute=open(argv[6],O_CREAT|O_EXCL|O_WRONLY,0600);if(attribute<0)fail("attribute");if(write(attribute,attr,sizeof(attr))!=(ssize_t)sizeof(attr))fail("attribute write");if(close(attribute))fail("attribute close");
 if(fsetxattr(target,"com.apple.decmpfs",attr,sizeof(attr),0,0))fail("header install");if(fchflags(target,UF_COMPRESSED))fail("compressed flag");if(close(target))fail("target close");if(close(fork))fail("fork close");
 printf("{\"type\":%u,\"logical_size\":%llu,\"fork_size\":%llu}\n",kind,(unsigned long long)size,(unsigned long long)offset);
 return 0;
}
