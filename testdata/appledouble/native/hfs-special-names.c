#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/attr.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void must(int bad,const char *why){if(bad){perror(why);exit(2);}}
static void hex(const char *s){for(size_t i=0;i<strlen(s);i++)printf("%02x",(unsigned char)s[i]);}
int main(int argc,char **argv){
 if(argc!=2||getuid()==0)return 2;
 const char *names[]={"plain",".","..",".\xe2\x80\x8d","\xe2\x80\x8d.","..\xe2\x80\x8d","\xe2\x80\x8d..","\xe2\x80\x8d","x\xe2\x90\x80y","\xe2\x90\x80","x\xef\xbf\xbfy","x%EF%BF%BFy","x:y"};
 int root=open(argv[1],O_RDONLY|O_DIRECTORY);must(root<0,"root");struct statfs fs;must(fstatfs(root,&fs),"statfs");
 struct attrlist attrs={.bitmapcount=ATTR_BIT_MAP_COUNT,.volattr=ATTR_VOL_INFO|ATTR_VOL_CAPABILITIES};struct{unsigned length;vol_capabilities_attr_t value;}caps;must(fgetattrlist(root,&attrs,&caps,sizeof(caps),0),"caps");must(!(caps.value.valid[0]&VOL_CAP_FMT_CASE_SENSITIVE),"missing case policy");
 printf("{\"filesystem\":\"%s\",\"flags\":%u,\"case_sensitive\":%s,\"cases\":[",fs.f_fstypename,fs.f_flags,caps.value.capabilities[0]&VOL_CAP_FMT_CASE_SENSITIVE?"true":"false");
 for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++){
  char d[32];snprintf(d,sizeof(d),"case-%03u",i);must(mkdirat(root,d,0700),"mkdir");int dir=openat(root,d,O_RDONLY|O_DIRECTORY);must(dir<0,"case");
  struct stat before;must(fstat(dir,&before),"parent stat");errno=0;int file=openat(dir,names[i],O_CREAT|O_EXCL|O_RDWR,0600);int ce=file<0?errno:0;struct stat st={0};if(file>=0){must(fstat(file,&st),"file stat");must(write(file,"payload",7)!=7,"payload");must(close(file),"file close");}
  errno=0;int found=openat(dir,names[i],O_RDONLY);int le=found<0?errno:0;struct stat got={0};if(found>=0){must(fstat(found,&got),"lookup stat");if(S_ISREG(got.st_mode)){char data[8]={0};must(read(found,data,sizeof(data))!=7||memcmp(data,"payload",7),"full payload read");}must(close(found),"lookup close");}
  DIR *stream=fdopendir(dir);must(!stream,"fdopendir");
  printf("%s{\"id\":\"%s\",\"name_hex\":\"",i?",":"",d);hex(names[i]);printf("\",\"parent\":%llu,\"create_errno\":%d,\"inode\":%llu,\"lookup_errno\":%d,\"lookup_inode\":%llu,\"stored\":[",(unsigned long long)before.st_ino,ce,(unsigned long long)st.st_ino,le,(unsigned long long)got.st_ino);
  struct dirent *entry;unsigned count=0;while((entry=readdir(stream))){if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;printf("%s{\"hex\":\"",count++?",":"");hex(entry->d_name);printf("\",\"inode\":%llu}",(unsigned long long)entry->d_ino);}printf("]}");must(closedir(stream),"closedir");
 }
 must(close(root),"root close");printf("],\"count\":%zu}\n",sizeof(names)/sizeof(names[0]));return 0;
}
