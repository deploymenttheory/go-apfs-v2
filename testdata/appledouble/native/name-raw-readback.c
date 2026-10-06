/* Supplemental raw receiver observations. Target calls follow name-readback.c;
 * durable markers and a one-time held volume observation are additional. */
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/attr.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
static const char *nonce,*control,*case_id="";static unsigned index_number;static volatile sig_atomic_t stopped;
static void signal_stop(int n){(void)n;stopped=1;}
static void durable(void){if(fflush(stdout)||fsync(STDOUT_FILENO))exit(3);}
static void marker(const char *op){printf("{\"type\":\"start\",\"index\":%u,\"id\":\"%s\",\"operation\":\"%s\"}\n",index_number,case_id,op);durable();}
static void fatal(const char *op,int e){printf("{\"type\":\"fatal\",\"index\":%u,\"id\":\"%s\",\"operation\":\"%s\",\"errno\":%d,\"interrupted\":%s}\n",index_number,case_id,op,e,stopped?"true":"false");durable();}
static void record(const char *name,const char *body){char p[4096],tmp[4096];if(snprintf(p,sizeof(p),"%s/%s",control,name)>=(int)sizeof(p)||snprintf(tmp,sizeof(tmp),"%s.tmp",p)>=(int)sizeof(tmp))exit(3);FILE*f=fopen(tmp,"w");if(!f||fputs(body,f)<0||fflush(f)||fsync(fileno(f))||fclose(f)||rename(tmp,p))exit(3);}
static int unhex(const char*s,char*out){size_t n=strlen(s);if(n%2||n>2048)return-1;for(size_t i=0;i<n;i+=2){unsigned x=0;if(sscanf(s+i,"%2x",&x)!=1||!x)return-1;out[i/2]=(char)x;}out[n/2]=0;return 0;}
int main(int argc,char **argv){if(argc!=5)return 2;const char*mount=argv[1],*cases=argv[2];control=argv[3];nonce=argv[4];if(strlen(nonce)!=32)return 2;struct sigaction action={0};action.sa_handler=signal_stop;if(sigaction(SIGTERM,&action,NULL))return 2;
char body[2048];snprintf(body,sizeof(body),"{\"schema\":1,\"nonce\":\"%s\",\"pid\":%ld,\"uid\":%u,\"gid\":%u}\n",nonce,(long)getpid(),(unsigned)getuid(),(unsigned)getgid());record("ready.json",body);
char request[4096];if(snprintf(request,sizeof(request),"%s/start",control)>=(int)sizeof(request))return 2;time_t begun=time(NULL);while(access(request,F_OK)&&!stopped){if(time(NULL)-begun>60)return 2;struct timespec delay={0,10000000};nanosleep(&delay,NULL);}if(stopped)return 2;
int root=-1,base=-1,dir=-1,file=-1,error=0;FILE *input=NULL;char *line=NULL;size_t capacity=0;unsigned count=0;
#define REQUIRE(bad,op) do{if(bad){error=errno?errno:EINVAL;fatal(op,error);goto cleanup;}}while(0)
marker("root-open");root=open(mount,O_RDONLY|O_DIRECTORY);REQUIRE(root<0,"root-open");marker("corpus-open");base=openat(root,"collation",O_RDONLY|O_DIRECTORY);REQUIRE(base<0,"corpus-open");
struct statfs fs;marker("held-fstatfs");REQUIRE(fstatfs(base,&fs),"held-fstatfs");struct attrlist attrs={0};attrs.bitmapcount=ATTR_BIT_MAP_COUNT;attrs.volattr=ATTR_VOL_INFO|ATTR_VOL_CAPABILITIES|ATTR_VOL_UUID;struct __attribute__((packed)){uint32_t length;vol_capabilities_attr_t value;unsigned char uuid[16];} caps;marker("held-capabilities");REQUIRE(fgetattrlist(base,&attrs,&caps,sizeof(caps),0),"held-capabilities");struct utsname host;REQUIRE(uname(&host),"uname");printf("{\"type\":\"volume\",\"filesystem\":\"%s\",\"mount_flags\":%u,\"capabilities\":[%u,%u,%u,%u],\"valid\":[%u,%u,%u,%u],\"machine\":\"%s\",\"release\":\"%s\"}\n",fs.f_fstypename,fs.f_flags,caps.value.capabilities[0],caps.value.capabilities[1],caps.value.capabilities[2],caps.value.capabilities[3],caps.value.valid[0],caps.value.valid[1],caps.value.valid[2],caps.value.valid[3],host.machine,host.release);durable();printf("{\"type\":\"volume-uuid\",\"uuid\":\"");for(unsigned u=0;u<16;u++)printf("%02x",caps.uuid[u]);printf("\"}\n");durable();
input=fopen(cases,"r");REQUIRE(!input,"cases-open");while(!stopped&&getline(&line,&capacity,input)>=0){line[strcspn(line,"\n")]=0;char *id=strtok(line,"\t"),*a=strtok(NULL,"\t"),*b=strtok(NULL,"\t");REQUIRE(!id||!a||!b||strtok(NULL,"\t"),"case-fields");case_id=id;index_number=count;marker("case-open");dir=openat(base,id,O_RDONLY|O_DIRECTORY);REQUIRE(dir<0,"case-open");char names[2][1025];REQUIRE(unhex(a,names[0])||unhex(b,names[1]),"case-bytes");int errors[2]={0};struct stat stats[2]={{0},{0}};ssize_t reads[2]={-1,-1};
for(int i=0;i<2;i++){marker(i?"queried-open":"created-open");errno=0;file=openat(dir,names[i],O_RDONLY);errors[i]=file<0?errno:0;if(file>=0){marker(i?"queried-fstat":"created-fstat");REQUIRE(fstat(file,&stats[i]),"file-stat");marker(i?"queried-read":"created-read");char byte;reads[i]=read(file,&byte,1);REQUIRE(reads[i]<0,"file-read");marker(i?"queried-close":"created-close");int rc=close(file);file=-1;REQUIRE(rc,"file-close");}}
marker("case-close");int rc=close(dir);dir=-1;REQUIRE(rc,"case-close");printf("{\"type\":\"case\",\"index\":%u,\"id\":\"%s\",\"results\":[",count,id);for(int i=0;i<2;i++)printf("%s{\"errno\":%d,\"inode\":%llu,\"size\":%lld,\"read\":%lld}",i?",":"",errors[i],(unsigned long long)stats[i].st_ino,(long long)stats[i].st_size,(long long)reads[i]);printf("],\"interrupted\":%s}\n",stopped?"true":"false");durable();count++;case_id="";}
REQUIRE(ferror(input),"cases-read");marker("cases-close");int rc=fclose(input);input=NULL;REQUIRE(rc,"cases-close");marker("corpus-close");rc=close(base);base=-1;REQUIRE(rc,"corpus-close");marker("root-close");rc=close(root);root=-1;REQUIRE(rc,"root-close");
cleanup:;
int cleanup_error=0;int descriptors[]={file,dir,base,root};for(unsigned i=0;i<4;i++)if(descriptors[i]>=0){marker("cleanup-close");if(close(descriptors[i])<0&&cleanup_error==0)cleanup_error=errno;}if(input&&fclose(input)&&cleanup_error==0)cleanup_error=errno;free(line);case_id="";
printf("{\"type\":\"finished\",\"count\":%u,\"error\":%d,\"cleanup_errno\":%d,\"stopped\":%s}\n",count,error,cleanup_error,stopped?"true":"false");durable();snprintf(body,sizeof(body),"{\"schema\":1,\"nonce\":\"%s\",\"pid\":%ld,\"completed\":%u,\"stopped\":%s,\"cleanup_errno\":%d,\"error\":%d}\n",nonce,(long)getpid(),count,stopped?"true":"false",cleanup_error,error);record("finished.json",body);return error||cleanup_error||stopped?2:0;}
