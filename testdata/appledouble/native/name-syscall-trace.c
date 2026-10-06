/* Supplemental diagnostic only. Keep the original name-readback.c operation
 * order and descriptors alive across durable workflow checkpoints. */
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

static volatile sig_atomic_t stop_requested;
static void stop_signal(int number) { (void)number; stop_requested=1; }
static void must(int bad,const char *label) { if(bad) { perror(label); exit(2); } }
static void unhex(const char *s,char *out) { size_t n=strlen(s);must(n%2||n>2048,"hex length");for(size_t i=0;i<n;i+=2) {unsigned x;must(sscanf(s+i,"%2x",&x)!=1||!x,"hex");out[i/2]=(char)x;}out[n/2]=0; }
static void path(char *out,size_t size,const char *dir,const char *name) {int n=snprintf(out,size,"%s/%s",dir,name);must(n<0||(size_t)n>=size,"control path");}
static FILE *begin(const char *dir,const char *name,char *temporary,size_t size) {char leaf[128];int n=snprintf(leaf,sizeof(leaf),"%s.tmp",name);must(n<0||(size_t)n>=sizeof(leaf),"temporary path");path(temporary,size,dir,leaf);FILE *f=fopen(temporary,"w");must(!f,"response open");return f;}
static void publish(FILE *f,const char *dir,const char *name,const char *temporary) {char final[4096];must(fflush(f),"response flush");must(fsync(fileno(f)),"response sync");must(fclose(f),"response close");path(final,sizeof(final),dir,name);must(rename(temporary,final),"response publish");}
int main(int ac,char **av) {
 if(ac!=5) return 2;
 const char *mount=av[1],*input_path=av[2],*control=av[3],*nonce=av[4];
 must(strlen(nonce)!=32,"nonce length");
 struct sigaction action={0};action.sa_handler=stop_signal;must(sigaction(SIGTERM,&action,NULL),"signal handler");
 FILE *input=fopen(input_path,"r");must(!input,"cases");char *line=NULL;size_t capacity=0;must(getline(&line,&capacity,input)<0,"one case required");line[strcspn(line,"\n")]=0;
 char *id=strtok(line,"\t"),*a=strtok(NULL,"\t"),*b=strtok(NULL,"\t");must(!id||!a||!b||strtok(NULL,"\t"),"case fields");
 char case_id[256],names[2][1025];must(strlen(id)>=sizeof(case_id),"case id length");strcpy(case_id,id);unhex(a,names[0]);unhex(b,names[1]);must(fgetc(input)!=EOF||ferror(input),"exactly one case");free(line);must(fclose(input),"close cases");
 char temporary[4096];FILE *out=begin(control,"ready.json",temporary,sizeof(temporary));fprintf(out,"{\"schema\":1,\"nonce\":\"%s\",\"pid\":%ld,\"uid\":%u,\"gid\":%u}\n",nonce,(long)getpid(),(unsigned)getuid(),(unsigned)getgid());publish(out,control,"ready.json",temporary);
 int root=-1,base=-1,dir=-1,file=-1;unsigned completed=0;
 static const char *operations[]={"root-open","corpus-open","case-open","created-open","created-fstat","created-read","created-close","queried-open","queried-fstat","queried-read","queried-close","case-close","corpus-close","root-close"};
 for(unsigned step=1;step<=14&&!stop_requested;step++) {
  char request[4096],request_name[64],response[64],stop_path[4096];snprintf(request_name,sizeof(request_name),"request-%02u.txt",step);snprintf(response,sizeof(response),"result-%02u.json",step);path(request,sizeof(request),control,request_name);path(stop_path,sizeof(stop_path),control,"stop");
  FILE *command=NULL;time_t waiting=time(NULL);
  while(!stop_requested && !(command=fopen(request,"r"))) {must(errno!=ENOENT,"request open");if(access(stop_path,F_OK)==0||time(NULL)-waiting>=180) {stop_requested=1;break;}struct timespec delay={0,10000000};nanosleep(&delay,NULL);}
  if(stop_requested) { if(command) must(fclose(command),"stopped request close"); break; }
  char token[65];unsigned requested=0;must(fscanf(command,"%64s %u",token,&requested)!=2||strcmp(token,nonce)||requested!=step,"request identity");must(fclose(command),"request close");
  fprintf(stdout,"START %u %s\n",step,operations[step-1]);must(fflush(stdout),"trace flush");
  struct stat st={0};ssize_t result=0;int attempted=1;errno=0;
  switch(step) {
   case 1: result=root=open(mount,O_RDONLY|O_DIRECTORY);break;
   case 2: if(root<0) attempted=0;else result=base=openat(root,"collation",O_RDONLY|O_DIRECTORY);break;
   case 3: if(base<0) attempted=0;else result=dir=openat(base,case_id,O_RDONLY|O_DIRECTORY);break;
   case 4: case 8: if(dir<0) attempted=0;else result=file=openat(dir,names[step==4?0:1],O_RDONLY);break;
   case 5: case 9: if(file<0) attempted=0;else result=fstat(file,&st);break;
   case 6: case 10: if(file<0) attempted=0;else {char byte;result=read(file,&byte,1);}break;
   case 7: case 11: if(file<0) attempted=0;else {result=close(file);file=-1;}break;
   case 12: if(dir<0) attempted=0;else {result=close(dir);dir=-1;}break;
   case 13: if(base<0) attempted=0;else {result=close(base);base=-1;}break;
   case 14: if(root<0) attempted=0;else {result=close(root);root=-1;}break;
  }
  int operation_errno=result<0?errno:0;
  fprintf(stdout,"END %u %s result=%lld errno=%d\n",step,operations[step-1],(long long)result,operation_errno);must(fflush(stdout),"trace flush");
  out=begin(control,response,temporary,sizeof(temporary));fprintf(out,"{\"schema\":1,\"nonce\":\"%s\",\"pid\":%ld,\"step\":%u,\"operation\":\"%s\",\"attempted\":%s,\"interrupted\":%s,\"result\":%lld,\"errno\":%d,\"device\":%llu,\"inode\":%llu,\"size\":%lld,\"mode\":%u}\n",nonce,(long)getpid(),step,operations[step-1],attempted?"true":"false",stop_requested?"true":"false",(long long)result,operation_errno,(unsigned long long)st.st_dev,(unsigned long long)st.st_ino,(long long)st.st_size,(unsigned)st.st_mode);publish(out,control,response,temporary);completed=step;
 }
 int cleanup_error=0;int descriptors[]={file,dir,base,root};for(unsigned i=0;i<4;i++) if(descriptors[i]>=0 && close(descriptors[i])<0 && cleanup_error==0) cleanup_error=errno;
 out=begin(control,"finished.json",temporary,sizeof(temporary));fprintf(out,"{\"schema\":1,\"nonce\":\"%s\",\"pid\":%ld,\"completed\":%u,\"stopped\":%s,\"cleanup_errno\":%d}\n",nonce,(long)getpid(),completed,stop_requested?"true":"false",cleanup_error);publish(out,control,"finished.json",temporary);
 return cleanup_error?2:0;
}
