/* Independent native receiver reference. TSV results are emitted only after
 * closing each candidate; the completion record follows all directory closes.
 * Creation/producer errno is deliberately not an input to this program. */
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *current_case = "-";
static int candidate = -1;

static void boundary(const char *phase, const char *operation, long long result, int error) {
    int saved = errno;
    if (fprintf(stderr, "REFERENCE %s case=%s candidate=%d operation=%s result=%lld errno=%d\n",
                phase, current_case, candidate, operation, result, error) < 0 || fflush(stderr)) exit(2);
    errno = saved;
}
#define CALL(target, operation, expression) do { \
    boundary("START", operation, 0, 0); \
    (target) = (expression); \
    int saved_error = (target) < 0 ? errno : 0; \
    boundary("END", operation, (long long)(target), saved_error); \
    errno = saved_error; \
} while (0)

static void require(int failed, const char *operation) {
    if (failed) { perror(operation); exit(2); }
}
static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c-'0';
    if (c >= 'a' && c <= 'f') return c-'a'+10;
    return -1;
}
static void decode(const char *s, char *name) {
    size_t length = strlen(s);
    require(length == 0 || length > 2048 || length % 2, "name length");
    for (size_t i=0; i<length; i+=2) {
        int hi=hex_digit(s[i]), lo=hex_digit(s[i+1]);
        require(hi<0 || lo<0 || (hi==0 && lo==0), "name hex");
        name[i/2]=(char)((hi<<4)|lo);
    }
    name[length/2]=0;
}
static void observe(int directory, const char *hex) {
    char name[1025]; decode(hex,name);
    int fd, status;
    struct stat info={0};
    ssize_t count=-1;
    CALL(fd,"openat-file",openat(directory,name,O_RDONLY));
    int error=fd<0?errno:0;
    if(fd>=0) {
        CALL(status,"fstat-file",fstat(fd,&info)); require(status,"fstat");
        char byte;
        CALL(count,"read-file",read(fd,&byte,1)); require(count<0,"read");
        CALL(status,"close-file",close(fd)); require(status,"close");
    }
    require(printf("%s\t%d\t%d\t%llu\t%lld\t%lld\tclosed\n",current_case,candidate,error,
                   (unsigned long long)info.st_ino,(long long)info.st_size,(long long)count)<0 || fflush(stdout),"result");
}
int main(int argc,char **argv) {
    if(argc!=3) return 2;
    FILE *cases=fopen(argv[2],"r"); require(cases==NULL,"cases");
    int root,corpus,status;
    CALL(root,"open-root",open(argv[1],O_RDONLY|O_DIRECTORY)); require(root<0,"root");
    CALL(corpus,"openat-corpus",openat(root,"collation",O_RDONLY|O_DIRECTORY)); require(corpus<0,"corpus");
    char *line=NULL;size_t capacity=0;unsigned count=0;
    while(getline(&line,&capacity,cases)>=0) {
        line[strcspn(line,"\n")]=0;
        char *id=line,*a=strchr(id,'\t'); require(a==NULL,"case");*a++=0;
        char *b=strchr(a,'\t');require(b==NULL,"case");*b++=0;
        require(strchr(b,'\t')!=NULL || *id==0,"case");
        current_case=id;candidate=-1;
        int directory;
        CALL(directory,"openat-case",openat(corpus,id,O_RDONLY|O_DIRECTORY)); require(directory<0,"directory");
        candidate=0;observe(directory,a);
        candidate=1;observe(directory,b);
        candidate=-1;CALL(status,"close-case",close(directory)); require(status,"directory close");
        count++;
        if(count%100==0) { require(fprintf(stderr,"REFERENCE PROGRESS cases=%u last=%s\n",count,id)<0 || fflush(stderr),"progress"); }
    }
    require(ferror(cases),"cases read");require(fclose(cases),"cases close");
    current_case="-";free(line);
    CALL(status,"close-corpus",close(corpus));require(status,"corpus close");
    CALL(status,"close-root",close(root));require(status,"root close");
    require(printf("complete\t%u\n",count)<0 || fflush(stdout),"completion");
    return 0;
}
