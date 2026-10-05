#define main compression_policy_main
#include "compression-policy.c"
#undef main
#include <sys/acl.h>
#include <membership.h>
#include <sys/mount.h>
#include <sys/attr.h>

static void retained_data(const char *path,const char *prefix) {
    char output[4096];if(snprintf(output,sizeof(output),"%s.data",prefix)>=(int)sizeof(output))exit(2);
    int input=open(path,O_RDONLY|O_NONBLOCK|O_CLOEXEC),error=errno;
    if(input<0){printf(",\"read_errno\":%d,\"read_bytes\":0",error);return;}
    FILE *out=fopen(output,"wb");if(!out)die("data output");
    unsigned char buffer[4096];size_t total=0;ssize_t n;error=0;
    while((n=read(input,buffer,sizeof(buffer)))>0){total+=(size_t)n;if(total>65536)die("unexpected logical growth");if(fwrite(buffer,1,(size_t)n,out)!=(size_t)n)die("save logical bytes");}
    if(n<0)error=errno;
    if(close(input)||fclose(out))die("close logical capture");
    printf(",\"read_errno\":%d,\"read_bytes\":%zu",error,total);
}
static void metadata_changes(const struct stat *before,const struct stat *after) {
    printf(",\"uid_unchanged\":%s,\"gid_unchanged\":%s,\"birth_unchanged\":%s,\"modify_unchanged\":%s,\"access_unchanged\":%s",before->st_uid==after->st_uid?"true":"false",before->st_gid==after->st_gid?"true":"false",before->st_birthtimespec.tv_sec==after->st_birthtimespec.tv_sec&&before->st_birthtimespec.tv_nsec==after->st_birthtimespec.tv_nsec?"true":"false",before->st_mtimespec.tv_sec==after->st_mtimespec.tv_sec&&before->st_mtimespec.tv_nsec==after->st_mtimespec.tv_nsec?"true":"false",before->st_atimespec.tv_sec==after->st_atimespec.tv_sec&&before->st_atimespec.tv_nsec==after->st_atimespec.tv_nsec?"true":"false");
}

// Exploratory native-only probe; each invocation owns one disposable test tree.
int main(int argc, char **argv) {
    if (argc != 6) return 2;
    const char *scenario=argv[1], *path=argv[2], *prefix=argv[3];
    char auxiliary[4096];
    if (snprintf(auxiliary,sizeof(auxiliary),"%s-other",path)>=(int)sizeof(auxiliary)) return 2;
    if (!strcmp(scenario,"directory")) {
        if (mkdir(path,0700)) die("mkdir");
    } else if (!strcmp(scenario,"fifo")) {
        if (mkfifo(path,0600)) die("mkfifo");
    } else {
        int f=open(path,O_CREAT|O_EXCL|O_RDWR,0600); if(f<0)die("create");
        unsigned char content[65536];for(size_t i=0;i<sizeof(content);i++)content[i]="abcd"[i%4];
        if(write(f,content,sizeof(content))!=sizeof(content))die("write");
        if(!strcmp(scenario,"fork")&&fsetxattr(f,"com.apple.ResourceFork","independent",11,0,0))die("fork");
        if(!strcmp(scenario,"empty-fork")&&fsetxattr(f,"com.apple.ResourceFork","",0,0,0))die("empty fork");
        if(!strcmp(scenario,"stale-attribute")&&fsetxattr(f,"com.apple.decmpfs","stale",5,0,0))die("stale attr");
        struct attrlist times_list={.bitmapcount=ATTR_BIT_MAP_COUNT,.commonattr=ATTR_CMN_CRTIME|ATTR_CMN_MODTIME|ATTR_CMN_ACCTIME};
        struct timespec times[3]={{1500000000,0},{1600000000,0},{1550000000,0}};
        if(fsetattrlist(f,&times_list,times,sizeof(times),0))die("fixture times");
        if(!strcmp(scenario,"immutable")&&fchflags(f,UF_IMMUTABLE))die("immutable");
        if(!strcmp(scenario,"append")&&fchflags(f,UF_APPEND))die("append");
        if(!strcmp(scenario,"hidden")&&fchflags(f,UF_HIDDEN))die("hidden");
        if(!strncmp(scenario,"mode-",5)&&fchmod(f,(mode_t)strtoul(scenario+5,NULL,8)))die("mode");
        if(!strncmp(scenario,"deny-",5)) {
            acl_perm_t permission=0;
            if(!strcmp(scenario,"deny-write"))permission=ACL_WRITE_DATA;
            if(!strcmp(scenario,"deny-read"))permission=ACL_READ_DATA;
            if(!strcmp(scenario,"deny-writeattr"))permission=ACL_WRITE_ATTRIBUTES;
            if(!strcmp(scenario,"deny-writexattr"))permission=ACL_WRITE_EXTATTRIBUTES;
            if(!strcmp(scenario,"deny-readxattr"))permission=ACL_READ_EXTATTRIBUTES;
            if(!permission)return 2;
            uuid_t identity;if(mbr_uid_to_uuid(getuid(),identity))die("identity");
            acl_t acl=acl_init(1);acl_entry_t entry;acl_permset_t set;
            if(!acl||acl_create_entry(&acl,&entry)||acl_set_tag_type(entry,ACL_EXTENDED_DENY)||acl_set_qualifier(entry,identity)||acl_get_permset(entry,&set)||acl_add_perm(set,permission)||acl_set_permset(entry,set)||acl_set_fd_np(f,acl,ACL_TYPE_EXTENDED))die("ACL");
            if(acl_free(acl))die("free ACL");
        }
        if(close(f))die("close");
        if(!strcmp(scenario,"hardlink")&&link(path,auxiliary))die("link");
        if(!strcmp(scenario,"symlink")) {
            const char *name=strrchr(auxiliary,'/');if(!name)return 2;
            if(rename(path,auxiliary)||symlink(name+1,path))die("symlink");
        }
    }
    struct stat before,after;if(lstat(path,&before))die("before");struct statfs volume;if(statfs(path,&volume))die("statfs");
    void *library=dlopen("/System/Library/PrivateFrameworks/AppleFSCompression.framework/AppleFSCompression",RTLD_NOW);
    if(!library)die("library");
    void *(*create)(const void*,const void*,const void*,const void*,CFDictionaryRef)=dlsym(library,"CreateCompressionQueue");
    bool (*compress)(void*,const char*,const char*)=dlsym(library,"CompressFile");
    void (*finish)(void*)=dlsym(library,"FinishCompressionAndCleanUp");
    if(!create||!compress||!finish)return 2;
    CFMutableDictionaryRef options=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    if(strcmp(argv[4],"default")){CFStringRef type=CFStringCreateWithCString(NULL,argv[4],kCFStringEncodingUTF8);CFDictionarySetValue(options,CFSTR("CompressionTypes"),type);CFRelease(type);}
    if(!strcmp(argv[5],"no"))CFDictionarySetValue(options,CFSTR("AllowStoringDataInXattr"),kCFBooleanFalse);
    else if(!strcmp(argv[5],"yes"))CFDictionarySetValue(options,CFSTR("AllowStoringDataInXattr"),kCFBooleanTrue);
    else if(strcmp(argv[5],"default"))return 2;
    struct stat target_before,target_after; if(stat(path,&target_before))die("target before");
    void *queue=create(NULL,NULL,NULL,NULL,options);if(!queue)return 2;
    void (*arm)(void)=dlsym(RTLD_DEFAULT,"afsc_probe_arm"),(*disarm)(void)=dlsym(RTLD_DEFAULT,"afsc_probe_disarm");if(getenv("APFS_NATIVE_FAULT_STAGE")&&(!arm||!disarm))die("interposer unavailable");if(arm)arm(); errno=0;bool accepted=compress(queue,path,NULL);int queue_errno=errno;finish(queue);if(disarm)disarm();CFRelease(options);
    if(lstat(path,&after))die("after");
    if(stat(path,&target_after))die("target after");
    printf("{\"volume_flags\":%u,\"accepted\":%s,\"errno\":%d,\"before_mode\":%u,\"after_mode\":%u,\"before_flags\":%u,\"after_flags\":%u,\"before_size\":%lld,\"after_size\":%lld,\"links\":%u,\"inode_unchanged\":%s",volume.f_flags,accepted?"true":"false",queue_errno,before.st_mode,after.st_mode,before.st_flags,after.st_flags,(long long)before.st_size,(long long)after.st_size,after.st_nlink,before.st_ino==after.st_ino?"true":"false");
    metadata_changes(&before,&after);
    printf(",\"target_flags\":%u,\"target_size\":%lld,\"target_inode_unchanged\":%s",target_after.st_flags,(long long)target_after.st_size,target_before.st_ino==target_after.st_ino?"true":"false");
    // Capture operation state first; relax only test-owned restrictions to read
    // remaining bytes and remove the disposable objects after observation.
    if(S_ISREG(after.st_mode)) {
        if(chflags(path,after.st_flags&~(UF_IMMUTABLE|UF_APPEND))||chmod(path,0600))die("cleanup permissions");
        if(!strncmp(scenario,"deny-",5)) { acl_t acl=acl_init(0);if(!acl||acl_set_file(path,ACL_TYPE_EXTENDED,acl)||acl_free(acl))die("cleanup ACL"); }
        printf(",\"storage\":{");inspect(library,path,prefix);printf("}");
        retained_data(path,prefix);
    } else if(S_ISLNK(after.st_mode)) {
        printf(",\"storage\":{");inspect(library,auxiliary,prefix);printf("}");
        retained_data(auxiliary,prefix);
    }
    printf("}\n");
    return dlclose(library)?2:0;
}
