// Research oracle only: execute Darwin pathname operations, never emulate errno.
// Build: xcrun clang -std=c11 -Wall -Wextra -Werror probe.c -o probe
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/acl.h>
#include <sys/kauth.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <membership.h>
#include <fcntl.h>
#include <unistd.h>
#include <grp.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

extern ssize_t acl_copy_ext_native(void *, acl_t, ssize_t);
enum { ROOT, MIDDLE, PARENT, LEAF, STAGE, DEST_PARENT, DEST_LEAF, COUNT };
static const char *names[] = {"root", "a", "a/b", "a/b/file", "a/b/stage", "a/c", "a/c/file"};
static int handles[COUNT]={-1,-1,-1,-1,-1,-1,-1};
static uid_t actor_uid;
static gid_t actor_gid;
static uuid_t actor_uuid, group_uuid;
static int privileged;
static char fixture[PATH_MAX], absolute[PATH_MAX];
static char destination_fixture[PATH_MAX];
static int destination_root=-1;
static int cleanup_done;
static const char *base_directory="/private/tmp";
static int prepare_only;
static int regular(int index) {return index==LEAF||index==STAGE||index==DEST_LEAF;}
static void must(int bad, const char *what) { if (bad) { perror(what); exit(2); } }
static void hex(const void *data, size_t size) {
    const unsigned char *p = data;
    putchar('"'); for (size_t i=0;i<size;i++) printf("%02x",p[i]); putchar('"');
}
static void clear_acl(int fd) {
    acl_t acl=acl_init(0); must(!acl,"acl_init");
    must(acl_set_fd_np(fd,acl,ACL_TYPE_EXTENDED),"clear ACL"); acl_free(acl);
}
static void install_acl(int fd, const uuid_t identity, uint32_t rights, int deny,
                        uint32_t second_rights, int second_deny) {
    acl_t acl=acl_init(2); must(!acl,"acl_init");
    uint32_t masks[2]={rights,second_rights};
    for (unsigned i=0;i<(second_rights?2U:1U);i++) {
        acl_entry_t entry; must(acl_create_entry(&acl,&entry),"acl_create_entry");
        must(acl_set_tag_type(entry,(i?second_deny:deny)?ACL_EXTENDED_DENY:ACL_EXTENDED_ALLOW),"acl tag");
        must(acl_set_qualifier(entry,identity),"acl identity");
        must(acl_set_permset_mask_np(entry,masks[i]&0x001fffff),"acl permissions");
    }
    ssize_t length=acl_size(acl); must(length<44,"ACL size");
    struct kauth_filesec *raw=calloc(1,(size_t)length); must(!raw,"calloc");
    must(acl_copy_ext_native(raw,acl,length)!=length,"ACL raw");
    for (unsigned i=0;i<(second_rights?2U:1U);i++) raw->fsec_acl.acl_ace[i].ace_rights=masks[i];
    filesec_t sec=filesec_init(); size_t allocation=(size_t)length; must(!sec,"filesec_init");
    must(filesec_set_property(sec,FILESEC_ACL_ALLOCSIZE,&allocation),"ACL allocation");
    must(filesec_set_property(sec,FILESEC_ACL_RAW,&raw),"ACL property");
    must(fchmodx_np(fd,sec),"ACL installation");
    // FILESEC_ACL_RAW transfers ownership to the filesec object.
    filesec_free(sec); acl_free(acl);
}
static void snapshot(int fd, int regular) {
    struct stat s; struct statfs fs;
    must(fstat(fd,&s),"fstat snapshot"); must(fstatfs(fd,&fs),"fstatfs");
    printf("{\"dev\":%llu,\"inode\":%llu,\"links\":%u,\"size\":%lld,\"uid\":%u,\"gid\":%u,\"mode\":%u,\"flags\":%u,\"mount_flags\":%u,\"filesystem\":\"%s\",",(unsigned long long)s.st_dev,(unsigned long long)s.st_ino,s.st_nlink,(long long)s.st_size,s.st_uid,s.st_gid,s.st_mode,s.st_flags,fs.f_flags,fs.f_fstypename);
    printf("\"times\":[[%lld,%ld],[%lld,%ld],[%lld,%ld],[%lld,%ld]],",(long long)s.st_atimespec.tv_sec,s.st_atimespec.tv_nsec,(long long)s.st_mtimespec.tv_sec,s.st_mtimespec.tv_nsec,(long long)s.st_ctimespec.tv_sec,s.st_ctimespec.tv_nsec,(long long)s.st_birthtimespec.tv_sec,s.st_birthtimespec.tv_nsec);
    errno=0; acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED); int error=acl?0:errno;
    printf("\"security_captured\":%s,\"security_errno\":%d,\"security\":",acl||error==ENOENT?"true":"false",error);
    if (acl) { ssize_t size=acl_size(acl); must(size<0||size>65536,"acl_size"); unsigned char *raw=malloc((size_t)size);must(!raw,"malloc");must(acl_copy_ext(raw,acl,size)!=size,"acl export");hex(raw,(size_t)size);free(raw);acl_free(acl); } else printf("\"\"");
    if (regular) { unsigned char data[64]; errno=0;ssize_t n=pread(fd,data,sizeof(data),0);int e=n<0?errno:0;printf(",\"data_errno\":%d,\"data\":",e);hex(data,n>0?(size_t)n:0); }
    printf("}");
}
static void snapshots(void) {
    printf("[");for(int i=0;i<COUNT;i++){if(i)printf(",");printf("{\"name\":\"%s\",\"state\":",names[i]);snapshot(handles[i],regular(i));printf("}");}printf("]");
}
static void namespace_state(void) {
    const char *entries[]={"file","stage","new","file"};
    printf("[");for(int i=0;i<4;i++) {
        struct stat s;errno=0;int rc=fstatat(handles[i==3?DEST_PARENT:PARENT],entries[i],&s,AT_SYMLINK_NOFOLLOW),e=rc?errno:0;
        printf("%s{\"name\":\"a/%s/%s\",\"errno\":%d",i?",":"",i==3?"c":"b",entries[i],e);
        if(!rc)printf(",\"dev\":%llu,\"inode\":%llu,\"links\":%u",(unsigned long long)s.st_dev,(unsigned long long)s.st_ino,s.st_nlink);
        printf("}");
    }printf("]");
}
static void emergency_cleanup(void) {
    if(cleanup_done)return;
    for(int i=0;i<COUNT;i++)if(handles[i]>=0){
        if(fchflags(handles[i],0))perror("failed-setup cleanup flags");
        acl_t empty=acl_init(0);if(empty){if(acl_set_fd_np(handles[i],empty,ACL_TYPE_EXTENDED))perror("failed-setup cleanup ACL");acl_free(empty);}
        if(fchmod(handles[i],regular(i)?0600:0700))perror("failed-setup cleanup mode");
    }
    const char *entries[]={"file","stage","new"};for(int i=0;i<3;i++)if(handles[PARENT]>=0&&unlinkat(handles[PARENT],entries[i],0)&&errno!=ENOENT)perror("failed-setup cleanup entry");
    if(handles[DEST_PARENT]>=0&&unlinkat(handles[DEST_PARENT],"file",0)&&errno!=ENOENT)perror("failed-setup cleanup destination");
    for(int i=COUNT-1;i>=0;i--)if(handles[i]>=0&&close(handles[i]))perror("failed-setup cleanup close");
    if(*fixture){char path[PATH_MAX];const char *suffix[]={"/a/b","/a/c","/a",""};for(int i=0;i<4;i++){snprintf(path,sizeof(path),"%s%s",fixture,suffix[i]);if(rmdir(path)&&errno!=ENOENT)perror("failed-setup cleanup directory");}}
}
struct result { int setup_errno, error, close_errno; uid_t uid; gid_t gid; int ngroups; gid_t groups[128]; int process_policy,process_policy_errno,thread_policy,thread_policy_errno; };
static struct result perform(const char *operation,const char *route) {
    int pipes[2];must(pipe(pipes),"pipe");pid_t pid=fork();must(pid<0,"fork");
    if (!pid) {
        close(pipes[0]);struct result r={0};
        if(privileged) { if(setgroups(1,&actor_gid)||setgid(actor_gid)||setuid(actor_uid))r.setup_errno=errno; }
        r.uid=geteuid();r.gid=getegid();r.ngroups=getgroups(128,r.groups);if(r.ngroups<0)r.setup_errno=errno;
        errno=0;r.process_policy=getiopolicy_np(IOPOL_TYPE_VFS_IGNORE_PERMISSIONS,IOPOL_SCOPE_PROCESS);r.process_policy_errno=r.process_policy<0?errno:0;
        errno=0;r.thread_policy=getiopolicy_np(IOPOL_TYPE_VFS_IGNORE_PERMISSIONS,IOPOL_SCOPE_THREAD);r.thread_policy_errno=r.thread_policy<0?errno:0;
        int dfd=AT_FDCWD;const char *path=absolute,*stage=NULL;char stagepath[PATH_MAX];
        if(!strcmp(route,"root")){dfd=handles[ROOT];path="a/b/file";stage="a/b/stage";}
        else if(!strcmp(route,"parent")){dfd=handles[PARENT];path="file";stage="stage";}
        else {int n=snprintf(stagepath,sizeof(stagepath),"%s/a/b/stage",fixture);if(n<0||(size_t)n>=sizeof(stagepath))r.setup_errno=ENAMETOOLONG;stage=stagepath;}
        if(!r.setup_errno) {
            errno=0;int rc=-1,fd=-1;
            if(!strcmp(operation,"open"))fd=openat(dfd,path,O_RDWR),rc=fd<0?-1:0;
            else if(!strcmp(operation,"open-read"))fd=openat(dfd,path,O_RDONLY),rc=fd<0?-1:0;
            else if(!strcmp(operation,"create")){const char *newname=!strcmp(route,"root")?"a/b/new":!strcmp(route,"parent")?"new":NULL;char newpath[PATH_MAX];if(!newname){int n=snprintf(newpath,sizeof(newpath),"%s/a/b/new",fixture);if(n<0||(size_t)n>=sizeof(newpath))_exit(3);newname=newpath;}fd=openat(dfd,newname,O_CREAT|O_EXCL|O_RDWR,0600);rc=fd<0?-1:0;}
            else if(!strcmp(operation,"unlink"))rc=unlinkat(dfd,path,0);
            else if(!strcmp(operation,"rename"))rc=renameat(dfd,stage,dfd,path);
            else if(!strcmp(operation,"rename-absent")||!strcmp(operation,"rename-cross")) {
                int cross=!strcmp(operation,"rename-cross");int targetfd=dfd;
                const char *target=NULL;char targetpath[PATH_MAX];
                if(!strcmp(route,"root")){target=cross?"a/c/file":"a/b/new";if(cross&&destination_root>=0)targetfd=destination_root;}
                else if(!strcmp(route,"parent")){target=cross?"file":"new";if(cross)targetfd=handles[DEST_PARENT];}
                else {int n=snprintf(targetpath,sizeof(targetpath),"%s/%s",cross&&*destination_fixture?destination_fixture:fixture,cross?"a/c/file":"a/b/new");if(n<0||(size_t)n>=sizeof(targetpath))_exit(3);target=targetpath;}
                rc=renameat(dfd,stage,targetfd,target);
            }
            else if(!strcmp(operation,"held-write"))rc=(int)write(handles[LEAF],"",0);
            else if(!strcmp(operation,"chmod-open")){rc=fchmod(handles[LEAF],0600);if(!rc){fd=openat(dfd,path,O_RDWR);rc=fd<0?-1:0;}}
            else _exit(3);
            r.error=rc<0?errno:0;if(fd>=0&&close(fd))r.close_errno=errno;
        }
        ssize_t n=write(pipes[1],&r,sizeof(r));close(pipes[1]);_exit(n==sizeof(r)?0:3);
    }
    close(pipes[1]);struct result r;size_t offset=0;while(offset<sizeof(r)){ssize_t n=read(pipes[0],(char*)&r+offset,sizeof(r)-offset);must(n<=0,"child result");offset+=(size_t)n;}close(pipes[0]);int status;must(waitpid(pid,&status,0)<0||!WIFEXITED(status)||WEXITSTATUS(status),"child status");return r;
}
static void emit_result(struct result r) {
    printf("{\"setup_errno\":%d,\"errno\":%d,\"close_errno\":%d,\"uid\":%u,\"gid\":%u,\"process_policy\":%d,\"process_policy_errno\":%d,\"thread_policy\":%d,\"thread_policy_errno\":%d,\"groups\":[",r.setup_errno,r.error,r.close_errno,r.uid,r.gid,r.process_policy,r.process_policy_errno,r.thread_policy,r.thread_policy_errno);for(int i=0;i<r.ngroups;i++)printf("%s%u",i?",":"",r.groups[i]);printf("]}");
}
// Mounted fixtures belong to the caller. Prepare the same a/b and a/c records
// before mounting readonly; this entry point never fabricates unavailable setup.
static int mounted(int argc,char **argv) {
    if(argc!=8)return 2;
    const char *operation=argv[2],*route=argv[3];actor_uid=(uid_t)strtoul(argv[6],NULL,10);actor_gid=(gid_t)strtoul(argv[7],NULL,10);privileged=geteuid()==0;
    if(actor_uid==0||strlen(argv[4])>=sizeof(fixture)||strlen(argv[5])>=sizeof(destination_fixture))return 2;
    strcpy(fixture,argv[4]);strcpy(destination_fixture,argv[5]);
    handles[ROOT]=open(fixture,O_RDONLY|O_DIRECTORY);must(handles[ROOT]<0,"mounted root");
    handles[MIDDLE]=openat(handles[ROOT],"a",O_RDONLY|O_DIRECTORY);handles[PARENT]=openat(handles[ROOT],"a/b",O_RDONLY|O_DIRECTORY);must(handles[MIDDLE]<0||handles[PARENT]<0,"mounted parents");
    destination_root=open(destination_fixture,O_RDONLY|O_DIRECTORY);must(destination_root<0,"mounted destination root");
    handles[DEST_PARENT]=openat(destination_root,"a/c",O_RDONLY|O_DIRECTORY);must(handles[DEST_PARENT]<0,"mounted destination parent");
    handles[LEAF]=openat(handles[PARENT],"file",O_RDONLY);handles[STAGE]=openat(handles[PARENT],"stage",O_RDONLY);handles[DEST_LEAF]=openat(handles[DEST_PARENT],"file",O_RDONLY);must(handles[LEAF]<0||handles[STAGE]<0||handles[DEST_LEAF]<0,"mounted files");
    int n=snprintf(absolute,sizeof(absolute),"%s/a/b/file",fixture);must(n<0||(size_t)n>=sizeof(absolute),"mounted path");
    must(mbr_uid_to_uuid(actor_uid,actor_uuid),"mounted actor identity");must(mbr_gid_to_uuid(actor_gid,group_uuid),"mounted group identity");int group_member=0;int membership_error=mbr_check_membership(actor_uuid,group_uuid,&group_member);
    printf("{\"qualification\":\"captured\",\"operation\":\"%s\",\"route\":\"%s\",\"fixture_owned\":false,\"user_uuid\":",operation,route);hex(actor_uuid,16);printf(",\"group_uuid\":");hex(group_uuid,16);printf(",\"group_membership_errno\":%d,\"group_member\":%d,\"before\":",membership_error,group_member);snapshots();printf(",\"namespace_before\":");namespace_state();
    struct result r=perform(operation,route);printf(",\"result\":");emit_result(r);printf(",\"after\":");snapshots();printf(",\"namespace_after\":");namespace_state();
    for(int i=0;i<COUNT;i++)must(close(handles[i]),"mounted close");must(close(destination_root),"mounted destination close");printf(",\"handles_closed\":true}\n");return 0;
}
static int restrict_fixture(const char *profile) {
    int p=handles[PARENT],f=handles[LEAF];
    if(!strcmp(profile,"ordinary"))return 0;
    if(!strcmp(profile,"root-no-search"))return fchmod(handles[ROOT],0600);
    if(!strcmp(profile,"middle-no-search"))return fchmod(handles[MIDDLE],0600);
    if(!strcmp(profile,"parent-no-search"))return fchmod(p,0600);
    if(!strcmp(profile,"parent-search-only"))return fchmod(p,0100);
    if(!strcmp(profile,"parent-list-only"))return fchmod(p,0400);
    if(!strcmp(profile,"parent-no-write"))return fchmod(p,0500);
    if(!strcmp(profile,"parent-deny-search"))install_acl(p,actor_uuid,ACL_SEARCH,1,0,0);
    else if(!strcmp(profile,"parent-allow-search")){must(fchmod(p,0),"mode");install_acl(p,actor_uuid,ACL_SEARCH,0,0,0);}
    else if(!strcmp(profile,"parent-allow-deny-search")){must(fchmod(p,0),"mode");install_acl(p,actor_uuid,ACL_SEARCH,0,ACL_SEARCH,1);}
    else if(!strcmp(profile,"parent-deny-allow-search"))install_acl(p,actor_uuid,ACL_SEARCH,1,ACL_SEARCH,0);
    else if(!strcmp(profile,"parent-generic-execute")){must(fchmod(p,0),"mode");install_acl(p,actor_uuid,KAUTH_ACE_GENERIC_EXECUTE,0,0,0);}
    else if(!strcmp(profile,"parent-deny-add"))install_acl(p,actor_uuid,ACL_ADD_FILE,1,0,0);
    else if(!strcmp(profile,"parent-allow-add")){must(fchmod(p,0500),"mode");install_acl(p,actor_uuid,ACL_ADD_FILE,0,0,0);}
    else if(!strcmp(profile,"parent-deny-delete"))install_acl(p,actor_uuid,ACL_DELETE_CHILD,1,0,0);
    else if(!strcmp(profile,"destination-deny-search"))install_acl(handles[DEST_PARENT],actor_uuid,ACL_SEARCH,1,0,0);
    else if(!strcmp(profile,"destination-deny-add"))install_acl(handles[DEST_PARENT],actor_uuid,ACL_ADD_FILE,1,0,0);
    else if(!strcmp(profile,"destination-deny-delete"))install_acl(handles[DEST_LEAF],actor_uuid,ACL_DELETE,1,0,0);
    else if(!strcmp(profile,"destination-no-write"))return fchmod(handles[DEST_PARENT],0500);
    else if(!strcmp(profile,"destination-immutable"))return fchflags(handles[DEST_LEAF],UF_IMMUTABLE);
    else if(!strcmp(profile,"leaf-deny-delete"))install_acl(f,actor_uuid,ACL_DELETE,1,0,0);
    else if(!strcmp(profile,"leaf-allow-parent-deny")){install_acl(f,actor_uuid,ACL_DELETE,0,0,0);install_acl(p,actor_uuid,ACL_DELETE_CHILD,1,0,0);}
    else if(!strcmp(profile,"leaf-deny-parent-allow")){install_acl(f,actor_uuid,ACL_DELETE,1,0,0);install_acl(p,actor_uuid,ACL_DELETE_CHILD,0,0,0);}
    else if(!strcmp(profile,"stage-deny-delete"))install_acl(handles[STAGE],actor_uuid,ACL_DELETE,1,0,0);
    else if(!strcmp(profile,"stage-immutable"))return fchflags(handles[STAGE],UF_IMMUTABLE);
    else if(!strcmp(profile,"parent-immutable"))return fchflags(p,UF_IMMUTABLE);
    else if(!strcmp(profile,"parent-append"))return fchflags(p,UF_APPEND);
    else if(!strcmp(profile,"leaf-immutable"))return fchflags(f,UF_IMMUTABLE);
    else if(!strcmp(profile,"leaf-append"))return fchflags(f,UF_APPEND);
    else if(!strcmp(profile,"sticky-owner"))return fchmod(p,01777);
    else if(!strcmp(profile,"group-search-allow")){must(fchown(p,0,actor_gid),"group owner");return fchmod(p,0070);}
    else if(!strcmp(profile,"group-search-deny")){must(fchown(p,0,actor_gid),"group owner");return fchmod(p,0060);}
    else if(!strcmp(profile,"other-search-allow")){must(fchown(p,0,0),"other owner");return fchmod(p,0007);}
    else if(!strcmp(profile,"other-search-deny")){must(fchown(p,0,0),"other owner");return fchmod(p,0006);}
    else if(!strcmp(profile,"sticky-neither")){must(fchown(p,0,0)||fchown(f,0,0),"sticky ownership");return fchmod(p,01777);}
    else if(!strcmp(profile,"sticky-parent-owner")){must(fchown(f,0,0),"sticky leaf ownership");return fchmod(p,01777);}
    else if(!strcmp(profile,"parent-group-deny-search"))install_acl(p,group_uuid,ACL_SEARCH,1,0,0);
    else if(!strcmp(profile,"parent-group-allow-search")){must(fchmod(p,0),"mode");install_acl(p,group_uuid,ACL_SEARCH,0,0,0);}
    else return EINVAL;
    return 0;
}
int main(int argc,char **argv) {
    if(argc>1&&!strcmp(argv[1],"--mounted"))return mounted(argc,argv);
    if(argc>1&&(!strcmp(argv[1],"--under")||!strcmp(argv[1],"--prepare"))){if(argc!=8)return 2;prepare_only=!strcmp(argv[1],"--prepare");base_directory=argv[2];argc-=2;argv+=2;}
    if(argc!=6){fprintf(stderr,"usage: probe [--under|--prepare ROOT] PROFILE OPERATION ROUTE ACTOR_UID ACTOR_GID\n");return 2;}
    const char *profile=argv[1],*operation=argv[2],*route=argv[3];actor_uid=(uid_t)strtoul(argv[4],NULL,10);actor_gid=(gid_t)strtoul(argv[5],NULL,10);privileged=geteuid()==0;
    int needs_root=!strncmp(profile,"group-search-",13)||!strncmp(profile,"other-search-",13)||!strcmp(profile,"sticky-neither")||!strcmp(profile,"sticky-parent-owner");
    if(actor_uid==0){fprintf(stderr,"actor must not be root\n");return 2;}
    if((!privileged&&(actor_uid!=geteuid()||actor_gid!=getegid()))||(needs_root&&!privileged)){printf("{\"profile\":\"%s\",\"operation\":\"%s\",\"route\":\"%s\",\"qualification\":\"unavailable\",\"reason\":\"requires privileged fixture ownership and non-root actor\"}\n",profile,operation,route);return 0;}
    must(mbr_uid_to_uuid(actor_uid,actor_uuid),"actor identity");must(mbr_gid_to_uuid(actor_gid,group_uuid),"group identity");
    must(snprintf(fixture,sizeof(fixture),"%s/apfs-path-auth-XXXXXX",base_directory)>=(int)sizeof(fixture),"fixture path");must(!mkdtemp(fixture),"mkdtemp");must(atexit(emergency_cleanup),"atexit");handles[ROOT]=open(fixture,O_RDONLY|O_DIRECTORY);must(handles[ROOT]<0,"root");
    must(mkdirat(handles[ROOT],"a",0700),"mkdir a");handles[MIDDLE]=openat(handles[ROOT],"a",O_RDONLY|O_DIRECTORY);must(handles[MIDDLE]<0,"middle");
    must(mkdirat(handles[MIDDLE],"b",0700),"mkdir b");handles[PARENT]=openat(handles[MIDDLE],"b",O_RDONLY|O_DIRECTORY);must(handles[PARENT]<0,"parent");
    must(mkdirat(handles[MIDDLE],"c",0700),"mkdir c");handles[DEST_PARENT]=openat(handles[MIDDLE],"c",O_RDONLY|O_DIRECTORY);must(handles[DEST_PARENT]<0,"destination parent");
    handles[LEAF]=openat(handles[PARENT],"file",O_CREAT|O_EXCL|O_RDWR,0600);handles[STAGE]=openat(handles[PARENT],"stage",O_CREAT|O_EXCL|O_RDWR,0600);must(handles[LEAF]<0||handles[STAGE]<0,"files");
    must(write(handles[LEAF],"original",8)!=8||write(handles[STAGE],"replacement",11)!=11,"file contents");
    handles[DEST_LEAF]=openat(handles[DEST_PARENT],"file",O_CREAT|O_EXCL|O_RDWR,0600);must(handles[DEST_LEAF]<0||write(handles[DEST_LEAF],"destination",11)!=11,"destination file");
    for(int i=0;i<COUNT;i++){clear_acl(handles[i]);if(privileged)must(fchown(handles[i],actor_uid,actor_gid),"initial ownership");}
    int n=snprintf(absolute,sizeof(absolute),"%s/a/b/file",fixture);must(n<0||(size_t)n>=sizeof(absolute),"path");
    struct result control=perform("open",route);must(control.setup_errno||control.error||control.close_errno,"positive open control");
    int group_member=0;int membership_error=mbr_check_membership(actor_uuid,group_uuid,&group_member);
    printf("{\"profile\":\"%s\",\"operation\":\"%s\",\"route\":\"%s\",\"qualification\":\"captured\",\"privileged_setup\":%s,\"user_uuid\":",profile,operation,route,privileged?"true":"false");hex(actor_uuid,16);printf(",\"group_uuid\":");hex(group_uuid,16);printf(",\"group_membership_errno\":%d,\"group_member\":%d,\"positive_open_control\":",membership_error,group_member);emit_result(control);
    errno=0;int restriction=restrict_fixture(profile),restriction_error=restriction?(errno?errno:restriction):0;must(restriction_error,"restrictions");
    if(prepare_only){printf(",\"fixture\":\"%s\",\"before\":",fixture);snapshots();for(int i=0;i<COUNT;i++){must(close(handles[i]),"prepared close");handles[i]=-1;}cleanup_done=1;printf(",\"prepared\":true,\"handles_closed\":true}\n");return 0;}
    printf(",\"before\":");snapshots();printf(",\"namespace_before\":");namespace_state();struct result result=perform(operation,route);printf(",\"result\":");emit_result(result);printf(",\"after\":");snapshots();printf(",\"namespace_after\":");namespace_state();
    printf(",\"cleanup\":[");for(int i=0;i<COUNT;i++){errno=0;int rc=fchflags(handles[i],0),e=rc?errno:0;printf("%s{\"record\":\"%s\",\"clear_flags_errno\":%d",i?",":"",names[i],e);must(e,"cleanup flags");clear_acl(handles[i]);must(fchmod(handles[i],regular(i)?0600:0700),"cleanup mode");printf(",\"acl_and_mode_restored\":true}");}printf("]");
    const char *files[]={"file","stage","new"};for(int i=0;i<3;i++)if(unlinkat(handles[PARENT],files[i],0)&&errno!=ENOENT)must(1,"cleanup unlink");
    must(unlinkat(handles[DEST_PARENT],"file",0),"cleanup destination");
    for(int i=COUNT-1;i>=0;i--){must(close(handles[i]),"close");handles[i]=-1;}char b[PATH_MAX],a[PATH_MAX],c[PATH_MAX];snprintf(b,sizeof(b),"%s/a/b",fixture);snprintf(a,sizeof(a),"%s/a",fixture);snprintf(c,sizeof(c),"%s/a/c",fixture);must(rmdir(b)||rmdir(c)||rmdir(a)||rmdir(fixture),"cleanup dirs");cleanup_done=1;printf(",\"cleanup_complete\":true}\n");return 0;
}
