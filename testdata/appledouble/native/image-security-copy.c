// Destination statfs above verifies MNT_NOSUID; the shared oracle replays that\n// captured bit for descriptor 12. Source metadata is supplied, not opened.\n// Test-only ordinary copyfile_security applied to held image destinations.
#include <sys/attr.h>
#define main security_copy_reference_main
#include "security-copy.c"
#undef main
extern ssize_t acl_copy_ext_native(void *,acl_t,ssize_t);
static const char *observation_path;
static void image_snapshot(int fd,struct stat *st) {
 filesec_t sec=filesec_init();if(!sec)fail("filesec init");
 if(fd<0?lstatx_np(observation_path,st,sec):fstatx_np(fd,st,sec))fail("destination stat");
 acl_t acl=NULL;errno=0;if(filesec_get_property(sec,FILESEC_ACL,&acl)){if(errno!=ENOENT)fail("read ACL");acl=(acl_t)_FILESEC_REMOVE_ACL;}
 ssize_t n=acl_size(acl);if(n<44)fail("ACL size");struct kauth_filesec *record=calloc((size_t)n,1);if(!record)fail("allocate ACL");
 if(acl_copy_ext_native(record,acl,n)!=n)fail("export ACL");
 if(filesec_get_property(sec,FILESEC_UUID,&record->fsec_owner)&&errno!=ENOENT)fail("owner UUID");
 if(filesec_get_property(sec,FILESEC_GRPUUID,&record->fsec_group)&&errno!=ENOENT)fail("group UUID");
 printf("{\"Security\":");hex(record,(size_t)n);printf(",\"UID\":%u,\"GID\":%u,\"Mode\":%u,\"Flags\":%u}",st->st_uid,st->st_gid,st->st_mode,st->st_flags);
 if(acl!=(acl_t)_FILESEC_REMOVE_ACL)acl_free(acl);free(record);filesec_free(sec);
}
static void attributes(int fd){struct attrlist request={.bitmapcount=ATTR_BIT_MAP_COUNT,.commonattr=0x01c38000};unsigned char data[56+44+128*24]={0};int rc=fd<0?getattrlist(observation_path,&request,data,sizeof(data),FSOPT_NOFOLLOW):fgetattrlist(fd,&request,data,sizeof(data),0);if(rc)fail("attributes");uint32_t size;memcpy(&size,data,4);if(size<56||size>sizeof(data))fail("attribute extent");hex(data,size);}
int main(int argc,char **argv){
 if(argc!=6)return 2;int apply=!strcmp(argv[1],"apply");if(!apply&&strcmp(argv[1],"observe"))return 2;observation_path=argv[2];
 struct statfs filesystem;if(statfs(argv[5],&filesystem)||strcmp(filesystem.f_fstypename,argv[4])||(filesystem.f_flags&MNT_IGNORE_OWNERSHIP)||!(filesystem.f_flags&MNT_NOSUID)||(apply&&(filesystem.f_flags&MNT_RDONLY)))fail("filesystem identity/ownership/set-ID");
 int fd=-1,temporary=0;struct stat original;
 if(apply){if(lstat(argv[2],&original))fail("setup stat");temporary=!(original.st_mode&S_IRUSR);if(temporary&&lchmod(argv[2],(original.st_mode&07777)|S_IRUSR))fail("descriptor setup");fd=open(argv[2],O_EVTONLY|O_SYMLINK);if(fd<0)fail("open");if(fd!=12){if(dup2(fd,12)<0||close(fd))fail("held descriptor slot");fd=12;}if(temporary&&fchmod(fd,original.st_mode&07777))fail("exact mode");}
 struct stat before,after;printf("{\"Before\":");image_snapshot(fd,&before);printf(",\"BeforeAttributes\":");attributes(fd);
 if(apply&&(before.st_ino!=original.st_ino||before.st_dev!=original.st_dev||before.st_mode!=original.st_mode))fail("setup changed baseline");
 struct _copyfile_state state={.src_fd=11,.dst_fd=fd,.fsec=filesec_init(),.src="captured",.dst=argv[2]};if(!state.fsec)fail("source cache");
 if(apply){
  unsigned uid,gid,statmode,mask,propmode,options;char owner[33],group[33],raw[6233];FILE *f=fopen(argv[3],"rb");if(!f)fail("packet open");if(fscanf(f,"%u %u %u %u %u %u %32s %32s %6232s",&uid,&gid,&statmode,&mask,&propmode,&options,owner,group,raw)!=9||fclose(f))fail("packet");
  state.sb.st_uid=uid;state.sb.st_gid=gid;state.sb.st_mode=(mode_t)statmode;
  if(options&1)state.flags|=COPYFILE_ACL;if(options&2)state.flags|=COPYFILE_STAT;if(options&4)state.internal_flags|=cfForbidCopySuidBits;if(options&8)state.internal_flags|=cfAlwaysCopySuidBits;
  if(strcmp(raw,"-")){size_t n;void *b=unhex(raw,&n);if(n<44)fail("raw input");if(filesec_set_property(state.fsec,FILESEC_ACL_ALLOCSIZE,&n)||filesec_set_property(state.fsec,FILESEC_ACL_RAW,&b))fail("raw properties");}
  mode_t m=(mode_t)propmode;if((mask&1)&&filesec_set_property(state.fsec,FILESEC_OWNER,&uid))fail("UID");if((mask&2)&&filesec_set_property(state.fsec,FILESEC_GROUP,&gid))fail("GID");if((mask&4)&&filesec_set_property(state.fsec,FILESEC_MODE,&m))fail("mode");
  if(strcmp(owner,"-")){size_t n;void *b=unhex(owner,&n);if(n!=16||filesec_set_property(state.fsec,FILESEC_UUID,b))fail("owner");free(b);}if(strcmp(group,"-")){size_t n;void *b=unhex(group,&n);if(n!=16||filesec_set_property(state.fsec,FILESEC_GRPUUID,b))fail("group");free(b);}
 }
 printf(",\"Events\":[");live=1;filter=4;errno=0;int code=apply?copyfile_security(&state):0,error=code?errno:0;
 printf("],\"Cache\":");print_properties(state.fsec);printf(",\"TemporaryReadSetup\":%s,\"Code\":%d,\"Errno\":%d,\"After\":",temporary?"true":"false",code,error);image_snapshot(fd,&after);printf(",\"AfterAttributes\":");attributes(fd);
 printf(",\"Inode\":%llu,\"SameIdentity\":%s}\n",(unsigned long long)after.st_ino,before.st_dev==after.st_dev&&before.st_ino==after.st_ino?"true":"false");filesec_free(state.fsec);if(fd>=0&&close(fd))fail("close");return 0;
}
