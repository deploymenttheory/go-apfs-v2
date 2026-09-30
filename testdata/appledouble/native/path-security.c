// Qualification only. path-security-source.h retains complete unchanged Apple
// functions with their original copyright. Wrappers inject explicit provider
// failures; ordinary cases use the installed SDK/filesec/ACL implementation.
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <copyfile.h>
#include <membership.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

struct _copyfile_state { int src_fd,dst_fd; unsigned internal_flags; copyfile_flags_t flags; };
enum { cfDelayAce=1 };
static int fault, active, event_count;
static bool fail(const char *name,int number){
 if(!active)return false;
 if(event_count++)putchar(',');
 printf("\"%s\"",name);
 if(fault==number){errno=number==3?ENOTSUP:EIO;return true;}
 return false;
}
static filesec_t observed_init(void){if(fail("filesec-init",1))return NULL;return filesec_init();}
static filesec_t observed_dup(filesec_t p){if(fail("filesec-dup",8))return NULL;return filesec_dup(p);}
static int observed_statx(int fd,struct stat *st,filesec_t p){
 if(fault==3&&active){(void)fail("statx",3);return -1;}
 if(fail("statx",2))return -1;return fstatx_np(fd,st,p);
}
static int observed_delete(acl_t a,acl_entry_t e){if(fail("acl-delete",4))return -1;return acl_delete_entry(a,e);}
static int observed_property(filesec_t p,filesec_property_t prop,const void *value){
 int number=prop==FILESEC_ACL?5:prop==FILESEC_MODE?6:0;
 if(fail(prop==FILESEC_ACL?"set-acl":prop==FILESEC_MODE?"set-mode":"set-property",number))return -1;
 return filesec_set_property(p,prop,value);
}
static int observed_chmodx(int fd,filesec_t p){if(fail("chmodx",7))return -1;return fchmodx_np(fd,p);}
static int observed_chmod(int fd,mode_t mode){if(fail("chmod",10))return -1;return fchmod(fd,mode);}
static int observed_create(acl_t *a,acl_entry_t *e,int i){if(fail("acl-create",9))return -1;return acl_create_entry_np(a,e,i);}
#define filesec_init observed_init
#define filesec_dup observed_dup
#define fstatx_np observed_statx
#define acl_delete_entry observed_delete
#define filesec_set_property observed_property
#define fchmodx_np observed_chmodx
#define fchmod observed_chmod
#define acl_create_entry_np observed_create
#define copyfile_warn(...) ((void)0)
#include "path-security-source.h"
#undef filesec_init
#undef filesec_dup
#undef fstatx_np
#undef acl_delete_entry
#undef filesec_set_property
#undef fchmodx_np
#undef fchmod
#undef acl_create_entry_np

static const acl_perm_t rights[]={ACL_READ_DATA,ACL_WRITE_DATA,ACL_APPEND_DATA,ACL_WRITE_ATTRIBUTES,ACL_WRITE_EXTATTRIBUTES,ACL_WRITE_SECURITY,ACL_SYNCHRONIZE};
static const acl_flag_t entry_flags[]={ACL_ENTRY_INHERITED,ACL_ENTRY_FILE_INHERIT,ACL_ENTRY_DIRECTORY_INHERIT,ACL_ENTRY_LIMIT_INHERIT,ACL_ENTRY_ONLY_INHERIT};

static int set_entries(filesec_t fs,int count,int first,int flags){
 if(count<0)return 0;
 acl_t a=acl_init(count);if(!a)return -1;
 for(int i=0;i<count;i++){
  acl_entry_t e;acl_permset_t perms;acl_flagset_t bits;uuid_t uuid={1};
  if(i==0&&first!=0&&mbr_uid_to_uuid(getuid(),uuid)!=0)return -1;
  if(acl_create_entry(&a,&e)||acl_set_tag_type(e,first==2&&i==0?ACL_EXTENDED_DENY:ACL_EXTENDED_ALLOW)||acl_set_qualifier(e,uuid)||acl_get_permset(e,&perms))return -1;
  for(unsigned j=0;j<sizeof(rights)/sizeof(rights[0]);j++)if((first!=0&&i==0)?j>0:j==0)if(acl_add_perm(perms,rights[j]))return -1;
  if(i==0&&first==3&&acl_add_perm(perms,ACL_READ_DATA))return -1;
  if(acl_set_permset(e,perms)||acl_get_flagset_np(e,&bits))return -1;
  for(unsigned j=0;j<sizeof(entry_flags)/sizeof(entry_flags[0]);j++)if(flags&(1<<j))if(acl_add_flag_np(bits,entry_flags[j]))return -1;
  if(acl_set_flagset_np(e,bits))return -1;
 }
 int result=filesec_set_property(fs,FILESEC_ACL,&a);acl_free(a);return result;
}

static void describe(filesec_t fs){
 mode_t mode=0;acl_t a=NULL;int count=-1;unsigned mask=0,flags=0;int matches=0,tag=0;
 int has_mode=filesec_get_property(fs,FILESEC_MODE,&mode)==0;
 if(filesec_get_property(fs,FILESEC_ACL,&a)==0){
  count=0;acl_entry_t e;int next=ACL_FIRST_ENTRY;
  while(acl_get_entry(a,next,&e)==0){
   if(count==0){
    acl_permset_t p;acl_flagset_t f;acl_tag_t t;uuid_t current;
    acl_get_permset(e,&p);acl_get_flagset_np(e,&f);acl_get_tag_type(e,&t);tag=t==ACL_EXTENDED_ALLOW?1:t==ACL_EXTENDED_DENY?2:0;
    for(unsigned j=0;j<sizeof(rights)/sizeof(rights[0]);j++)if(acl_get_perm_np(p,rights[j]))mask|=(unsigned)rights[j];
    for(unsigned j=0;j<sizeof(entry_flags)/sizeof(entry_flags[0]);j++)if(acl_get_flag_np(f,entry_flags[j]))flags|=(unsigned)entry_flags[j];
    void *q=acl_get_qualifier(e);if(q&&mbr_uid_to_uuid(getuid(),current)==0)matches=memcmp(q,current,sizeof(current))==0;if(q)acl_free(q);
   }
   count++;next=ACL_NEXT_ENTRY;
  }
  acl_free(a);
 }
 printf("{\"ModePresent\":%s,\"Mode\":%u,\"ACLCount\":%d,\"FirstRights\":%u,\"FirstFlags\":%u,\"FirstTag\":%d,\"FirstMatchesRealUID\":%s}",has_mode?"true":"false",(unsigned)mode,count,mask,flags,tag,matches?"true":"false");
}

int main(void){
 int operation,count,first,flags,has_mode;
 while(scanf("%d %d %d %d %d %d",&operation,&count,&first,&flags,&has_mode,&fault)==6){
  active=0;event_count=0;
  filesec_t initial=filesec_init();mode_t mode=0400;if(!initial||set_entries(initial,count,first,flags))return 2;
  if(has_mode&&filesec_set_property(initial,FILESEC_MODE,&mode))return 3;
  FILE *file=NULL;int fd=-1;
  if(operation==1){file=tmpfile();if(!file)return 4;fd=fileno(file);if(fchmodx_np(fd,initial))return 5;}
  printf("{\"Before\":");describe(initial);printf(",\"Events\":[");
  active=1;errno=0;filesec_t after=NULL;int code=0;
  if(operation==0){after=copyfile_fix_perms(NULL,&initial);if(!after)code=-1;}
  else if(operation==1){struct stat desired={.st_mode=S_IFREG|0440};remove_uberace(fd,&desired);}
  else if(operation==2){struct _copyfile_state state={.src_fd=fd,.dst_fd=-1};reset_security(&state);}
  int error=errno;active=0;
  if(operation==1){after=filesec_init();struct stat st;if(fstatx_np(fd,&st,after))return 6;}
  printf("],\"Code\":%d,\"Errno\":%d,\"RealEqualsEffectiveUID\":%s,\"After\":",code,error,getuid()==geteuid()?"true":"false");
  if(after)describe(after);else printf("null");puts("}");
  if(after)filesec_free(after);filesec_free(initial);if(file)fclose(file);
 }
 return ferror(stdin)?7:0;
}
