// Test-only native image capture plus document-ID verification on tracked inodes.
#include "image-security-base.h"
#include <sys/attr.h>
#include "image-document-source.h"
int main(int argc,char **argv){
 uint32_t reference[8]={0};reference[4]=0x12345678;
 if(hfs_get_document_id_internal((const uint8_t*)reference,S_IFREG)!=0x12345678 || hfs_get_document_id_internal((const uint8_t*)reference,S_IFDIR)!=0x12345678 || hfs_get_document_id_internal((const uint8_t*)reference,S_IFLNK)!=0)fail("HFS document reference");
 if(argc==3&&!strcmp(argv[1],"--document-id")){
  struct attrlist a={.bitmapcount=ATTR_BIT_MAP_COUNT,.commonattr=ATTR_CMN_DOCUMENT_ID};
  struct {uint32_t length,id;} value={0,0};
  if(getattrlist(argv[2],&a,&value,sizeof(value),FSOPT_NOFOLLOW|FSOPT_ATTR_CMN_EXTENDED)||value.length!=sizeof(value))fail("document ID capture");
  printf("%u\n",value.id);return 0;
 }
 return image_security_main(argc,argv);
}
