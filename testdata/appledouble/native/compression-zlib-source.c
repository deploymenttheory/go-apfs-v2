#include "zlib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv){
 if(argc!=3)return 2;
 FILE *f=fopen(argv[1],"rb");if(!f)return 2;
 unsigned char src[65537],out[131072];size_t n=fread(src,1,sizeof(src),f);
 if(ferror(f)||n>65536||fclose(f))return 2;
 z_stream s;memset(&s,0,sizeof(s));
 if(deflateInit2(&s,5,Z_DEFLATED,-15,8,Z_DEFAULT_STRATEGY)!=Z_OK)return 3;
 s.next_in=src;s.avail_in=(uInt)n;s.next_out=out;s.avail_out=sizeof(out);
 if(deflate(&s,Z_FINISH)!=Z_STREAM_END)return 4;
 size_t count=s.total_out;if(deflateEnd(&s)!=Z_OK)return 5;
 f=fopen(argv[2],"wb");if(!f)return 6;
 if(fwrite(out,1,count,f)!=count||fclose(f))return 7;
 return 0;
}
