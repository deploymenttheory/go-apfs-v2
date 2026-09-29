// Test-only image-policy oracle: complete unchanged Apple functions, with
// controlled success responses. Native mounted-image readback is independent.
#define main stat_copy_main
#include "stat-copy.c"
#undef main
int main(int argc,char **argv) {
 if(argc!=4)return 2;
 uint32_t sf=(uint32_t)strtoul(argv[1],NULL,0),tf=(uint32_t)strtoul(argv[2],NULL,0);
 unsigned options=(unsigned)strtoul(argv[3],NULL,0);
 source_fd=11;target_fd=12;current_flags=tf;
 struct _copyfile_state state={.src_fd=11,.dst_fd=12,.sb={.st_uid=501,.st_gid=20,.st_mode=0106755,.st_flags=sf,.st_mtimespec={1600000000,987654321},.st_atimespec={1500000000,456789123}},.flags=COPYFILE_STAT};
 if(options&1)state.internal_flags|=cfAlwaysCopySuidBits;
 if(options&2)state.internal_flags|=cfForbidCopySuidBits;
 if(options&4)state.internal_flags|=cfMakeFileInvisible;
 if(options&8)state.flags|=COPYFILE_PRESERVE_DST_TRACKED;
 printf("{\"Source\":{\"UID\":501,\"GID\":20,\"Mode\":%u,\"Flags\":%u,\"Times\":[1600000000,987654321,1500000000,456789123]},\"Events\":[",state.sb.st_mode,sf);
 int rc=copyfile_stat(&state),e=rc?errno:0;
 printf("],\"Code\":%d,\"Errno\":%d}\n",rc,e);return 0;
}
