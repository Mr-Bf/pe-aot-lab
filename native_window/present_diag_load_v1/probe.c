/* Load the real three-library closure and inspect the shared registry only.
 * No D3D/Metal device, CommandQueue, WSI, guest or render entry is called.
 * Library initializers and process-exit destructors can still execute.
 */
#include "dxmt_present_diagnostics_v1.h"
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

_Static_assert(sizeof(DXMTPresentDiagConfigV1)==8,"config layout");
_Static_assert(sizeof(DXMTPresentDiagSnapshotV1)==45152,"snapshot layout");
typedef uint32_t (*Configure)(const DXMTPresentDiagConfigV1 *);
typedef uint32_t (*Read)(DXMTPresentDiagSnapshotV1 *,uint32_t);
static unsigned checks;
static void string(const char *s) {
  putchar('"');
  for(const unsigned char *p=(const unsigned char *)s;*p;p++) {
    if(*p=='"'||*p=='\\'){putchar('\\');putchar(*p);}
    else if(*p<32)printf("\\u%04x",*p);
    else putchar(*p);
  }
  putchar('"');
}
static void need(int ok,const char *what) {
  checks++;
  if(ok)return;
  printf("{\"event\":\"failure\",\"check\":");string(what);
  printf(",\"checks\":%u}\n",checks);fflush(stdout);exit(1);
}
static int same_path(const char *a,const char *b) {
  char aa[PATH_MAX],bb[PATH_MAX];
  return realpath(a,aa)&&realpath(b,bb)&&strcmp(aa,bb)==0;
}
static int system_path(const char *s) {
  return strncmp(s,"/usr/lib/",9)==0 || strncmp(s,"/System/Library/",16)==0;
}
static void snapshot(Read read,uint32_t configured,const char *name) {
  DXMTPresentDiagSnapshotV1 got,want={0};
  memset(&got,0xa5,sizeof(got));
  uint32_t result=read(&got,sizeof(got));
  want.version=DXMT_PRESENT_DIAG_VERSION_V1;want.size=sizeof(want);
  want.configured=configured;
  need(result==DXMT_PD_NOT_READY,"empty registry status");
  need(memcmp(&got,&want,sizeof(got))==0,"entire empty snapshot bytes");
  printf("{\"event\":\"snapshot\",\"name\":");string(name);
  printf(",\"returncode\":%u,\"configured\":%u,\"bytes_compared\":%zu,\"queues_seen\":0,\"queues_live\":0,\"queues_closed\":0}\n",result,configured,sizeof(got));
}
int main(int argc,char **argv) {
  need(argc==9,"three absolute libraries and five symbol names required");
  int translated=-1;size_t size=sizeof(translated);errno=0;
  int rc=sysctlbyname("sysctl.proc_translated",&translated,&size,NULL,0);
  int error=rc==0?0:errno;
  printf("{\"event\":\"native_identity\",\"returncode\":%d,\"errno\":%d,\"value\":%d,\"size\":%zu}\n",rc,error,translated,size);
#if defined(__arm64__) || defined(__aarch64__)
  need((rc==0 && size==sizeof(int) && translated==0)||(rc==-1 && error==ENOENT),"native ARM64 identity");
#else
  need(0,"ARM64 compile identity");
#endif
  void *handles[3],*symbols[3][5];
  for(unsigned i=0;i<3;i++) {
    need(argv[1+i][0]=='/',"absolute library path");
    handles[i]=dlopen(argv[1+i],RTLD_NOW|RTLD_LOCAL);
    if(!handles[i]){const char *e=dlerror();fprintf(stderr,"dlopen: %s\n",e?e:"unknown");}
    need(handles[i]!=NULL,"real library loaded");
    printf("{\"event\":\"loaded\",\"index\":%u,\"path\":",i);string(argv[1+i]);puts("}");
  }
  need(strcmp(argv[4],"DXMTPresentDiagConfigureV1")==0 && strcmp(argv[5],"DXMTPresentDiagReadV1")==0,"public symbol order");
  for(unsigned i=0;i<3;i++)for(unsigned j=0;j<5;j++) {
    dlerror();symbols[i][j]=dlsym(handles[i],argv[4+j]);const char *error_text=dlerror();
    need(!error_text && symbols[i][j],"symbol resolution");
    Dl_info info={0};
    need(dladdr(symbols[i][j],&info)!=0 && info.dli_fname,"symbol owning image");
    need(same_path(info.dli_fname,argv[3]),"symbol belongs to exact new winemetal");
    need(i==0 || symbols[i][j]==symbols[0][j],"one provider address across handles");
    printf("{\"event\":\"symbol\",\"handle\":%u,\"symbol\":",i);string(argv[4+j]);
    printf(",\"address\":\"%p\",\"owner\":",symbols[i][j]);string(info.dli_fname);puts("}");
  }
  Read read0=(Read)symbols[0][1],read1=(Read)symbols[1][1],read2=(Read)symbols[2][1];
  Configure configure0=(Configure)symbols[0][0],configure2=(Configure)symbols[2][0];
  snapshot(read0,0,"before");
  DXMTPresentDiagConfigV1 config={DXMT_PRESENT_DIAG_VERSION_V1,sizeof(config)};
  uint32_t configured=configure2(&config);
  need(configured==DXMT_PD_OK,"configure via provider handle");
  printf("{\"event\":\"configure\",\"handle\":2,\"returncode\":%u}\n",configured);
  snapshot(read1,1,"after-other-handle");
  uint32_t again=configure0(&config);
  need(again==DXMT_PD_ALREADY_STARTED,"second configure through d3d11 rejects");
  printf("{\"event\":\"configure\",\"handle\":0,\"returncode\":%u}\n",again);
  snapshot(read2,1,"after-rejection");
  unsigned seen[4]={0};uint32_t count=_dyld_image_count();
  for(uint32_t i=0;i<count;i++) {
    const char *name=_dyld_get_image_name(i);need(name!=NULL,"loaded image name");
    if(system_path(name))continue;
    int match=-1;
    for(unsigned j=0;j<4;j++)if(same_path(name,argv[j])){need(match==-1,"unique loaded image identity");match=(int)j;}
    need(match>=0,"no unexpected non-system image");seen[match]++;
    printf("{\"event\":\"non_system_image\",\"index\":%d,\"path\":",match);string(name);puts("}");
  }
  for(unsigned i=0;i<4;i++)need(seen[i]==1,"each exact non-system image loaded once");
  printf("{\"event\":\"result\",\"status\":\"PASS_SHARED_PROVIDER_LOAD_ONLY\",\"checks\":%u,\"loaded_images_total\":%u,\"library_handles\":3,\"symbol_lookups\":15,\"snapshot_checks\":3,\"configure_calls\":2,\"non_system_images\":4,\"explicit_device_queue_render_guest_calls\":0}\n",checks,count);
  need(fflush(stdout)==0,"flush output");
  return 0;
}
