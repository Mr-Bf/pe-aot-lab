/* Pure callback protocol checks. Fake tokens here are intentionally not GPU or
 * Cocoa evidence; native window/Present is validated by the separate probe. */
#include "native_wsi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern uintptr_t DXMTNativeCreateMetalViewV1(uint64_t,uintptr_t,uintptr_t*);
extern void DXMTNativeReleaseMetalViewV1(uintptr_t);
static unsigned checks,queries,resizes,creates,releases,alive=1,invalid_flags,missing_layer;
static uintptr_t next_token=0x10000,returned;
#define C(x) do{checks++;if(!(x)){fprintf(stderr,"check line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static int query(void *user,uint64_t handle,DXMTNativeWindowInfoV1 *out){C(user==&alive);queries++;if(handle!=42||!alive)return 0;out->width_pixels=640;out->height_pixels=360;out->flags=invalid_flags?8:DXMT_WSI_VISIBLE;return 1;}
static int resize(void *user,uint64_t handle,uint32_t w,uint32_t h){C(user==&alive&&handle==42&&w==800&&h==450);resizes++;return 1;}
static uintptr_t create(void *user,uint64_t handle,uintptr_t device,uintptr_t *layer){C(user==&alive&&handle==42&&device==123);creates++;DXMTNativeWindowInfoV1 info={sizeof info,0,0,0};C(DXMTNativeQueryWindowV1(handle,&info));*layer=missing_layer?0:456;returned=++next_token;return returned;}
static void release(void *user,uintptr_t token){C(user==&alive&&token==returned);releases++;DXMTNativeWindowInfoV1 info={sizeof info,0,0,0};C(DXMTNativeQueryWindowV1(42,&info));}
int main(void){
 DXMTNativeWindowInfoV1 info={sizeof info,9,9,9};C(!DXMTNativeQueryWindowV1(42,&info));C(info.width_pixels==0&&info.height_pixels==0&&info.flags==0);
 DXMTNativeWSIV1 table={1,sizeof table,&alive,query,resize,create,release};C(!DXMTNativeInstallWSIV1(NULL));
 DXMTNativeWSIV1 bad=table;bad.version=2;C(!DXMTNativeInstallWSIV1(&bad));bad=table;bad.size--;C(!DXMTNativeInstallWSIV1(&bad));bad=table;bad.query=NULL;C(!DXMTNativeInstallWSIV1(&bad));
 C(DXMTNativeInstallWSIV1(&table));C(!DXMTNativeInstallWSIV1(&table));C(DXMTNativeQueryWindowV1(42,&info));C(info.width_pixels==640&&info.height_pixels==360&&info.flags==1);
 C(!DXMTNativeQueryWindowV1(99,&info));invalid_flags=1;C(!DXMTNativeQueryWindowV1(42,&info));C(!info.width_pixels&&!info.flags);invalid_flags=0;
 C(!DXMTNativeResizeWindowV1(42,0,450));C(!DXMTNativeResizeWindowV1(42,800,16385));C(DXMTNativeResizeWindowV1(42,800,450)&&resizes==1);
 uintptr_t layer=99;C(!DXMTNativeCreateMetalViewV1(99,123,&layer)&&layer==0);C(!DXMTNativeCreateMetalViewV1(42,0,&layer));C(!creates);
 missing_layer=1;C(!DXMTNativeCreateMetalViewV1(42,123,&layer)&&!layer);C(creates==1&&releases==1);missing_layer=0;
 uintptr_t token=DXMTNativeCreateMetalViewV1(42,123,&layer);C(token&&layer==456);C(!DXMTNativeCreateMetalViewV1(42,123,&layer)&&!layer&&creates==2);
 DXMTNativeReleaseMetalViewV1(token+1);C(releases==1);DXMTNativeReleaseMetalViewV1(token);C(releases==2);DXMTNativeReleaseMetalViewV1(token);C(releases==2);
 uintptr_t second=DXMTNativeCreateMetalViewV1(42,123,&layer);C(second>token&&layer==456);DXMTNativeReleaseMetalViewV1(second);C(releases==3);
 alive=0;C(!DXMTNativeQueryWindowV1(42,&info));C(!DXMTNativeCreateMetalViewV1(42,123,&layer)&&!layer);C(!DXMTNativeResizeWindowV1(42,800,450));
 printf("{\"status\":\"PASS\",\"checks\":%u,\"query_callbacks\":%u,\"create_callbacks\":%u,\"release_callbacks\":%u,\"gpu_calls\":0,\"cocoa_calls\":0}\n",checks,queries,creates,releases);return 0;
}
