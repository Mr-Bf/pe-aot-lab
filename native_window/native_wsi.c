/* Project native-window ABI v1. This file is added only to the independent
 * native DXMT build. Wine/macdrv implementation remains unchanged. */
#include "native_wsi.h"
#include <pthread.h>
#include <string.h>
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static DXMTNativeWSIV1 table;
static unsigned installed,view_state;
static uintptr_t active_view;
static int get_table(DXMTNativeWSIV1 *out){pthread_mutex_lock(&lock);unsigned ready=installed;if(ready)*out=table;pthread_mutex_unlock(&lock);return ready!=0;}
int DXMTNativeInstallWSIV1(const DXMTNativeWSIV1 *callbacks){
    if(!callbacks || callbacks->version!=DXMT_NATIVE_WSI_VERSION || callbacks->size!=sizeof *callbacks ||
       !callbacks->query || !callbacks->resize || !callbacks->create_metal_view || !callbacks->release_metal_view)return 0;
    pthread_mutex_lock(&lock);if(installed){pthread_mutex_unlock(&lock);return 0;}table=*callbacks;installed=1;pthread_mutex_unlock(&lock);return 1;
}
int DXMTNativeQueryWindowV1(uint64_t window,DXMTNativeWindowInfoV1 *out){
    if(!out || out->size!=sizeof *out)return 0;
    memset(out,0,sizeof *out);out->size=sizeof *out;DXMTNativeWSIV1 callbacks;
    if(!window || !get_table(&callbacks))return 0;
    DXMTNativeWindowInfoV1 info={sizeof info,0,0,0};
    if(callbacks.query(callbacks.user,window,&info)!=1 || info.size!=sizeof info ||
       !info.width_pixels || !info.height_pixels || info.width_pixels>16384 || info.height_pixels>16384 ||
       (info.flags&~7u))return 0;
    *out=info;return 1;
}
int DXMTNativeResizeWindowV1(uint64_t window,uint32_t width,uint32_t height){
    if(!width || !height || width>16384 || height>16384)return 0;
    DXMTNativeWindowInfoV1 info={sizeof info,0,0,0};DXMTNativeWSIV1 callbacks;
    if(!DXMTNativeQueryWindowV1(window,&info) || !get_table(&callbacks))return 0;
    return callbacks.resize(callbacks.user,window,width,height)==1;
}
/* Internal native-WineMetal adapters. A single active view is the explicit v1
 * scope. Do not hold the registry mutex while calling a main-thread callback. */
uintptr_t DXMTNativeCreateMetalViewV1(uint64_t window,uintptr_t device,uintptr_t *layer){
    if(!layer)return 0;*layer=0;if(!device)return 0;
    DXMTNativeWindowInfoV1 info={sizeof info,0,0,0};DXMTNativeWSIV1 callbacks;
    if(!DXMTNativeQueryWindowV1(window,&info) || !get_table(&callbacks))return 0;
    pthread_mutex_lock(&lock);if(view_state){pthread_mutex_unlock(&lock);return 0;}view_state=1;pthread_mutex_unlock(&lock);
    uintptr_t out_layer=0,view=callbacks.create_metal_view(callbacks.user,window,device,&out_layer);
    if(!view || !out_layer){
        if(view)callbacks.release_metal_view(callbacks.user,view);
        pthread_mutex_lock(&lock);view_state=0;pthread_mutex_unlock(&lock);return 0;
    }
    pthread_mutex_lock(&lock);active_view=view;view_state=2;pthread_mutex_unlock(&lock);*layer=out_layer;return view;
}
void DXMTNativeReleaseMetalViewV1(uintptr_t view){
    DXMTNativeWSIV1 callbacks;
    pthread_mutex_lock(&lock);
    if(!installed || view_state!=2 || !view || view!=active_view){pthread_mutex_unlock(&lock);return;}
    callbacks=table;view_state=3;pthread_mutex_unlock(&lock);
    callbacks.release_metal_view(callbacks.user,view);
    pthread_mutex_lock(&lock);active_view=0;view_state=0;pthread_mutex_unlock(&lock);
}
