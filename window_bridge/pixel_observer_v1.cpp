// Read-only native backbuffer instrumentation; never a guest render path.
#define D3D11_NO_HELPERS
#define D3D10_NO_HELPERS
#include <d3d11.h>
#include "pixel_observer_v1.h"
#include <cerrno>
#include <cinttypes>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static_assert(sizeof(HRESULT)==4 && sizeof(UINT)==4 && sizeof(void*)==8);
static_assert(sizeof(AotPixelObserverConfig)==32);
static_assert(sizeof(AotPixelObserverStats)==168);
extern "C" uint32_t aot_window_native_present_plain(void *,uint32_t,uint32_t);
namespace {
struct Observer {
    int directory_fd=-1;
    uint32_t max_frames=0;
    uint64_t max_bytes=0;
    bool busy=false;
    AotPixelObserverStats stats={};
};
static thread_local Observer observer;
struct Frame {
    uint64_t index=0;
    uint32_t error=0,os_error=0,interval=0,flags=0;
    uint32_t device_hr=0,buffer_hr=0,staging_hr=0,map_hr=0,removed_hr=0,present_hr=0;
    uint32_t called=0,row_pitch=0,depth_pitch=0,desc[11]={};
    uint32_t acquired=0,released=0,mapped=0,unmapped=0;
    bool packed=false,raw_complete=false;
};
enum { CALLED_DEVICE=1,CALLED_CONTEXT=2,CALLED_BUFFER=4,CALLED_STAGING=8,
       CALLED_COPY=16,CALLED_MAP=32,CALLED_REMOVED=64,CALLED_PRESENT=128 };
static void latch(uint32_t error,int os_error=0) {
    if(!observer.stats.first_error){observer.stats.first_error=error;observer.stats.first_errno=(uint32_t)os_error;}
}
static void fail(Frame &f,uint32_t error,int os_error=0) {
    if(!f.error){f.error=error;f.os_error=(uint32_t)os_error;}latch(error,os_error);
}
template<typename T> static void acquired(Frame &f,T *p) {
    if(p){f.acquired++;observer.stats.refs_acquired++;observer.stats.live_refs++;}
}
template<typename T> static void release(Frame &f,T *&p) {
    if(p){p->Release();p=nullptr;f.released++;observer.stats.refs_released++;observer.stats.live_refs--;}
}
static bool write_file(const char *name,const void *data,size_t size,int &error) {
    int fd=openat(observer.directory_fd,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0){error=errno;return false;}
    const uint8_t *bytes=static_cast<const uint8_t*>(data);size_t offset=0;bool ok=true;
    while(offset<size) {
        ssize_t n=write(fd,bytes+offset,size-offset);
        if(n<0 && errno==EINTR)continue;
        if(n<=0){error=n<0?errno:EIO;ok=false;break;}
        offset+=(size_t)n;
    }
    // A failed or partial file is evidence, never silently removed/retried.
    if(close(fd)!=0){if(ok)error=errno;ok=false;}return ok;
}
static bool exact_desc(const D3D11_TEXTURE2D_DESC &d) {
    return d.Width==AOT_PIXEL_WIDTH && d.Height==AOT_PIXEL_HEIGHT && d.MipLevels==1 && d.ArraySize==1 &&
        d.Format==DXGI_FORMAT_R8G8B8A8_UNORM && d.SampleDesc.Count==1 && !d.SampleDesc.Quality &&
        d.Usage==D3D11_USAGE_DEFAULT && d.BindFlags==D3D11_BIND_RENDER_TARGET && !d.CPUAccessFlags && !d.MiscFlags;
}
static void capture(void *pointer,Frame &f,uint8_t *packed) {
    auto *swap=static_cast<IDXGISwapChain*>(pointer);
    ID3D11Device *device=nullptr;ID3D11DeviceContext *context=nullptr;
    ID3D11Texture2D *source=nullptr,*staging=nullptr;
    D3D11_TEXTURE2D_DESC d={};D3D11_MAPPED_SUBRESOURCE map={};bool mapped=false;
    // Single cleanup block; no early return may strand a successful Map/ref.
    do {
        if(!swap || f.interval || f.flags){fail(f,AOT_PIXEL_INVALID);break;}
        f.called|=CALLED_DEVICE;f.device_hr=(uint32_t)swap->GetDevice(__uuidof(ID3D11Device),reinterpret_cast<void**>(&device));acquired(f,device);
        if((int32_t)f.device_hr<0 || !device){fail(f,AOT_PIXEL_GET_DEVICE);break;}
        f.called|=CALLED_CONTEXT;device->GetImmediateContext(&context);acquired(f,context);
        if(!context){fail(f,AOT_PIXEL_GET_CONTEXT);break;}
        f.called|=CALLED_BUFFER;f.buffer_hr=(uint32_t)swap->GetBuffer(0,__uuidof(ID3D11Texture2D),reinterpret_cast<void**>(&source));acquired(f,source);
        if((int32_t)f.buffer_hr<0 || !source){fail(f,AOT_PIXEL_GET_BUFFER);break;}
        source->GetDesc(&d);
        const uint32_t values[]={d.Width,d.Height,d.MipLevels,d.ArraySize,(uint32_t)d.Format,d.SampleDesc.Count,d.SampleDesc.Quality,
                                 (uint32_t)d.Usage,d.BindFlags,d.CPUAccessFlags,d.MiscFlags};
        std::memcpy(f.desc,values,sizeof values);
        if(!exact_desc(d)){fail(f,AOT_PIXEL_DESCRIPTOR);break;}
        d.Usage=D3D11_USAGE_STAGING;d.BindFlags=0;d.CPUAccessFlags=D3D11_CPU_ACCESS_READ;d.MiscFlags=0;
        f.called|=CALLED_STAGING;f.staging_hr=(uint32_t)device->CreateTexture2D(&d,nullptr,&staging);acquired(f,staging);
        if((int32_t)f.staging_hr<0 || !staging){fail(f,AOT_PIXEL_CREATE_STAGING);break;}
        f.called|=CALLED_COPY;observer.stats.copy_calls++;context->CopyResource(staging,source);
        f.called|=CALLED_MAP;observer.stats.map_calls++;f.map_hr=(uint32_t)context->Map(staging,0,D3D11_MAP_READ,0,&map);
        if((int32_t)f.map_hr<0){fail(f,AOT_PIXEL_MAP);break;}
        mapped=true;f.mapped=1;observer.stats.live_maps++;f.row_pitch=map.RowPitch;f.depth_pitch=map.DepthPitch;
        const uint64_t last_offset=uint64_t(AOT_PIXEL_HEIGHT-1)*map.RowPitch;
        const uint64_t viewed_bytes=last_offset+uint64_t(AOT_PIXEL_WIDTH)*4;
        const uintptr_t address=reinterpret_cast<uintptr_t>(map.pData);
        if(!map.pData || map.RowPitch<AOT_PIXEL_WIDTH*4 || viewed_bytes>SIZE_MAX || viewed_bytes>UINTPTR_MAX-address) {
            fail(f,AOT_PIXEL_MAP_LAYOUT);break;
        }
        // Only real pixel rows. Native padding and DepthPitch are not assumed
        // to be an allocation bound or copied into deterministic artifacts.
        for(unsigned y=0;y<AOT_PIXEL_HEIGHT;y++)
            std::memcpy(packed+size_t(y)*AOT_PIXEL_WIDTH*4,
                        static_cast<const uint8_t*>(map.pData)+size_t(y)*map.RowPitch,AOT_PIXEL_WIDTH*4);
        f.packed=true;
    } while(false);
    if(mapped){context->Unmap(staging,0);f.unmapped=1;observer.stats.unmap_calls++;observer.stats.live_maps--;}
    if(device){f.called|=CALLED_REMOVED;f.removed_hr=(uint32_t)device->GetDeviceRemovedReason();if((int32_t)f.removed_hr<0)fail(f,AOT_PIXEL_DEVICE_REMOVED);}
    release(f,staging);release(f,source);release(f,context);release(f,device);
}
static bool emit_frame(Frame &f,const uint8_t *packed) {
    char raw_name[64],json_name[64],record[4096];
    std::snprintf(raw_name,sizeof raw_name,"frame-%06" PRIu64 ".rgba",f.index);
    std::snprintf(json_name,sizeof json_name,"frame-%06" PRIu64 ".json",f.index);
    int error=0;
    if(f.packed) {
        f.raw_complete=write_file(raw_name,packed,AOT_PIXEL_RGBA_BYTES,error);
        if(f.raw_complete)observer.stats.raw_bytes_written+=AOT_PIXEL_RGBA_BYTES;else fail(f,AOT_PIXEL_FILE,error);
    }
    int n=std::snprintf(record,sizeof record,
        "{\"schema\":1,\"profile\":\"window-pixel-observer-v1\",\"frame\":%" PRIu64 ",\"error\":%u,\"errno\":%u,"
        "\"interval\":%u,\"flags\":%u,\"called_mask\":%u,\"device_hr\":%u,\"buffer_hr\":%u,\"staging_hr\":%u,"
        "\"map_hr\":%u,\"removed_hr\":%u,\"present_hr\":%u,\"row_pitch\":%u,\"depth_pitch\":%u,"
        "\"descriptor\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u],\"refs_acquired\":%u,\"refs_released\":%u,"
        "\"mapped\":%u,\"unmapped\":%u,\"packed\":%s,\"raw_complete\":%s,\"rgba_file\":\"%s\","
        "\"rgba_bytes\":%u,\"source\":\"actual_backbuffer_before_present\",\"padding_copied\":false}\n",
        f.index,f.error,f.os_error,f.interval,f.flags,f.called,f.device_hr,f.buffer_hr,f.staging_hr,f.map_hr,f.removed_hr,f.present_hr,
        f.row_pitch,f.depth_pitch,f.desc[0],f.desc[1],f.desc[2],f.desc[3],f.desc[4],f.desc[5],f.desc[6],f.desc[7],f.desc[8],f.desc[9],f.desc[10],
        f.acquired,f.released,f.mapped,f.unmapped,f.packed?"true":"false",f.raw_complete?"true":"false",raw_name,f.raw_complete?AOT_PIXEL_RGBA_BYTES:0);
    if(n<0 || (size_t)n>=sizeof record){fail(f,AOT_PIXEL_FILE,EOVERFLOW);return false;}
    if(!write_file(json_name,record,(size_t)n,error)){fail(f,AOT_PIXEL_FILE,error);return false;}
    observer.stats.records_written++;return true;
}
static bool emit_summary() {
    const auto &s=observer.stats;char text[4096];int error=0;
    int n=std::snprintf(text,sizeof text,
        "{\"schema\":1,\"profile\":\"window-pixel-observer-v1\",\"active\":%u,\"first_error\":%u,\"first_errno\":%u,"
        "\"last_present_hr\":%u,\"attempts\":%" PRIu64 ",\"present_calls\":%" PRIu64 ",\"captured_frames\":%" PRIu64 ",\"records_written\":%" PRIu64 ","
        "\"raw_bytes_written\":%" PRIu64 ",\"rgba_bytes_reserved\":%" PRIu64 ",\"copy_calls\":%" PRIu64 ",\"map_calls\":%" PRIu64 ",\"unmap_calls\":%" PRIu64 ","
        "\"refs_acquired\":%" PRIu64 ",\"refs_released\":%" PRIu64 ",\"live_refs\":%" PRIu64 ",\"live_maps\":%" PRIu64 ","
        "\"failures\":%" PRIu64 ",\"capacity_rejections\":%" PRIu64 ",\"unconfigured_calls\":%" PRIu64 ",\"reentrant_calls\":%" PRIu64 ","
        "\"max_frames\":%u,\"max_total_rgba_bytes\":%" PRIu64 ",\"pixels_verified\":false,\"performance_sample\":false}\n",
        s.active,s.first_error,s.first_errno,s.last_present_hr,s.attempts,s.present_calls,s.captured_frames,s.records_written,
        s.raw_bytes_written,s.rgba_bytes_reserved,s.copy_calls,s.map_calls,s.unmap_calls,s.refs_acquired,s.refs_released,s.live_refs,s.live_maps,
        s.failures,s.capacity_rejections,s.unconfigured_calls,s.reentrant_calls,observer.max_frames,observer.max_bytes);
    if(n<0 || (size_t)n>=sizeof text){latch(AOT_PIXEL_FILE,EOVERFLOW);return false;}
    if(!write_file("observer-summary.json",text,(size_t)n,error)){latch(AOT_PIXEL_FILE,error);return false;}return true;
}
} // namespace

uint32_t aot_window_observer_begin(const AotPixelObserverConfig *config) {
    if(observer.stats.active || observer.busy)return AOT_PIXEL_BUSY;
    if(observer.stats.unconfigured_calls)return AOT_PIXEL_NOT_CONFIGURED;
    if(!config || config->version!=AOT_PIXEL_OBSERVER_VERSION || config->size!=sizeof *config || config->reserved ||
       !config->max_frames || config->max_frames>AOT_PIXEL_MAX_FRAMES ||
       config->max_total_rgba_bytes<uint64_t(config->max_frames)*AOT_PIXEL_RGBA_BYTES ||
       config->max_total_rgba_bytes>uint64_t(AOT_PIXEL_MAX_FRAMES)*AOT_PIXEL_RGBA_BYTES ||
       !config->directory || config->directory[0]!='/' || strnlen(config->directory,PATH_MAX)==PATH_MAX)return AOT_PIXEL_INVALID;
    int fd=open(config->directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return AOT_PIXEL_DIRECTORY;
    int copy=dup(fd);if(copy<0){close(fd);return AOT_PIXEL_DIRECTORY;}
    DIR *dir=fdopendir(copy);if(!dir){close(copy);close(fd);return AOT_PIXEL_DIRECTORY;}
    bool empty=true;errno=0;
    while(dirent *entry=readdir(dir))if(std::strcmp(entry->d_name,".") && std::strcmp(entry->d_name,"..")){empty=false;break;}
    int scan_error=errno;if(closedir(dir)!=0)scan_error=errno;
    if(!empty || scan_error){close(fd);return AOT_PIXEL_DIRECTORY;}
    observer=Observer{};observer.directory_fd=fd;observer.max_frames=config->max_frames;observer.max_bytes=config->max_total_rgba_bytes;
    observer.stats.version=AOT_PIXEL_OBSERVER_VERSION;observer.stats.size=sizeof observer.stats;observer.stats.active=1;return AOT_PIXEL_OK;
}
uint32_t aot_window_observer_end(AotPixelObserverStats *out) {
    if(!out)return AOT_PIXEL_INVALID;
    if(!observer.stats.active || observer.busy){*out=observer.stats;return AOT_PIXEL_BUSY;}
    observer.stats.active=0;(void)emit_summary();
    if(close(observer.directory_fd)!=0)latch(AOT_PIXEL_FILE,errno);
    observer.directory_fd=-1;*out=observer.stats;return observer.stats.first_error;
}
void aot_window_observer_stats(AotPixelObserverStats *out){if(out)*out=observer.stats;}
uint32_t aot_window_native_present(void *swapchain,uint32_t interval,uint32_t flags) {
    observer.stats.attempts++;
    if(!observer.stats.active || observer.busy) {
        if(!observer.stats.active){observer.stats.unconfigured_calls++;latch(AOT_PIXEL_NOT_CONFIGURED);}
        else {observer.stats.reentrant_calls++;latch(AOT_PIXEL_BUSY);}
        observer.stats.failures++;observer.stats.present_calls++;
        uint32_t hr=aot_window_native_present_plain(swapchain,interval,flags);observer.stats.last_present_hr=hr;return hr;
    }
    observer.busy=true;Frame f;f.index=observer.stats.attempts;f.interval=interval;f.flags=flags;
    bool room=f.index<=observer.max_frames && observer.stats.rgba_bytes_reserved<=observer.max_bytes-AOT_PIXEL_RGBA_BYTES;
    uint8_t *bytes=nullptr;
    if(!room){observer.stats.capacity_rejections++;fail(f,AOT_PIXEL_CAPACITY);}
    else {
        observer.stats.rgba_bytes_reserved+=AOT_PIXEL_RGBA_BYTES;
        bytes=static_cast<uint8_t*>(std::malloc(AOT_PIXEL_RGBA_BYTES));
        if(!bytes)fail(f,AOT_PIXEL_ALLOCATION);else capture(swapchain,f,bytes);
    }
    // No live observer COM object or mapping may cross the actual Present.
    if(f.acquired!=f.released || f.mapped!=f.unmapped || observer.stats.live_refs || observer.stats.live_maps)fail(f,AOT_PIXEL_INVALID);
    f.called|=CALLED_PRESENT;observer.stats.present_calls++;
    f.present_hr=aot_window_native_present_plain(swapchain,interval,flags);observer.stats.last_present_hr=f.present_hr;
    if((int32_t)f.present_hr<0)fail(f,AOT_PIXEL_PRESENT);
    bool emitted=room && emit_frame(f,bytes);
    if(emitted && !f.error && f.packed && f.raw_complete)observer.stats.captured_frames++;
    if(f.error)observer.stats.failures++;
    std::free(bytes);observer.busy=false;return f.present_hr;
}
