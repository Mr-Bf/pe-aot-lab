// Native D3D11 swapchain probe; no PE, guest HWND, user input, or shader Draw.
#include <sys/sysctl.h>
#include <cerrno>
#include <chrono>
#include <atomic>
#include <thread>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <d3d11.h>
#include <dxgi1_2.h>
#include "cocoa_registry.h"

namespace {
const char *truth(bool x) { return x?"true":"false"; }
struct HR {
  bool called=false; HRESULT value=0;
  bool set(HRESULT x) { called=true; value=x; return SUCCEEDED(x); }
  void print() const {
    if (!called) { std::printf("null"); return; }
    std::printf("{\"signed\":%d,\"hex\":\"0x%08x\",\"succeeded\":%s}",int(value),unsigned(value),truth(SUCCEEDED(value)));
  }
};
unsigned released=0;
template<class T> struct Owned {
  T *p=nullptr;
  ~Owned(){ release(); }
  void release(){ if(p){p->Release(); p=nullptr; ++released;} }
  T *operator->() const{return p;}
};
struct Phase {
  uint32_t width=0,height=0,color[4]={};
  HR buffer,rtv,staging,map,present,query;
  DXMTNativeWindowInfoV1 window={sizeof(window),0,0,0};
  uint32_t row_pitch=0,pixels=0,channels=0,bad_pixels=0,bad_channels=0,max_error=0;
  bool clear=false,copy=false,unmapped=false,query_complete=false;
  void print()const {
    std::printf("{\"width\":%u,\"height\":%u,\"expected_rgba8\":[%u,%u,%u,%u],",width,height,color[0],color[1],color[2],color[3]);
    std::printf("\"hresult\":{\"GetBuffer\":");buffer.print();std::printf(",\"CreateRTV\":");rtv.print();
    std::printf(",\"CreateStaging\":");staging.print();std::printf(",\"Map\":");map.print();
    std::printf(",\"Present\":");present.print();std::printf(",\"GetData\":");query.print();
    std::printf("},\"window\":{\"width_pixels\":%u,\"height_pixels\":%u,\"flags\":%u},",window.width_pixels,window.height_pixels,window.flags);
    std::printf("\"clear\":%s,\"copy\":%s,\"unmap\":%s,\"gpu_query_complete\":%s,",truth(clear),truth(copy),truth(unmapped),truth(query_complete));
    std::printf("\"row_pitch\":%u,\"pixels_checked\":%u,\"channels_checked\":%u,\"bad_pixels\":%u,\"bad_channels\":%u,\"max_error\":%u}",row_pitch,pixels,channels,bad_pixels,bad_channels,max_error);
  }
};
struct Result {
  bool native=false,pass=false;
  int translated=-1,translation_return=-1,translation_errno=0;
  size_t translation_size=sizeof(int);
  const char *failure="not_started";
  HR device,qi,adapter,factory,create,invalid_window,query_create,resize,removed,invalid_sync;
  D3D_FEATURE_LEVEL feature=static_cast<D3D_FEATURE_LEVEL>(0);
  Phase phases[2];
  bool callback_installed=false,repeat_install_rejected=false,wrong_version_rejected=false;
  bool unknown_query_rejected=false,invalid_resize_rejected=false,resize_callback=false;
  bool close_kept_view=false,window_destroyed=false,tombstone_rejected=false;
  uint32_t phases_done=0;
  NWRegistryStats stats={};
};

bool render_phase(Result &r,Phase &p,IDXGISwapChain1 *swap,ID3D11Device *device,
                  ID3D11DeviceContext *context,ID3D11Query *event,uint64_t window) {
  Owned<ID3D11Texture2D> buffer,staging;
  Owned<ID3D11RenderTargetView> rtv;
  r.failure="GetBuffer";
  if (!p.buffer.set(swap->GetBuffer(0,__uuidof(ID3D11Texture2D),reinterpret_cast<void **>(&buffer.p))) || !buffer.p) return false;
  D3D11_TEXTURE2D_DESC desc={};buffer->GetDesc(&desc);
  r.failure="backbuffer_description";
  if(desc.Width!=p.width || desc.Height!=p.height || desc.Format!=DXGI_FORMAT_R8G8B8A8_UNORM) return false;
  r.failure="CreateRenderTargetView";
  if(!p.rtv.set(device->CreateRenderTargetView(buffer.p,nullptr,&rtv.p)) || !rtv.p) return false;
  desc.Usage=D3D11_USAGE_STAGING;desc.BindFlags=0;desc.CPUAccessFlags=D3D11_CPU_ACCESS_READ;desc.MiscFlags=0;
  r.failure="CreateStaging";
  if(!p.staging.set(device->CreateTexture2D(&desc,nullptr,&staging.p)) || !staging.p) return false;
  FLOAT color[4];for(unsigned n=0;n<4;n++)color[n]=p.color[n]/255.0f;
  context->ClearRenderTargetView(rtv.p,color);p.clear=true;
  context->CopyResource(staging.p,buffer.p);p.copy=true;
  D3D11_MAPPED_SUBRESOURCE mapped={};
  r.failure="Map";
  if(!p.map.set(context->Map(staging.p,0,D3D11_MAP_READ,0,&mapped)))return false;
  p.row_pitch=mapped.RowPitch;
  if(mapped.pData && mapped.RowPitch>=p.width*4){
    for(uint32_t y=0;y<p.height;y++){
      const auto *row=static_cast<const uint8_t *>(mapped.pData)+size_t(y)*mapped.RowPitch;
      for(uint32_t x=0;x<p.width;x++){
        bool bad=false;
        for(unsigned c=0;c<4;c++){
          unsigned a=row[x*4+c],e=p.color[c],d=a>e?a-e:e-a;
          if(d>p.max_error)p.max_error=d;
          if(d>1){++p.bad_channels;bad=true;}
          ++p.channels;
        }
        ++p.pixels;if(bad)++p.bad_pixels;
      }
    }
  }
  context->Unmap(staging.p,0);p.unmapped=true;
  r.failure="readback_pixels";
  if(p.pixels!=p.width*p.height || p.bad_channels)return false;
  r.failure="registered_window_query";
  if(DXMTNativeQueryWindowV1(window,&p.window)!=1 || p.window.width_pixels!=p.width ||
      p.window.height_pixels!=p.height || !(p.window.flags&DXMT_WSI_VISIBLE) || (p.window.flags&DXMT_WSI_MINIMIZED)) return false;
  r.failure="Present0";
  if(!p.present.set(swap->Present(0,0)) || p.present.value!=S_OK)return false;
  // An event after Present plus Flush waits for the native command queue. This
  // does not establish that a compositor has displayed the image to a person.
  context->End(event);context->Flush();
  auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(15);
  r.failure="GPU_event_timeout";
  while(std::chrono::steady_clock::now()<deadline){
    BOOL completed=FALSE;HRESULT hr=context->GetData(event,&completed,sizeof(completed),0);
    p.query.set(hr);
    if(hr==S_OK && completed){p.query_complete=true;break;}
    if(FAILED(hr))return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return p.query_complete;
}

void worker(Result &r,NWRegistry *registry,uint64_t window,unsigned hold_ms){
  Owned<ID3D11Device> device;Owned<ID3D11DeviceContext> context;
  Owned<IDXGIDevice> dxgi;Owned<IDXGIAdapter> adapter;Owned<IDXGIFactory2> factory;
  Owned<IDXGISwapChain1> swap;Owned<ID3D11Query> event;
  do{
    const D3D_FEATURE_LEVEL requested[]={D3D_FEATURE_LEVEL_11_0};
    r.failure="D3D11CreateDevice";
    if(!r.device.set(D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,0,requested,1,
        D3D11_SDK_VERSION,&device.p,&r.feature,&context.p)) || !device.p || !context.p || r.feature!=requested[0])break;
    r.failure="QueryInterface_IDXGIDevice";
    if(!r.qi.set(device->QueryInterface(__uuidof(IDXGIDevice),reinterpret_cast<void **>(&dxgi.p))) || !dxgi.p)break;
    r.failure="GetAdapter";if(!r.adapter.set(dxgi->GetAdapter(&adapter.p)) || !adapter.p)break;
    r.failure="GetParent_IDXGIFactory2";
    if(!r.factory.set(adapter->GetParent(__uuidof(IDXGIFactory2),reinterpret_cast<void **>(&factory.p))) || !factory.p)break;
    DXGI_SWAP_CHAIN_DESC1 description={};
    description.Width=640;description.Height=360;description.Format=DXGI_FORMAT_R8G8B8A8_UNORM;
    description.SampleDesc.Count=1;description.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;
    description.BufferCount=2;description.Scaling=DXGI_SCALING_STRETCH;
    description.SwapEffect=DXGI_SWAP_EFFECT_FLIP_DISCARD;description.AlphaMode=DXGI_ALPHA_MODE_IGNORE;
    Owned<IDXGISwapChain1> invalid;
    r.failure="unknown_HWND_not_rejected";
    r.invalid_window.set(factory->CreateSwapChainForHwnd(device.p,reinterpret_cast<HWND>(uintptr_t(0x123)),
        &description,nullptr,nullptr,&invalid.p));
    if(r.invalid_window.value!=DXGI_ERROR_INVALID_CALL || invalid.p)break;
    r.failure="CreateSwapChainForHwnd";
    if(!r.create.set(factory->CreateSwapChainForHwnd(device.p,reinterpret_cast<HWND>(uintptr_t(window)),
        &description,nullptr,nullptr,&swap.p)) || !swap.p)break;
    r.failure="Present1_not_rejected";r.invalid_sync.set(swap->Present(1,0));
    if(r.invalid_sync.value!=DXGI_ERROR_UNSUPPORTED)break;
    D3D11_QUERY_DESC query={D3D11_QUERY_EVENT,0};
    r.failure="CreateQuery";if(!r.query_create.set(device->CreateQuery(&query,&event.p)) || !event.p)break;
    r.phases[0].width=640;r.phases[0].height=360;
    r.phases[1].width=800;r.phases[1].height=450;
    const uint32_t colors[2][4]={{17,85,170,255},{34,170,85,255}};
    for(unsigned i=0;i<2;i++)std::memcpy(r.phases[i].color,colors[i],sizeof(colors[i]));
    if(!render_phase(r,r.phases[0],swap.p,device.p,context.p,event.p,window))break;
    r.phases_done++;
    std::fprintf(stderr,"NATIVE_WINDOW_PHASE 0 complete; visible 640x360\n");std::fflush(stderr);
    std::this_thread::sleep_for(std::chrono::milliseconds(hold_ms));
    if(nw_stop_requested(registry)){r.failure="external_close_before_completion";break;}
    r.failure="resize_callback";r.resize_callback=DXMTNativeResizeWindowV1(window,800,450)==1;
    if(!r.resize_callback)break;
    r.failure="ResizeBuffers";
    if(!r.resize.set(swap->ResizeBuffers(2,800,450,DXGI_FORMAT_R8G8B8A8_UNORM,0)))break;
    if(!render_phase(r,r.phases[1],swap.p,device.p,context.p,event.p,window))break;
    r.phases_done++;
    std::fprintf(stderr,"NATIVE_WINDOW_PHASE 1 complete; visible 800x450\n");std::fflush(stderr);
    std::this_thread::sleep_for(std::chrono::milliseconds(hold_ms));
    r.failure="GetDeviceRemovedReason";
    if(!r.removed.set(device->GetDeviceRemovedReason()) || r.removed.value!=S_OK)break;
    // Explicit synthetic close, distinguished from a user's window event.
    nw_request_close(registry,window);
    NWRegistryStats snapshot={};nw_stats(registry,&snapshot);
    DXMTNativeWindowInfoV1 still={sizeof(still),0,0,0};
    r.close_kept_view=nw_stop_requested(registry) && snapshot.active_views==1 &&
        DXMTNativeQueryWindowV1(window,&still)==1;
    r.failure="close_destroyed_active_view";if(!r.close_kept_view)break;
    r.failure=nullptr;r.pass=true;
  }while(false);
  if(context.p){context->ClearState();context->Flush();}
  event.release();swap.release();factory.release();adapter.release();dxgi.release();context.release();device.release();
}

void print_result(const Result &r){
  std::printf("{\"schema\":1,\"probe\":\"native_dxmt_window_v1\",\"status\":\"%s\",\"failure_stage\":",r.pass?"PASS":"FAIL");
  if(r.failure)std::printf("\"%s\"",r.failure);else std::printf("null");
  std::printf(",\"scope\":{\"native_window\":true,\"present0\":true,\"resize\":true,\"shader_draw\":false,\"guest\":false,\"user_input\":false,\"visual_compositor_verified\":false},");
  std::printf("\"native_arm64\":%s,\"translation\":{\"returncode\":%d,\"errno\":%d,\"value\":%d,\"size\":%zu},\"feature_level\":%u,",truth(r.native),r.translation_return,r.translation_errno,r.translated,r.translation_size,unsigned(r.feature));
  std::printf("\"hresult\":{");
  const char *names[]={"D3D11CreateDevice","QueryIDXGIDevice","GetAdapter","GetFactory","CreateSwapChain","UnknownWindow","CreateQuery","ResizeBuffers","GetDeviceRemovedReason","UnsupportedPresent1"};
  const HR *values[]={&r.device,&r.qi,&r.adapter,&r.factory,&r.create,&r.invalid_window,&r.query_create,&r.resize,&r.removed,&r.invalid_sync};
  for(unsigned i=0;i<10;i++){if(i)std::printf(",");std::printf("\"%s\":",names[i]);values[i]->print();}
  std::printf("},\"phases_done\":%u,\"phases\":[",r.phases_done);r.phases[0].print();std::printf(",");r.phases[1].print();
  std::printf("],\"installed\":%s,\"repeat_install_rejected\":%s,\"wrong_version_rejected\":%s,\"unknown_query_rejected\":%s,\"invalid_resize_rejected\":%s,",truth(r.callback_installed),truth(r.repeat_install_rejected),truth(r.wrong_version_rejected),truth(r.unknown_query_rejected),truth(r.invalid_resize_rejected));
  std::printf("\"resize_callback\":%s,\"synthetic_close_kept_view\":%s,\"window_destroyed\":%s,\"tombstone_rejected\":%s,\"released_application_references\":%u,",truth(r.resize_callback),truth(r.close_kept_view),truth(r.window_destroyed),truth(r.tombstone_rejected),released);
  const auto &s=r.stats;
  std::printf("\"registry\":{\"created\":%u,\"destroyed\":%u,\"queries\":%u,\"query_rejections\":%u,\"resizes\":%u,\"resize_rejections\":%u,\"views_created\":%u,\"views_released\":%u,\"active_views\":%u,\"view_rejections\":%u,\"release_rejections\":%u,\"close_requests\":%u,\"main_dispatches\":%u,\"event_pumps\":%u,\"visible_observations\":%u,\"main_thread_violations\":%u,\"width_pixels\":%u,\"height_pixels\":%u,\"window_number\":%u,\"tombstones\":%u,\"backing_scale\":%.9g}}\n",
      s.windows_created,s.windows_destroyed,s.queries,s.query_rejections,s.resizes,s.resize_rejections,s.views_created,s.views_released,s.active_views,s.view_rejections,s.release_rejections,s.close_requests,s.main_dispatches,s.event_pumps,s.visible_observations,s.main_thread_violations,s.width_pixels,s.height_pixels,s.window_number,s.tombstones,s.backing_scale);
}
}

int main(int argc,char **argv){
  unsigned hold_ms=1000;
  if(argc==3 && std::strcmp(argv[1],"--hold-ms")==0){char *end=nullptr;unsigned long n=std::strtoul(argv[2],&end,10);if(!end||*end||n>10000)return 64;hold_ms=unsigned(n);}
  else if(argc!=1)return 64;
  Result r;
  errno=0;r.translation_return=sysctlbyname("sysctl.proc_translated",&r.translated,&r.translation_size,nullptr,0);
  r.translation_errno=r.translation_return?errno:0;
#if defined(__arm64__) || defined(__aarch64__)
  r.native=(r.translation_return==0 && r.translation_size==sizeof(int) && r.translated==0) ||
      (r.translation_return==-1 && r.translation_errno==ENOENT);
#endif
  if(!r.native){r.failure="native_identity_unverified";print_result(r);return 1;}
  NWRegistry *registry=nw_registry_create();
  if(!registry){r.failure="Cocoa_application";print_result(r);return 1;}
  uint64_t window=nw_window_create(registry,640,360);
  if(!window){r.failure="Cocoa_window";print_result(r);return 1;}
  DXMTNativeWSIV1 callbacks={};nw_callbacks(registry,&callbacks);
  DXMTNativeWSIV1 wrong=callbacks;wrong.version=2;
  r.wrong_version_rejected=DXMTNativeInstallWSIV1(&wrong)==0;
  r.callback_installed=DXMTNativeInstallWSIV1(&callbacks)==1;
  r.repeat_install_rejected=DXMTNativeInstallWSIV1(&callbacks)==0;
  DXMTNativeWindowInfoV1 unknown={sizeof(unknown),0,0,0};
  r.unknown_query_rejected=DXMTNativeQueryWindowV1(0x123,&unknown)==0 && unknown.width_pixels==0 && unknown.height_pixels==0;
  r.invalid_resize_rejected=DXMTNativeResizeWindowV1(window,0,360)==0;
  bool config=r.wrong_version_rejected && r.callback_installed && r.repeat_install_rejected && r.unknown_query_rejected && r.invalid_resize_rejected;
  if(config){
    std::atomic<bool> done=false;
    std::thread thread([&]{worker(r,registry,window,hold_ms);done.store(true);});
    while(!done.load())nw_pump_once(registry,0.01);
    thread.join();
  }else r.failure="WSI_callback_contract";
  r.window_destroyed=nw_window_destroy(registry,window)==1;
  DXMTNativeWindowInfoV1 tombstone={sizeof(tombstone),0,0,0};
  r.tombstone_rejected=DXMTNativeQueryWindowV1(window,&tombstone)==0;
  nw_stats(registry,&r.stats);
  bool cleanup=r.window_destroyed && r.tombstone_rejected && r.stats.active_views==0 &&
      r.stats.views_created==1 && r.stats.views_released==1 && r.stats.main_thread_violations==0;
  if(r.pass && !cleanup){r.pass=false;r.failure="window_cleanup";}
  print_result(r);return r.pass?0:1;
}
