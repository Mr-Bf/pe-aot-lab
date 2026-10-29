// Versioned swapchain extension. Uses real pinned DXMT/DirectX declarations.
// The existing native_backend.cpp remains unchanged and supplies other methods.
#define D3D11_NO_HELPERS
#define D3D10_NO_HELPERS
#include <d3d11.h>
#include <cstddef>
#include <cstring>
#include "native_backend_window.h"

static_assert(sizeof(HRESULT)==4 && sizeof(ULONG)==4 && sizeof(UINT)==4);
static_assert(sizeof(HWND)==8 && sizeof(uintptr_t)==8 && sizeof(GUID)==16);
static_assert(sizeof(DXGI_MODE_DESC)==28 && sizeof(DXGI_SWAP_CHAIN_DESC)==72);
static_assert(offsetof(DXGI_SWAP_CHAIN_DESC,BufferDesc)==0);
static_assert(offsetof(DXGI_SWAP_CHAIN_DESC,SampleDesc)==28);
static_assert(offsetof(DXGI_SWAP_CHAIN_DESC,BufferUsage)==36);
static_assert(offsetof(DXGI_SWAP_CHAIN_DESC,BufferCount)==40);
static_assert(offsetof(DXGI_SWAP_CHAIN_DESC,OutputWindow)==48);
static_assert(offsetof(DXGI_SWAP_CHAIN_DESC,Windowed)==56);
static_assert(offsetof(DXGI_SWAP_CHAIN_DESC,SwapEffect)==60);
static_assert(offsetof(DXGI_SWAP_CHAIN_DESC,Flags)==64);
static_assert(sizeof(D3D11_TEXTURE2D_DESC)==11*sizeof(uint32_t));
static_assert(sizeof(AotWindowNativeSwapDesc)==72);
static_assert(offsetof(AotWindowNativeSwapDesc,hwnd_token)==48);

uint32_t aot_window_native_create_device_swapchain(
    const AotWindowNativeSwapDesc *values,void **swapchain,void **device,
    uint32_t *level,void **context) {
    // Field-wise marshaling intentionally excludes host/guest padding bytes.
    DXGI_SWAP_CHAIN_DESC desc={};
    desc.BufferDesc.Width=values->width;
    desc.BufferDesc.Height=values->height;
    desc.BufferDesc.RefreshRate={values->refresh_numerator,values->refresh_denominator};
    desc.BufferDesc.Format=static_cast<DXGI_FORMAT>(values->format);
    desc.BufferDesc.ScanlineOrdering=static_cast<DXGI_MODE_SCANLINE_ORDER>(values->scanline_ordering);
    desc.BufferDesc.Scaling=static_cast<DXGI_MODE_SCALING>(values->scaling);
    desc.SampleDesc={values->sample_count,values->sample_quality};
    desc.BufferUsage=values->buffer_usage;
    desc.BufferCount=values->buffer_count;
    desc.OutputWindow=reinterpret_cast<HWND>(static_cast<uintptr_t>(values->hwnd_token));
    desc.Windowed=static_cast<BOOL>(values->windowed);
    desc.SwapEffect=static_cast<DXGI_SWAP_EFFECT>(values->swap_effect);
    desc.Flags=values->flags;

    IDXGISwapChain *swap=nullptr;
    ID3D11Device *d=nullptr;
    ID3D11DeviceContext *c=nullptr;
    const D3D_FEATURE_LEVEL requested=D3D_FEATURE_LEVEL_11_0;
    D3D_FEATURE_LEVEL selected=static_cast<D3D_FEATURE_LEVEL>(0);
    HRESULT hr=D3D11CreateDeviceAndSwapChain(nullptr,D3D_DRIVER_TYPE_HARDWARE,
        nullptr,0,&requested,1,D3D11_SDK_VERSION,&desc,&swap,&d,&selected,&c);
    *swapchain=swap;*device=d;*level=static_cast<uint32_t>(selected);*context=c;
    return static_cast<uint32_t>(hr);
}

uint32_t aot_window_native_get_buffer(void *swapchain,uint32_t buffer,
    const uint8_t iid_bytes[16],void **texture,uint32_t actual_desc[11]) {
    GUID iid={};std::memcpy(&iid,iid_bytes,sizeof iid);
    void *returned=nullptr;
    std::memset(actual_desc,0,11*sizeof(uint32_t));
    HRESULT hr=static_cast<IDXGISwapChain*>(swapchain)->GetBuffer(buffer,iid,&returned);
    *texture=returned;
    if(SUCCEEDED(hr) && returned) {
        // Runtime has checked that the actual IID is ID3D11Texture2D before
        // this typed function is called. No arbitrary interface cast is valid.
        D3D11_TEXTURE2D_DESC desc={};
        static_cast<ID3D11Texture2D*>(returned)->GetDesc(&desc);
        actual_desc[0]=desc.Width;actual_desc[1]=desc.Height;
        actual_desc[2]=desc.MipLevels;actual_desc[3]=desc.ArraySize;
        actual_desc[4]=static_cast<uint32_t>(desc.Format);
        actual_desc[5]=desc.SampleDesc.Count;actual_desc[6]=desc.SampleDesc.Quality;
        actual_desc[7]=static_cast<uint32_t>(desc.Usage);
        actual_desc[8]=desc.BindFlags;actual_desc[9]=desc.CPUAccessFlags;
        actual_desc[10]=desc.MiscFlags;
    }
    return static_cast<uint32_t>(hr);
}

uint32_t aot_window_native_present(void *swapchain,uint32_t interval,uint32_t flags) {
    return static_cast<uint32_t>(static_cast<IDXGISwapChain*>(swapchain)->Present(interval,flags));
}
void aot_window_native_clear_state(void *context) {
    static_cast<ID3D11DeviceContext*>(context)->ClearState();
}
void aot_window_native_flush(void *context) {
    static_cast<ID3D11DeviceContext*>(context)->Flush();
}
uint32_t aot_window_native_release_swap(void *swapchain) {
    return static_cast<IDXGISwapChain*>(swapchain)->Release();
}
