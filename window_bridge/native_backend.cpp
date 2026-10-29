// Real native DXMT adapter, using the original pinned DirectX declarations.
// No emulated pixels, no host recompilation of the guest's readback algorithm.
#define D3D11_NO_HELPERS
#define D3D10_NO_HELPERS
#include <d3d11.h>
#include "native_backend.h"
#include <cstring>
static_assert(sizeof(HRESULT)==4 && sizeof(ULONG)==4 && sizeof(FLOAT)==4);
static_assert(sizeof(D3D11_TEXTURE2D_DESC)==44 && sizeof(D3D11_MAPPED_SUBRESOURCE)==16);

uint32_t aot_d3d_native_create_device(void **device,void **context,uint32_t *level) {
    ID3D11Device *d=nullptr;ID3D11DeviceContext *c=nullptr;
    const D3D_FEATURE_LEVEL requested=D3D_FEATURE_LEVEL_11_0;
    D3D_FEATURE_LEVEL selected=static_cast<D3D_FEATURE_LEVEL>(0);
    HRESULT result=D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,0,
        &requested,1,D3D11_SDK_VERSION,&d,&selected,&c);
    *device=d;*context=c;*level=static_cast<uint32_t>(selected);
    return static_cast<uint32_t>(result);
}
uint32_t aot_d3d_native_create_texture(void *device,const uint32_t values[11],void **texture) {
    D3D11_TEXTURE2D_DESC desc={};
    desc.Width=values[0];desc.Height=values[1];desc.MipLevels=values[2];desc.ArraySize=values[3];
    desc.Format=static_cast<DXGI_FORMAT>(values[4]);desc.SampleDesc.Count=values[5];desc.SampleDesc.Quality=values[6];
    desc.Usage=static_cast<D3D11_USAGE>(values[7]);desc.BindFlags=values[8];desc.CPUAccessFlags=values[9];desc.MiscFlags=values[10];
    ID3D11Texture2D *result=nullptr;
    HRESULT status=static_cast<ID3D11Device*>(device)->CreateTexture2D(&desc,nullptr,&result);
    *texture=result;return static_cast<uint32_t>(status);
}
uint32_t aot_d3d_native_create_rtv(void *device,void *texture,void **view) {
    ID3D11RenderTargetView *result=nullptr;
    HRESULT status=static_cast<ID3D11Device*>(device)->CreateRenderTargetView(
        static_cast<ID3D11Texture2D*>(texture),nullptr,&result);
    *view=result;return static_cast<uint32_t>(status);
}
uint32_t aot_d3d_native_get_removed(void *device) {
    return static_cast<uint32_t>(static_cast<ID3D11Device*>(device)->GetDeviceRemovedReason());
}
void aot_d3d_native_clear(void *context,void *view,const float color[4]) {
    static_cast<ID3D11DeviceContext*>(context)->ClearRenderTargetView(static_cast<ID3D11RenderTargetView*>(view),color);
}
void aot_d3d_native_copy(void *context,void *destination,void *source) {
    static_cast<ID3D11DeviceContext*>(context)->CopyResource(static_cast<ID3D11Texture2D*>(destination),
                                                          static_cast<ID3D11Texture2D*>(source));
}
uint32_t aot_d3d_native_map(void *context,void *texture,AotD3DNativeMap *result) {
    D3D11_MAPPED_SUBRESOURCE mapped={};
    HRESULT status=static_cast<ID3D11DeviceContext*>(context)->Map(static_cast<ID3D11Texture2D*>(texture),
        0,D3D11_MAP_READ,0,&mapped);
    result->data=mapped.pData;result->row_pitch=mapped.RowPitch;result->depth_pitch=mapped.DepthPitch;
    return static_cast<uint32_t>(status);
}
void aot_d3d_native_unmap(void *context,void *texture) {
    static_cast<ID3D11DeviceContext*>(context)->Unmap(static_cast<ID3D11Texture2D*>(texture),0);
}
uint32_t aot_d3d_native_create_shader(uint32_t kind,void *device,const uint8_t *bytes,uint64_t size,void **shader) {
    if(kind==5) {
        ID3D11VertexShader *result=nullptr;
        HRESULT hr=static_cast<ID3D11Device*>(device)->CreateVertexShader(bytes,static_cast<SIZE_T>(size),nullptr,&result);
        *shader=result;return static_cast<uint32_t>(hr);
    }
    if(kind==6) {
        ID3D11PixelShader *result=nullptr;
        HRESULT hr=static_cast<ID3D11Device*>(device)->CreatePixelShader(bytes,static_cast<SIZE_T>(size),nullptr,&result);
        *shader=result;return static_cast<uint32_t>(hr);
    }
    __builtin_trap();
}
uint32_t aot_d3d_native_create_raster(void *device,const uint32_t values[10],void **raster) {
    static_assert(sizeof(D3D11_RASTERIZER_DESC)==40);
    D3D11_RASTERIZER_DESC desc={};std::memcpy(&desc,values,sizeof desc);
    ID3D11RasterizerState *result=nullptr;
    HRESULT hr=static_cast<ID3D11Device*>(device)->CreateRasterizerState(&desc,&result);
    *raster=result;return static_cast<uint32_t>(hr);
}
void aot_d3d_native_om_set(void *context,void *view) {
    ID3D11RenderTargetView *rtv=static_cast<ID3D11RenderTargetView*>(view);
    static_cast<ID3D11DeviceContext*>(context)->OMSetRenderTargets(1,&rtv,nullptr);
}
void aot_d3d_native_rs_set(void *context,void *raster) {
    static_cast<ID3D11DeviceContext*>(context)->RSSetState(static_cast<ID3D11RasterizerState*>(raster));
}
void aot_d3d_native_viewport(void *context,const uint32_t bits[6]) {
    static_assert(sizeof(D3D11_VIEWPORT)==24);
    D3D11_VIEWPORT viewport={};std::memcpy(&viewport,bits,sizeof viewport);
    static_cast<ID3D11DeviceContext*>(context)->RSSetViewports(1,&viewport);
}
void aot_d3d_native_topology(void *context) {
    static_cast<ID3D11DeviceContext*>(context)->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
}
void aot_d3d_native_shader_set(uint32_t kind,void *context,void *shader) {
    if(kind==5)static_cast<ID3D11DeviceContext*>(context)->VSSetShader(static_cast<ID3D11VertexShader*>(shader),nullptr,0);
    else if(kind==6)static_cast<ID3D11DeviceContext*>(context)->PSSetShader(static_cast<ID3D11PixelShader*>(shader),nullptr,0);
    else __builtin_trap();
}
void aot_d3d_native_draw(void *context) {
    static_cast<ID3D11DeviceContext*>(context)->Draw(3,0);
}
uint32_t aot_d3d_native_release(uint32_t kind,void *object) {
    switch(kind) {
    case 1:return static_cast<ID3D11Device*>(object)->Release();
    case 2:return static_cast<ID3D11DeviceContext*>(object)->Release();
    case 3:return static_cast<ID3D11Texture2D*>(object)->Release();
    case 4:return static_cast<ID3D11RenderTargetView*>(object)->Release();
    case 5:return static_cast<ID3D11VertexShader*>(object)->Release();
    case 6:return static_cast<ID3D11PixelShader*>(object)->Release();
    case 7:return static_cast<ID3D11RasterizerState*>(object)->Release();
    default:__builtin_trap(); // Trusted-host programming error; guest kind is validated by runtime.
    }
}
