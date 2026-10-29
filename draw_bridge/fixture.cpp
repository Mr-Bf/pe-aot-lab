// Genuine no-argument Windows PE entry. DirectX interfaces are unmodified
// pinned mingw-directx-headers + DXMT native/windows declarations.
// This source is not ARM execution or Windows-machine test evidence.
#include <d3d11.h>
#include "../graphics_stage5/shaders/draw_shaders.h"

// The shared DirectX header omits dllimport. Add only import decoration to its
// identical API declaration, so the ordinary Windows caller emits an IAT CALL.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdll-attribute-on-redeclaration"
extern "C" __declspec(dllimport) HRESULT WINAPI D3D11CreateDevice(
    IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL*,
    UINT, UINT, ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
#pragma clang diagnostic pop
// Intentionally not noreturn: the PE must retain a post-exit marker.
extern "C" __declspec(dllimport) void ExitProcess(DWORD);

static_assert(sizeof(void*) == 8 && sizeof(HRESULT) == 4 && sizeof(ULONG) == 4);
static_assert(sizeof(GUID) == 16 && sizeof(D3D11_TEXTURE2D_DESC) == 44);
static_assert(sizeof(D3D11_MAPPED_SUBRESOURCE) == 16);
static_assert(__builtin_offsetof(D3D11_MAPPED_SUBRESOURCE, RowPitch) == 8);
static_assert(__builtin_offsetof(D3D11_MAPPED_SUBRESOURCE, DepthPitch) == 12);

struct GraphicsResult {
  UINT stage, feature_level;
  HRESULT create_device_hr, create_target_hr, create_rtv_hr, create_staging_hr;
  HRESULT map_hr, device_removed_hr;
  UINT row_pitch, depth_pitch, pixels_checked, channels_checked;
  UINT mismatched_pixels, mismatched_channels, max_error;
  UINT clear_called, copy_called, unmap_called, released_objects, exit_code;
  UINT first_bad_x, first_bad_y, first_bad_channel, first_actual;
  HRESULT create_vs_hr, create_ps_hr, create_rasterizer_hr;
  UINT draw_called;
};
static_assert(sizeof(GraphicsResult) == 112);
static_assert(sizeof(D3D11_RASTERIZER_DESC) == 40 && sizeof(D3D11_VIEWPORT) == 24);

extern "C" {
volatile GraphicsResult graphics_result;
volatile UINT graphics_after_exit;
ID3D11Device *graphics_device;
ID3D11DeviceContext *graphics_context;
ID3D11Texture2D *graphics_target;
ID3D11RenderTargetView *graphics_rtv;
ID3D11Texture2D *graphics_staging;
ID3D11VertexShader *graphics_vs;
ID3D11PixelShader *graphics_ps;
ID3D11RasterizerState *graphics_rasterizer;
D3D11_MAPPED_SUBRESOURCE graphics_mapped;
D3D_FEATURE_LEVEL graphics_feature;
extern const D3D_FEATURE_LEVEL graphics_requested[] = {D3D_FEATURE_LEVEL_11_0};
extern const FLOAT graphics_clear[4] = {
    1.0f, 0.0f, 1.0f, 1.0f};
extern const UINT graphics_expected[4] = {0, 255, 0, 255};
extern const D3D11_TEXTURE2D_DESC graphics_target_desc = {
    32, 32, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0},
    D3D11_USAGE_DEFAULT, D3D11_BIND_RENDER_TARGET, 0, 0};
extern const D3D11_TEXTURE2D_DESC graphics_staging_desc = {
    32, 32, 1, 1, DXGI_FORMAT_R8G8B8A8_UNORM, {1, 0},
    D3D11_USAGE_STAGING, 0, D3D11_CPU_ACCESS_READ, 0};
extern const D3D11_RASTERIZER_DESC graphics_rasterizer_desc = {
    D3D11_FILL_SOLID, D3D11_CULL_NONE, FALSE, 0, 0.0f, 0.0f,
    TRUE, FALSE, FALSE, FALSE};
extern const D3D11_VIEWPORT graphics_viewport = {0.0f, 0.0f, 32.0f, 32.0f, 0.0f, 1.0f};
const void *graphics_image_anchor = &graphics_target_desc;
}

extern "C" void graphics_entry(void) {
  bool mapped = false;
  bool pixels_pass = false;
  do {
    graphics_result.stage = 1;
    HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        0, graphics_requested, 1, D3D11_SDK_VERSION, &graphics_device,
        &graphics_feature, &graphics_context);
    graphics_result.create_device_hr = hr;
    graphics_result.feature_level = graphics_feature;
    if (FAILED(hr) || !graphics_device || !graphics_context ||
        graphics_feature != D3D_FEATURE_LEVEL_11_0) break;
    graphics_result.stage = 2;
    hr = graphics_device->CreateTexture2D(&graphics_target_desc, nullptr,
                                         &graphics_target);
    graphics_result.create_target_hr = hr;
    if (FAILED(hr) || !graphics_target) break;
    graphics_result.stage = 3;
    hr = graphics_device->CreateRenderTargetView(graphics_target, nullptr,
                                                &graphics_rtv);
    graphics_result.create_rtv_hr = hr;
    if (FAILED(hr) || !graphics_rtv) break;
    graphics_result.stage = 4;
    hr = graphics_device->CreateTexture2D(&graphics_staging_desc, nullptr,
                                         &graphics_staging);
    graphics_result.create_staging_hr = hr;
    if (FAILED(hr) || !graphics_staging) break;
    graphics_result.stage = 5;
    hr = graphics_device->CreateVertexShader(kTriangleVsDxbc, sizeof kTriangleVsDxbc,
                                             nullptr, &graphics_vs);
    graphics_result.create_vs_hr = hr;
    if (FAILED(hr) || !graphics_vs) break;
    graphics_result.stage = 6;
    hr = graphics_device->CreatePixelShader(kTrianglePsDxbc, sizeof kTrianglePsDxbc,
                                            nullptr, &graphics_ps);
    graphics_result.create_ps_hr = hr;
    if (FAILED(hr) || !graphics_ps) break;
    graphics_result.stage = 7;
    hr = graphics_device->CreateRasterizerState(&graphics_rasterizer_desc, &graphics_rasterizer);
    graphics_result.create_rasterizer_hr = hr;
    if (FAILED(hr) || !graphics_rasterizer) break;
    graphics_result.stage = 8;
    graphics_context->ClearRenderTargetView(graphics_rtv, graphics_clear);
    graphics_result.clear_called = 1;
    graphics_context->OMSetRenderTargets(1, &graphics_rtv, nullptr);
    graphics_context->RSSetState(graphics_rasterizer);
    graphics_context->RSSetViewports(1, &graphics_viewport);
    graphics_context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    graphics_context->VSSetShader(graphics_vs, nullptr, 0);
    graphics_context->PSSetShader(graphics_ps, nullptr, 0);
    graphics_context->Draw(3, 0);
    graphics_result.draw_called = 1;
    graphics_context->CopyResource(graphics_staging, graphics_target);
    graphics_result.copy_called = 1;
    graphics_result.stage = 9;
    hr = graphics_context->Map(graphics_staging, 0, D3D11_MAP_READ, 0,
                                &graphics_mapped);
    graphics_result.map_hr = hr;
    if (FAILED(hr)) break;
    mapped = true;
    graphics_result.row_pitch = graphics_mapped.RowPitch;
    graphics_result.depth_pitch = graphics_mapped.DepthPitch;
    if (!graphics_mapped.pData || graphics_mapped.RowPitch < 128) break;
    graphics_result.stage = 10;
    const BYTE *data = static_cast<const BYTE*>(graphics_mapped.pData);
    for (UINT y = 0; y < 32; ++y) {
      const BYTE *row = data + static_cast<SIZE_T>(y) * graphics_mapped.RowPitch;
      for (UINT x = 0; x < 32; ++x) {
        bool bad_pixel = false;
        for (UINT channel = 0; channel < 4; ++channel) {
          UINT actual = row[x * 4 + channel], expected = graphics_expected[channel];
          UINT error = actual > expected ? actual - expected : expected - actual;
          if (error > graphics_result.max_error) graphics_result.max_error = error;
          if (error > 1) {
            if (graphics_result.mismatched_channels == 0) {
              graphics_result.first_bad_x = x; graphics_result.first_bad_y = y;
              graphics_result.first_bad_channel = channel;
              graphics_result.first_actual = actual;
            }
            ++graphics_result.mismatched_channels;
            bad_pixel = true;
          }
          ++graphics_result.channels_checked;
        }
        if (bad_pixel) ++graphics_result.mismatched_pixels;
        ++graphics_result.pixels_checked;
      }
    }
    pixels_pass = graphics_result.pixels_checked == 1024 &&
                  graphics_result.channels_checked == 4096 &&
                  graphics_result.mismatched_channels == 0;
  } while (false);

  if (mapped) {
    graphics_context->Unmap(graphics_staging, 0);
    graphics_result.unmap_called = 1;
  }
  if (graphics_device) {
    graphics_result.device_removed_hr = graphics_device->GetDeviceRemovedReason();
  }
  const bool passed = pixels_pass && graphics_result.draw_called && graphics_result.unmap_called &&
                      graphics_result.device_removed_hr == S_OK;
  // Release application references only; returned counts need not be zero.
  if (graphics_rasterizer) { graphics_rasterizer->Release(); graphics_rasterizer = nullptr; ++graphics_result.released_objects; }
  if (graphics_ps) { graphics_ps->Release(); graphics_ps = nullptr; ++graphics_result.released_objects; }
  if (graphics_vs) { graphics_vs->Release(); graphics_vs = nullptr; ++graphics_result.released_objects; }
  if (graphics_rtv) { graphics_rtv->Release(); graphics_rtv = nullptr; ++graphics_result.released_objects; }
  if (graphics_staging) { graphics_staging->Release(); graphics_staging = nullptr; ++graphics_result.released_objects; }
  if (graphics_target) { graphics_target->Release(); graphics_target = nullptr; ++graphics_result.released_objects; }
  if (graphics_context) { graphics_context->Release(); graphics_context = nullptr; ++graphics_result.released_objects; }
  if (graphics_device) { graphics_device->Release(); graphics_device = nullptr; ++graphics_result.released_objects; }
  graphics_result.exit_code = passed ? 0 : graphics_result.stage;
  if (passed) graphics_result.stage = 11;
  ExitProcess(graphics_result.exit_code);
  graphics_after_exit = 0xa5a55a5a;
}
