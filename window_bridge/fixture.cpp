// A self-authored Windows x64 input -> integer state -> Draw -> save sample.
// Preparation only: no window_bridge runtime or guest execution exists yet.
// Windows declarations below come from pinned, unmodified MinGW headers.
#define WIN32_LEAN_AND_MEAN
#define D3D11_NO_HELPERS
#define D3D10_NO_HELPERS
#include <windows.h>
#include <d3d11.h>
#include "../graphics_stage5/shaders/draw_shaders.h"

// Match the upstream declaration exactly; add only PE import decoration.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdll-attribute-on-redeclaration"
extern "C" __declspec(dllimport) HRESULT WINAPI D3D11CreateDeviceAndSwapChain(
    IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL*,
    UINT, UINT, const DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**, ID3D11Device**,
    D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);
#pragma clang diagnostic pop

static_assert(sizeof(WNDCLASSEXA) == 80 && sizeof(MSG) == 48);
static_assert(sizeof(CREATESTRUCTA) == 80 && sizeof(DXGI_SWAP_CHAIN_DESC) == 72);
static_assert(sizeof(WPARAM) == 8 && sizeof(LPARAM) == 8 && sizeof(LRESULT) == 8);

struct SampleState {
  UINT magic, version, position, moves, draws;
};
struct Observations {
  UINT stage, exit_code, create_messages, keydowns, ignored_repeats, paints;
  UINT closes, destroys, presents, saves, saved_bytes, win32_error;
  HRESULT graphics_hr;
  UINT quit_requested, dirty;
};
extern "C" {
SampleState window_state = {0x31574f43, 1, 3, 0, 0}; // COW1, little-endian.
volatile Observations window_result;
HWND window_handle;
HINSTANCE window_instance;
IDXGISwapChain *window_swap;
ID3D11Device *window_device;
ID3D11DeviceContext *window_context;
ID3D11Texture2D *window_backbuffer;
ID3D11RenderTargetView *window_rtv;
ID3D11VertexShader *window_vs;
ID3D11PixelShader *window_ps;
ID3D11RasterizerState *window_raster;
MSG window_message;
RECT window_rectangle = {0, 0, 640, 360};
RECT window_client;
DXGI_SWAP_CHAIN_DESC window_swap_desc = {
  {640, 360, {0, 1}, DXGI_FORMAT_R8G8B8A8_UNORM,
   DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED, DXGI_MODE_SCALING_UNSPECIFIED},
  {1, 0}, DXGI_USAGE_RENDER_TARGET_OUTPUT, 2, nullptr, TRUE,
  DXGI_SWAP_EFFECT_FLIP_DISCARD, 0};
D3D_FEATURE_LEVEL window_feature;
const D3D_FEATURE_LEVEL window_features[] = {D3D_FEATURE_LEVEL_11_0};
const char window_class_name[] = "PeAotIntegerTileV1";
const char window_title[] = "PE AOT: arrows move, Esc saves";
const char window_save_name[] = "integer-tile.bin";
const FLOAT window_background[] = {0.125f, 0.125f, 0.125f, 1.0f};
const D3D11_RASTERIZER_DESC window_raster_desc = {
  D3D11_FILL_SOLID, D3D11_CULL_NONE, FALSE, 0, 0.0f, 0.0f,
  TRUE, FALSE, FALSE, FALSE};
// Indexing these constants needs no guest floating-point arithmetic.
const D3D11_VIEWPORT window_viewports[] = {
  {0.0f,140.0f,80.0f,80.0f,0.0f,1.0f},
  {80.0f,140.0f,80.0f,80.0f,0.0f,1.0f},
  {160.0f,140.0f,80.0f,80.0f,0.0f,1.0f},
  {240.0f,140.0f,80.0f,80.0f,0.0f,1.0f},
  {320.0f,140.0f,80.0f,80.0f,0.0f,1.0f},
  {400.0f,140.0f,80.0f,80.0f,0.0f,1.0f},
  {480.0f,140.0f,80.0f,80.0f,0.0f,1.0f},
  {560.0f,140.0f,80.0f,80.0f,0.0f,1.0f}};
}

extern "C" LRESULT CALLBACK window_proc(HWND hwnd, UINT message,
                                        WPARAM key, LPARAM detail) {
  switch (message) {
    case WM_NCCREATE:
      ++window_result.create_messages;
      return TRUE;
    case WM_CREATE:
      ++window_result.create_messages;
      return 0;
    case WM_ERASEBKGND:
      return 1; // Every rendered frame clears the entire render target.
    case WM_PAINT:
      if (!ValidateRect(hwnd, nullptr)) {
        window_result.win32_error = GetLastError();
        window_result.exit_code = 20;
        window_result.quit_requested = 1;
      }
      ++window_result.paints;
      window_result.dirty = 1;
      return 0;
    case WM_KEYDOWN:
      ++window_result.keydowns;
      if ((static_cast<ULONG_PTR>(detail) & (ULONG_PTR(1) << 30)) != 0) {
        ++window_result.ignored_repeats;
        return 0;
      }
      if (key == VK_ESCAPE) window_result.quit_requested = 1;
      if (key == VK_LEFT && window_state.position != 0) {
        --window_state.position; ++window_state.moves; window_result.dirty = 1;
      }
      if (key == VK_RIGHT && window_state.position != 7) {
        ++window_state.position; ++window_state.moves; window_result.dirty = 1;
      }
      return 0;
    case WM_CLOSE:
      ++window_result.closes;
      window_result.quit_requested = 1; // Main releases the swapchain first.
      return 0;
    case WM_DESTROY:
      ++window_result.destroys;
      PostQuitMessage(static_cast<int>(window_result.exit_code));
      return 0;
    default:
      // The runtime must implement the admitted default-message contract.
      // An unknown message may not silently receive a fabricated success.
      return DefWindowProcA(hwnd, message, key, detail);
  }
}

static WNDCLASSEXA window_class = {
  sizeof(WNDCLASSEXA), 0, window_proc, 0, 0, nullptr, nullptr, nullptr,
  nullptr, nullptr, window_class_name, nullptr};

static bool initialize_graphics() {
  window_swap_desc.OutputWindow = window_handle;
  HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE,
      nullptr, 0, window_features, 1, D3D11_SDK_VERSION, &window_swap_desc,
      &window_swap, &window_device, &window_feature, &window_context);
  window_result.graphics_hr = hr;
  if (FAILED(hr) || !window_swap || !window_device || !window_context ||
      window_feature != D3D_FEATURE_LEVEL_11_0) return false;
  // Exactly one GetBuffer application reference in this first profile.
  hr = window_swap->GetBuffer(0, __uuidof(ID3D11Texture2D),
                             reinterpret_cast<void**>(&window_backbuffer));
  if (SUCCEEDED(hr)) hr = window_device->CreateRenderTargetView(window_backbuffer,
                                                               nullptr, &window_rtv);
  if (SUCCEEDED(hr)) hr = window_device->CreateVertexShader(kTriangleVsDxbc,
      sizeof kTriangleVsDxbc, nullptr, &window_vs);
  if (SUCCEEDED(hr)) hr = window_device->CreatePixelShader(kTrianglePsDxbc,
      sizeof kTrianglePsDxbc, nullptr, &window_ps);
  if (SUCCEEDED(hr)) hr = window_device->CreateRasterizerState(&window_raster_desc,
                                                             &window_raster);
  window_result.graphics_hr = hr;
  return SUCCEEDED(hr) && window_backbuffer && window_rtv && window_vs &&
         window_ps && window_raster;
}

static bool render_frame() {
  if (window_state.position > 7) return false;
  window_context->ClearRenderTargetView(window_rtv, window_background);
  // Flip-model Present unbinds the backbuffer: rebind it on every frame.
  window_context->OMSetRenderTargets(1, &window_rtv, nullptr);
  window_context->RSSetState(window_raster);
  window_context->RSSetViewports(1, &window_viewports[window_state.position]);
  window_context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
  window_context->VSSetShader(window_vs, nullptr, 0);
  window_context->PSSetShader(window_ps, nullptr, 0);
  window_context->Draw(3, 0);
  ++window_state.draws;
  HRESULT hr = window_swap->Present(0, 0);
  window_result.graphics_hr = hr;
  ++window_result.presents;
  return SUCCEEDED(hr);
}

static void release_graphics() {
  // Context-held references also matter for DXGI backbuffer/view lifetime.
  if (window_context) { window_context->ClearState(); window_context->Flush(); }
  if (window_raster) { window_raster->Release(); window_raster = nullptr; }
  if (window_ps) { window_ps->Release(); window_ps = nullptr; }
  if (window_vs) { window_vs->Release(); window_vs = nullptr; }
  if (window_rtv) { window_rtv->Release(); window_rtv = nullptr; }
  if (window_backbuffer) { window_backbuffer->Release(); window_backbuffer = nullptr; }
  if (window_swap) { window_swap->Release(); window_swap = nullptr; }
  if (window_context) { window_context->Release(); window_context = nullptr; }
  if (window_device) { window_device->Release(); window_device = nullptr; }
}

static bool save_state() {
  HANDLE file = CreateFileA(window_save_name, GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    window_result.win32_error = GetLastError();
    return false;
  }
  DWORD count = 0;
  BOOL written = WriteFile(file, &window_state, sizeof window_state, &count, nullptr);
  if (!written) window_result.win32_error = GetLastError();
  BOOL closed = CloseHandle(file);
  if (!closed) window_result.win32_error = GetLastError();
  window_result.saved_bytes = count;
  ++window_result.saves;
  return written && count == sizeof window_state && closed;
}

extern "C" void window_entry() {
  window_result.stage = 1;
  window_instance = GetModuleHandleA(nullptr);
  window_class.hInstance = window_instance;
  if (!window_instance || !RegisterClassExA(&window_class)) {
    window_result.win32_error = GetLastError(); ExitProcess(1);
  }
  const DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
  if (!AdjustWindowRectEx(&window_rectangle, style, FALSE, 0)) {
    window_result.win32_error = GetLastError(); ExitProcess(2);
  }
  window_handle = CreateWindowExA(0, window_class_name, window_title, style,
      CW_USEDEFAULT, CW_USEDEFAULT,
      window_rectangle.right - window_rectangle.left,
      window_rectangle.bottom - window_rectangle.top,
      nullptr, nullptr, window_instance, nullptr);
  if (!window_handle) { window_result.win32_error = GetLastError(); ExitProcess(3); }
  window_result.stage = 2;
  if (!GetClientRect(window_handle, &window_client) ||
      window_client.left != 0 || window_client.top != 0 ||
      window_client.right != 640 || window_client.bottom != 360) {
    window_result.exit_code = 4;
    window_result.win32_error = GetLastError();
    window_result.quit_requested = 1;
  } else if (!initialize_graphics()) {
    window_result.exit_code = 5; window_result.quit_requested = 1;
  }
  // ShowWindow's BOOL is previous visibility, not a success/failure indicator.
  ShowWindow(window_handle, SW_SHOW);
  SetFocus(window_handle);
  window_result.dirty = 1;
  window_result.stage = 3;
  for (;;) {
    if (window_result.quit_requested) {
      if (window_result.exit_code == 0 && !save_state()) window_result.exit_code = 6;
      release_graphics();
      if (!DestroyWindow(window_handle)) {
        window_result.win32_error = GetLastError(); ExitProcess(7);
      }
      window_handle = nullptr;
      window_result.stage = 4;
      // DestroyWindow synchronously sends WM_DESTROY; that callback posted QUIT.
      // Other queued messages may precede QUIT. Do not assume it is next.
      BOOL last;
      while ((last = GetMessageA(&window_message, nullptr, 0, 0)) > 0)
        DispatchMessageA(&window_message);
      if (last == -1 || window_message.message != WM_QUIT) ExitProcess(8);
      break;
    }
    if (window_result.dirty) {
      window_result.dirty = 0;
      if (!render_frame()) { window_result.exit_code = 9; window_result.quit_requested = 1; continue; }
    }
    BOOL got = GetMessageA(&window_message, nullptr, 0, 0);
    if (got == -1) {
      window_result.win32_error = GetLastError();
      window_result.exit_code = 10; window_result.quit_requested = 1; continue;
    }
    if (got == 0) { // An externally posted QUIT still requires resource cleanup.
      if (!save_state()) window_result.exit_code = 6;
      release_graphics();
      if (window_handle && !DestroyWindow(window_handle)) window_result.exit_code = 7;
      window_handle = nullptr;
      break;
    }
    DispatchMessageA(&window_message);
  }
  if (!UnregisterClassA(window_class_name, window_instance)) {
    window_result.win32_error = GetLastError(); window_result.exit_code = 11;
  }
  window_result.stage = 5;
  ExitProcess(window_result.exit_code);
}
