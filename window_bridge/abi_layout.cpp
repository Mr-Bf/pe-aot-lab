// Build-time Windows x64 ABI facts from original headers; never host emulation.
#define WIN32_LEAN_AND_MEAN
#define CINTERFACE
#define D3D11_NO_HELPERS
#define D3D10_NO_HELPERS
#include <windows.h>
#include <d3d11.h>

#define SIZE(T) extern "C" const unsigned long long size_##T = sizeof(T)
#define OFFSET(T, F) extern "C" const unsigned long long offset_##T##_##F = __builtin_offsetof(T, F)
#define SLOT(T, F) extern "C" const unsigned long long slot_##T##_##F = __builtin_offsetof(T##Vtbl, F) / sizeof(void*)
static_assert(sizeof(void*) == 8 && sizeof(LONG) == 4 && sizeof(BOOL) == 4);
SIZE(WNDCLASSEXA); SIZE(MSG); SIZE(CREATESTRUCTA); SIZE(RECT); SIZE(POINT);
SIZE(WPARAM); SIZE(LPARAM); SIZE(LRESULT); SIZE(HWND); SIZE(DXGI_SWAP_CHAIN_DESC);
SIZE(DXGI_MODE_DESC); SIZE(D3D11_VIEWPORT); SIZE(GUID);
OFFSET(WNDCLASSEXA, lpfnWndProc); OFFSET(WNDCLASSEXA, hInstance);
OFFSET(WNDCLASSEXA, lpszClassName); OFFSET(WNDCLASSEXA, hIconSm);
OFFSET(MSG, hwnd); OFFSET(MSG, message); OFFSET(MSG, wParam); OFFSET(MSG, lParam);
// MinGW v12 names only the public fields. Unlike current Learn's declaration,
// it has no lPrivate member; sizeof still includes Windows x64 tail padding.
OFFSET(MSG, time); OFFSET(MSG, pt);
OFFSET(CREATESTRUCTA, lpCreateParams); OFFSET(CREATESTRUCTA, hInstance);
OFFSET(CREATESTRUCTA, hwndParent); OFFSET(CREATESTRUCTA, cy);
OFFSET(CREATESTRUCTA, style); OFFSET(CREATESTRUCTA, lpszName);
OFFSET(CREATESTRUCTA, lpszClass); OFFSET(CREATESTRUCTA, dwExStyle);
OFFSET(DXGI_SWAP_CHAIN_DESC, SampleDesc); OFFSET(DXGI_SWAP_CHAIN_DESC, BufferUsage);
OFFSET(DXGI_SWAP_CHAIN_DESC, BufferCount); OFFSET(DXGI_SWAP_CHAIN_DESC, OutputWindow);
OFFSET(DXGI_SWAP_CHAIN_DESC, Windowed); OFFSET(DXGI_SWAP_CHAIN_DESC, SwapEffect);
OFFSET(DXGI_SWAP_CHAIN_DESC, Flags);
SLOT(IDXGISwapChain, Release); SLOT(IDXGISwapChain, Present);
SLOT(IDXGISwapChain, GetBuffer); SLOT(IDXGISwapChain, ResizeBuffers);
SLOT(ID3D11DeviceContext, OMSetRenderTargets); SLOT(ID3D11DeviceContext, ClearState);
SLOT(ID3D11DeviceContext, Flush); SLOT(ID3D11DeviceContext, Draw);
SLOT(ID3D11Device, CreateRenderTargetView); SLOT(ID3D11Device, CreateVertexShader);
SLOT(ID3D11Device, CreatePixelShader); SLOT(ID3D11Device, CreateRasterizerState);
