#ifndef PE_AOT_WINDOW_SWAPCHAIN_NATIVE_BACKEND_V1_H
#define PE_AOT_WINDOW_SWAPCHAIN_NATIVE_BACKEND_V1_H
#include "native_backend.h"

/* Trusted host values, decoded and validated by the guest runtime. This is
 * not a guest memory overlay. hwnd_token is a checked numeric WSI registry
 * token, not an NSWindow pointer or an arbitrary guest-provided host pointer. */
typedef struct {
    uint32_t width,height,refresh_numerator,refresh_denominator,format;
    uint32_t scanline_ordering,scaling,sample_count,sample_quality;
    uint32_t buffer_usage,buffer_count;
    uint64_t hwnd_token;
    uint32_t windowed,swap_effect,flags;
} AotWindowNativeSwapDesc;

#ifdef __cplusplus
extern "C" {
#endif
/* Caller preflights all guest outputs and reserves registry slots before
 * entering these functions. Non-null output pointers returned by the backend
 * carry native application references, including an anomalous failure result;
 * the caller must publish or release each exactly once. No implicit anchors. */
uint32_t aot_window_native_create_device_swapchain(
    const AotWindowNativeSwapDesc *desc,void **swapchain,void **device,
    uint32_t *level,void **context);
/* iid contains the actual copied guest GUID bytes. Runtime limits this first
 * profile to buffer 0 / ID3D11Texture2D / one successful acquisition per chain.
 * actual_desc comes from the real returned texture's GetDesc, not a fabricated
 * substitute. It is zero on failure or a null success pointer. */
uint32_t aot_window_native_get_buffer(void *swapchain,uint32_t buffer,
    const uint8_t iid[16],void **texture,uint32_t actual_desc[11]);
uint32_t aot_window_native_present(void *swapchain,uint32_t interval,uint32_t flags);
void aot_window_native_clear_state(void *context);
void aot_window_native_flush(void *context);
uint32_t aot_window_native_release_swap(void *swapchain);
#ifdef __cplusplus
}
#endif
#endif
