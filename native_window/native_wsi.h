#ifndef PE_AOT_NATIVE_WSI_V1_H
#define PE_AOT_NATIVE_WSI_V1_H
#include <stdint.h>
/* Project-owned native-only ABI, not Wine/macdrv. No pointer in this interface
 * is a guest address except the numeric window_handle. All other pointers and
 * callbacks are trusted host components with process lifetime. */
#define DXMT_NATIVE_WSI_VERSION 1u
enum { DXMT_WSI_VISIBLE=1u,DXMT_WSI_MINIMIZED=2u,DXMT_WSI_FOREGROUND=4u };
typedef struct DXMTNativeWindowInfoV1 {
    uint32_t size,width_pixels,height_pixels,flags;
} DXMTNativeWindowInfoV1;
typedef struct DXMTNativeWSIV1 {
    uint32_t version,size;
    void *user;
    /* Return exactly 1 on success, 0 for invalid/tombstoned handle or failure.
     * Query must validate numeric identity before touching any Cocoa object.
     * Width/height are actual backing pixels, not Cocoa points. Query may be
     * called from any native thread; main-thread dispatch must keep pumping. */
    int (*query)(void *user,uint64_t window_handle,DXMTNativeWindowInfoV1 *out);
    int (*resize)(void *user,uint64_t window_handle,uint32_t width_pixels,uint32_t height_pixels);
    /* Return a unique nonzero native token on success, zero on failure.
     * Host registry owns/retains the view and layer until release_metal_view.
     * out_layer is borrowed for that lifetime; DXMT balances any extra retain.
     * On failure set out_layer=0 and keep no active token/resource.
     * device is a native MTLDevice pointer, never obtained from guest memory. */
    uintptr_t (*create_metal_view)(void *user,uint64_t window_handle,uintptr_t device,uintptr_t *out_layer);
    /* Validate token against host registry; no arbitrary pointer dereference.
     * Successful tokens are released exactly once by this backend. Duplicate
     * release is rejected by the registry (and can be reported in host stats). */
    void (*release_metal_view)(void *user,uintptr_t view_token);
} DXMTNativeWSIV1;
#ifdef __cplusplus
extern "C" {
#endif
/* 1=installed; 0=wrong version/size/missing callbacks/already installed.
 * Copies the table once. No uninstall/replacement in v1. Host callback code and
 * user storage must remain valid until process teardown, after all views end.
 * Host window close first requests stop; only after the swapchain has released
 * its view token may the window be destroyed and the handle tombstoned. */
int DXMTNativeInstallWSIV1(const DXMTNativeWSIV1 *callbacks);
/* Same boolean status as query; output is zeroed on failure except size.
 * Exported for native DXMT's WSI and host negative checks, not for guest calls. */
int DXMTNativeQueryWindowV1(uint64_t window_handle,DXMTNativeWindowInfoV1 *out);
int DXMTNativeResizeWindowV1(uint64_t window_handle,uint32_t width_pixels,uint32_t height_pixels);
#ifdef __cplusplus
}
#endif
#endif
