#ifndef PE_AOT_WINDOW_PIXEL_OBSERVER_V1_H
#define PE_AOT_WINDOW_PIXEL_OBSERVER_V1_H
#include <stdint.h>

/* Trusted native-worker diagnostics only. No pointer here is a guest VA.
 * No observer interface may be exposed in the PE import/COM registry. */
enum { AOT_PIXEL_OBSERVER_VERSION=1, AOT_PIXEL_WIDTH=640, AOT_PIXEL_HEIGHT=360,
       AOT_PIXEL_RGBA_BYTES=640*360*4, AOT_PIXEL_MAX_FRAMES=64 };
enum AotPixelObserverError {
    AOT_PIXEL_OK=0, AOT_PIXEL_INVALID=1, AOT_PIXEL_BUSY=2,
    AOT_PIXEL_NOT_CONFIGURED=3, AOT_PIXEL_DIRECTORY=4,
    AOT_PIXEL_CAPACITY=5, AOT_PIXEL_ALLOCATION=6,
    AOT_PIXEL_GET_DEVICE=7, AOT_PIXEL_GET_CONTEXT=8,
    AOT_PIXEL_GET_BUFFER=9, AOT_PIXEL_DESCRIPTOR=10,
    AOT_PIXEL_CREATE_STAGING=11, AOT_PIXEL_MAP=12,
    AOT_PIXEL_MAP_LAYOUT=13, AOT_PIXEL_DEVICE_REMOVED=14,
    AOT_PIXEL_PRESENT=15, AOT_PIXEL_FILE=16
};
typedef struct {
    uint32_t version,size,max_frames,reserved;
    uint64_t max_total_rgba_bytes;
    const char *directory; /* dedicated, existing, empty, absolute directory */
} AotPixelObserverConfig;
typedef struct {
    uint32_t version,size,active,first_error;
    uint32_t first_errno,last_present_hr,reserved0,reserved1;
    uint64_t attempts,present_calls,captured_frames,records_written;
    uint64_t raw_bytes_written,rgba_bytes_reserved;
    uint64_t copy_calls,map_calls,unmap_calls;
    uint64_t refs_acquired,refs_released,live_refs,live_maps;
    uint64_t failures,capacity_rejections,unconfigured_calls,reentrant_calls;
} AotPixelObserverStats;
#ifdef __cplusplus
extern "C" {
#endif
/* Same owner worker: begin before guest execute; end after guest/native
 * cleanup. Repeated sessions require a fresh empty directory. Begin failures
 * do not start a session. No library loading or graphics call occurs here. */
uint32_t aot_window_observer_begin(const AotPixelObserverConfig *config);
/* Writes observer-summary.json and closes its directory FD even after an
 * earlier observation failure. Returns the first observer error, not a guest
 * status/HRESULT. Zero attempts alone is not a successful pixel test. */
uint32_t aot_window_observer_end(AotPixelObserverStats *out);
void aot_window_observer_stats(AotPixelObserverStats *out);
/* This definition exists only in the explicitly instrumented link. Exactly
 * one real Present is forwarded per call, including capture failures; the
 * original HRESULT is returned unchanged. All observer COM refs are released
 * before that Present. No cached staging/device/context references survive. */
uint32_t aot_window_native_present(void *swapchain,uint32_t interval,uint32_t flags);
#ifdef __cplusplus
}
#endif
#endif
