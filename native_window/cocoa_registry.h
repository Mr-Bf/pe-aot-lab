#ifndef PE_AOT_COCOA_REGISTRY_H
#define PE_AOT_COCOA_REGISTRY_H
#include <stdint.h>
#include "native_wsi.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct NWRegistry NWRegistry;
typedef struct NWRegistryStats {
  uint32_t windows_created, windows_destroyed, queries, query_rejections;
  uint32_t resizes, resize_rejections, views_created, views_released;
  uint32_t view_rejections, release_rejections, active_views, close_requests;
  uint32_t main_dispatches, event_pumps, visible_observations, main_thread_violations;
  uint32_t width_pixels, height_pixels, window_number, tombstones;
  double backing_scale;
} NWRegistryStats;
/* Main-thread lifecycle; callback methods dispatch Cocoa work to that thread. */
NWRegistry *nw_registry_create(void);
uint64_t nw_window_create(NWRegistry *,uint32_t width_pixels,uint32_t height_pixels);
int nw_window_destroy(NWRegistry *,uint64_t handle);
void nw_callbacks(NWRegistry *,DXMTNativeWSIV1 *);
void nw_pump_once(NWRegistry *,double seconds);
void nw_request_close(NWRegistry *,uint64_t handle);
int nw_stop_requested(NWRegistry *);
void nw_stats(NWRegistry *,NWRegistryStats *);
/* Registry/callback owner intentionally remains alive until process teardown. */
#ifdef __cplusplus
}
#endif
#endif
