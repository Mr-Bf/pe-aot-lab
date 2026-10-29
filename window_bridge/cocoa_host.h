#ifndef PE_AOT_WINDOW_COCOA_HOST_H
#define PE_AOT_WINDOW_COCOA_HOST_H
#include <stdint.h>
#include "../native_window/native_wsi.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct WBHost WBHost;
enum { WB_ORIGIN_COCOA_KEY=1, WB_ORIGIN_COCOA_WINDOW=2,
       WB_ORIGIN_TEST_QUEUE=3, WB_ORIGIN_GUEST_QUEUE_API=4,
       WB_ORIGIN_FOCUS_RECOVERY=5 };
enum { WB_HOST_ERROR_NONE=0, WB_HOST_ERROR_STOPPED=1,
       WB_HOST_ERROR_QUEUE_FULL=2, WB_HOST_ERROR_BACKING_SCALE=3,
       WB_HOST_ERROR_WRONG_THREAD=4 };
enum { WB_DELIVERY_POSTED=0, WB_DELIVERY_SENT_NOTIFICATION=1 };
/* Native host value, NOT the Windows MSG memory layout. The runtime writes
 * the validated 48-byte Windows MSG separately. No field is a host pointer. */
typedef struct WBHostMessage {
    uint64_t hwnd;
    uint32_t message,origin;
    uint64_t wparam;
    int64_t lparam;
    uint32_t time_ms;
    int32_t screen_x,screen_y;
    uint32_t delivery;
    uint64_t sequence;
} WBHostMessage;
typedef struct WBHostFrameMetrics {
    int32_t left,top,right,bottom; /* positive device-pixel nonclient extents */
    double backing_scale; /* host diagnostic, never a guest ABI field */
} WBHostFrameMetrics;
typedef struct WBHostFocusChange { uint64_t before,after; } WBHostFocusChange;
typedef struct WBHostStats {
    uint64_t windows_created,windows_destroyed,forced_cleanup_windows;
    uint64_t views_created,views_released,active_views;
    uint64_t cocoa_key_events,cocoa_window_events,test_queue_events;
    uint64_t focus_recovery_events,guest_queue_events,ignored_keys;
    uint64_t messages_taken,waits,quit_messages,queue_overflows;
    uint64_t main_dispatches,event_pumps,close_requests,resize_events;
    uint64_t api_focus_transitions,sent_notifications;
    uint32_t pending_messages,error,stopped,worker_bound;
    uint32_t paint_invalid,tombstones;
} WBHostStats;
/* MAIN only. Single window, fixed caption/close style, no user resizing or
 * minimization. Activation uses the already-Regular-safe v3 condition.
 * Registry/callback owner lives until process teardown (WSI has no uninstall). */
WBHost *wb_host_create(void);
/* Exactly one non-main worker; second binding and calls from other workers
 * fail. Main must keep pumping until the bound worker has returned. */
int wb_host_bind_worker(WBHost *);
void wb_host_pump_once(WBHost *,double seconds); /* MAIN only */
/* Worker methods marshal Cocoa work to MAIN without holding the queue lock.
 * Creation is HIDDEN; guest creation callbacks remain the runtime's job.
 * Dimensions are outer window dimensions in the fixed virtual pixel space. */
int wb_host_frame_metrics(WBHost *,WBHostFrameMetrics *);
uint64_t wb_host_create_window(WBHost *,uint32_t outer_width,uint32_t outer_height,const char *ascii_title);
/* Explicit API focus changes suppress duplicate Cocoa notifications. Runtime
 * sends the returned KILLFOCUS/SETFOCUS synchronously before guest API return. */
int wb_host_show_window(WBHost *,uint64_t hwnd,int show,int *previous_visible,WBHostFocusChange *);
int wb_host_focus_window(WBHost *,uint64_t hwnd,WBHostFocusChange *);
int wb_host_client_size(WBHost *,uint64_t hwnd,uint32_t *width,uint32_t *height);
/* Actual outer RECT in fixed virtual device pixels: primary-screen top-left
 * is (0,0), right/bottom exclusive. Secondary screen or scale changes reject.
 * Windows DPI virtualization beyond this explicit profile is not provided. */
int wb_host_window_rect(WBHost *,uint64_t hwnd,int32_t rect[4]);
/* Called after synchronous guest WM_DESTROY/WM_NCDESTROY and COM cleanup.
 * Fails while a Metal view is active. Does not execute guest code. */
int wb_host_destroy_window(WBHost *,uint64_t hwnd);
int wb_host_validate_rect(WBHost *,uint64_t hwnd); /* whole client only */
/* Worker only: blocks without busy polling, wakes on message/quit/end/error.
 * 1=message, 0=actual WM_QUIT, -1=stop/error. No fabricated quit on end.
 * All pending SENT_NOTIFICATION records precede ordinary posted records
 * (including QUIT), for worker callbacks; never write them as a guest MSG.
 * WM_PAINT is synthesized only while invalid and ordinary FIFO is empty. */
int wb_host_get_message(WBHost *,WBHostMessage *);
/* Worker test/diagnostic: same main-thread timestamp/primary-screen cursor
 * conversion used at message creation. This does not enable mouse messages. */
int wb_host_input_snapshot(WBHost *,uint32_t *time_ms,int32_t point[2]);
int wb_host_post_quit(WBHost *,uint32_t exit_code); /* worker thread message */
/* Trusted test queue injection, not an OS keyboard event. Allowed messages:
 * KEYDOWN/KEYUP/CLOSE/SIZE. Its origin can never be COCOA_KEY. */
int wb_host_test_post(WBHost *,uint64_t hwnd,uint32_t message,uint64_t wparam,int64_t lparam);
void wb_host_callbacks(WBHost *,DXMTNativeWSIV1 *);
void wb_host_stats(WBHost *,WBHostStats *);
/* Any trusted host thread may end/wake the queue. No Cocoa destruction here.
 * End is permanent, idempotent, discards undelivered messages and makes all
 * future GetMessage return -1. Join worker, release D3D/views, then finish. */
void wb_host_session_end(WBHost *);
/* MAIN after worker joined: closes remaining native windows only if no active
 * views. Does not impersonate guest DestroyWindow callbacks. Owner retained. */
int wb_host_finish(WBHost *);
#ifdef __cplusplus
}
#endif
#endif
