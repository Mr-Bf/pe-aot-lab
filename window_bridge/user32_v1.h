#ifndef PE_AOT_WINDOW_USER32_V1_H
#define PE_AOT_WINDOW_USER32_V1_H
#include "window_runtime/runtime.h"
#include "cocoa_host.h"

/* Trusted host configuration; the scratch region is a separate, exactly RW
 * guest page. CREATESTRUCT/RECT are written there, never on a native stack. */
typedef struct { WBHost *host;uint64_t scratch_base,scratch_size; } AotUser32Config;
typedef struct {
    uint64_t api_calls[14]; /* 0=GetModuleHandleA; 1..13=signatures 210..222 */
    /* callbacks counts invocation attempts; callback engine reports actual calls/returns. */
    uint64_t callbacks,sent_notifications,posted_dispatches,discarded_stale;
    uint64_t classes_registered,classes_unregistered,windows_created,windows_destroyed;
    uint32_t registered,window_state; /* 0=none,1=creating,2=live,3=destroying,4=dead */
    uint64_t hwnd;
} AotUser32Stats;
#ifdef __cplusplus
extern "C" {
#endif
uint32_t aot_user32_session_begin(AotContext *,const AotUser32Config *);
uint32_t aot_user32_session_end(AotContext *);
void aot_user32_stats(AotUser32Stats *);
#ifdef __cplusplus
}
#endif
#endif
