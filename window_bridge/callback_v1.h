#ifndef WINDOW_BRIDGE_CALLBACK_V1_H
#define WINDOW_BRIDGE_CALLBACK_V1_H
#include "runtime.h"

/* Trusted build-time root registration, never a guest/native pointer cast.
 * This version has one synchronous integer Win64 signature. Message queues,
 * HWND lifetime and the User32 contracts remain the caller's responsibility. */
enum { AOT_WINDOW_WNDPROC=1, AOT_WINDOW_MAX_CALLBACKS=16,
       AOT_WINDOW_MAX_CALLBACK_DEPTH=16 };
typedef struct { uint32_t rva,signature; AotEntry entry; } AotWindowCallback;
typedef struct {
    uint64_t calls,returns,rejections;
    uint32_t depth,max_depth;
} AotWindowCallbackStats;

/* Begin copies the table while the owning D3D/process session is idle and
 * unused. Failure changes neither registry nor Context. End is forbidden
 * during execution, and preserves the completed statistics for inspection. */
uint32_t aot_window_callbacks_begin(AotContext *,const AotWindowCallback *,size_t);
uint32_t aot_window_callbacks_end(AotContext *);
void aot_window_callback_stats(AotWindowCallbackStats *);

/* Internal typed dispatcher boundary. Only use from a committed import CALL
 * in the active owner session. Returns AOT_OK, the first guest fault, or
 * AOT_PROCESS_EXITED; out is written only on successful real callback RET.
 * The pointer out is trusted host storage disjoint from all guest backing,
 * runtime metadata, State and Context. UINT is deliberately only 32 bits;
 * HWND/WPARAM/LPARAM/LRESULT preserve all 64 bits without native pointer casts. */
uint32_t aot_wndproc_invoke(AotState *,AotContext *,uint64_t target,
    uint64_t hwnd,uint32_t message,uint64_t wparam,uint64_t lparam,uint64_t *out);
#endif
