#ifndef PE_AOT_WINDOW_SWITCH_V1_RUNTIME_H
#define PE_AOT_WINDOW_SWITCH_V1_RUNTIME_H
/* Additional ABI for the separately admitted window-switch-v1 contract.
 * Including this header cannot enable a legacy runtime: its implementation
 * must be compiled with AOT_WINDOW_SWITCH_V1 and the corresponding hooks. */
#include "../window_bridge/window_runtime/runtime.h"

enum { AOT_SWITCH_JUMP=5, AOT_WINDOW_SWITCH_MAX_TARGETS=32 };

#ifdef __cplusplus
extern "C" {
#endif
/* Copies the finite, proof-derived targets. Exactly one kind-5 instruction is
 * allowed in the merged instruction map; normal CALL/RET and COM/IAT remain
 * owned by the existing window transaction engine. */
uint32_t aot_configure_switch(AotContext *,uint64_t,const uint64_t *,size_t);
/* Single-use binding after ALL region registrations and before any guest step.
 * Requires byte-for-byte table identity, exact READ page rights and ordered
 * signed-rel32 targets. A failed attempt permanently disables this context.
 * The single-threaded trusted host keeps backing and permissions stable after
 * binding. This does not defend against malicious/concurrent host mutation. */
uint32_t aot_bind_switch(AotContext *,uint64_t,const uint8_t *,size_t);
void *aot_switch_miss(void *,uint64_t,void *);
/* Read-only evidence counter. Only a successful committed kind-5 instruction
 * increments it; binding rejection, budget exhaustion and rollback do not. */
uint64_t aot_window_switch_commits(const AotContext *);
#ifdef __cplusplus
}
#endif
#endif
