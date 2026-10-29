#ifndef PE_AOT_CALLBACK_BRIDGE_H
#define PE_AOT_CALLBACK_BRIDGE_H
#include "../native_bridge/runtime.h"
uint64_t aot_bridge_callback_calls(void);
uint64_t aot_bridge_callback_returns(void);
uint32_t aot_bridge_max_callback_depth(void);
#endif
