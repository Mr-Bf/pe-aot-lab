#ifndef PE_AOT_PROCESS_BRIDGE_H
#define PE_AOT_PROCESS_BRIDGE_H
#include "../file_bridge/runtime.h"
/* A terminal outcome, never an AotFault and never a fabricated guest RET.
 * 0 denotes a normal function return; faults retain the stage3 status values.
 * The host must always end the file session to release owned resources. */
enum { AOT_PROCESS_EXITED=11 };
uint32_t aot_process_exit_requested(void);
uint32_t aot_process_exit_code(void);
uint64_t aot_process_exit_pc(void);
uint64_t aot_process_exit_rsp(void);
uint32_t aot_process_exit_depth(void);
/* Repeated here because the versioned C engine is compiled with private names. */
uint32_t aot_execute(AotEntry,AotState *,AotContext *,uint64_t);
uint32_t aot_should_exit(void *);
uint32_t aot_begin(void *,uint64_t,void *);
uint32_t aot_commit(void *,uint64_t,void *);
#endif
