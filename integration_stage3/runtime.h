#ifndef PE_AOT_STAGE3_RUNTIME_H
#define PE_AOT_STAGE3_RUNTIME_H
#include <stddef.h>
#include <stdint.h>
#include "../memory_stage2/guest_memory.h"

enum { AOT_STATE_SIZE=3504, AOT_STATE_ALIGN=16, AOT_MAX_REGIONS=16, AOT_MAX_CALLS=64 };
enum AotRegister { AOT_RAX, AOT_RCX, AOT_RDX, AOT_RBX, AOT_RSP, AOT_RBP,
    AOT_RSI, AOT_RDI, AOT_R8, AOT_R9, AOT_R10, AOT_R11, AOT_R12, AOT_R13,
    AOT_R14, AOT_R15, AOT_RIP };
enum { AOT_OK=0, AOT_BOUNDS=1, AOT_PROTECTION=2, AOT_INVALID=3,
    AOT_BUDGET=4, AOT_BAD_RETURN=5, AOT_BAD_INSTRUCTION=6,
    AOT_MULTIWRITE=7, AOT_CALL_DEPTH=8, AOT_UNSUPPORTED=9, AOT_NOT_RETURNED=10 };
enum { AOT_NORMAL=0, AOT_CALL=1, AOT_RET=2, AOT_EXEC=4 };
typedef struct __attribute__((aligned(16))) { uint8_t bytes[AOT_STATE_SIZE]; } AotState;
typedef struct { uint32_t rva; uint16_t length; uint8_t kind, reserved;
    uint64_t target_rva; } AotInstruction;
typedef struct { uint32_t status, access; uint64_t pc, address, width; } AotFault;
typedef struct { AotFault fault; uint64_t steps; uint32_t call_depth, returned; } AotResult;
typedef struct AotContext AotContext;
typedef void *(*AotEntry)(void *, uint64_t, void *);

AotState *aot_state_create(void);
void aot_state_destroy(AotState *);
uint64_t aot_get_register(const AotState *, uint32_t);
void aot_set_register(AotState *, uint32_t, uint64_t);
uint32_t aot_get_flags(const AotState *);
AotContext *aot_context_create(uint64_t, const AotInstruction *, size_t,
    uint64_t, uint64_t, uint64_t);
void aot_context_destroy(AotContext *);
uint32_t aot_add_region(AotContext *, const GuestMemory *);
void aot_result(const AotContext *, AotResult *);
uint32_t aot_execute(AotEntry, AotState *, AotContext *, uint64_t);

uint32_t aot_begin(void *, uint64_t, void *);
uint32_t aot_commit(void *, uint64_t, void *);
uint32_t aot_should_exit(void *);
#endif
