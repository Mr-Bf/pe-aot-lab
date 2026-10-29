#ifndef PE_AOT_WINDOW_BRIDGE_RUNTIME_H
#define PE_AOT_WINDOW_BRIDGE_RUNTIME_H
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
enum { AOT_NORMAL=0, AOT_CALL=1, AOT_RET=2, AOT_VTABLE_CALL=3, AOT_REGISTER_CALL=4, AOT_EXEC=4 };
enum { AOT_PROCESS_EXITED=11, AOT_BAD_OBJECT=12, AOT_BAD_METHOD=13, AOT_REFCOUNT=14,
    AOT_BACKEND=15, AOT_MAP_STATE=16, AOT_CAPACITY=17 };
enum { AOT_D3D_PROXY_STRIDE=16, AOT_D3D_MAX_OBJECTS=32, AOT_D3D_MAX_MAPS=32,
    AOT_D3D_KIND_COUNT=7, AOT_D3D_METHOD_COUNT=18, AOT_D3D_MAX_MAP_BYTES=1024*1024 };
enum { AOT_D3D_DEVICE=1, AOT_D3D_CONTEXT=2, AOT_D3D_TEXTURE2D=3, AOT_D3D_RTV=4,
    AOT_D3D_VS=5, AOT_D3D_PS=6, AOT_D3D_RASTER=7 };
enum { AOT_D3D_RELEASE=0, AOT_D3D_CREATE_TEXTURE=1, AOT_D3D_CREATE_RTV=2,
    AOT_D3D_GET_REMOVED=3, AOT_D3D_CLEAR=4, AOT_D3D_COPY=5,
    AOT_D3D_MAP=6, AOT_D3D_UNMAP=7,
    AOT_D3D_CREATE_VS=8, AOT_D3D_CREATE_PS=9, AOT_D3D_CREATE_RASTER=10,
    AOT_D3D_OM_SET=11, AOT_D3D_RS_SET=12, AOT_D3D_VIEWPORT=13,
    AOT_D3D_TOPOLOGY=14, AOT_D3D_VS_SET=15, AOT_D3D_PS_SET=16, AOT_D3D_DRAW=17 };
enum { AOT_D3D_SIG_CREATE_DEVICE=100, AOT_D3D_SIG_RELEASE=101,
    AOT_D3D_SIG_CREATE_TEXTURE=110, AOT_D3D_SIG_CREATE_RTV=111,
    AOT_D3D_SIG_GET_REMOVED=112, AOT_D3D_SIG_CLEAR=120,
    AOT_D3D_SIG_COPY=121, AOT_D3D_SIG_MAP=122, AOT_D3D_SIG_UNMAP=123,
    AOT_D3D_SIG_CREATE_VS=130, AOT_D3D_SIG_CREATE_PS=131, AOT_D3D_SIG_CREATE_RASTER=132,
    AOT_D3D_SIG_OM_SET=140, AOT_D3D_SIG_RS_SET=141, AOT_D3D_SIG_VIEWPORT=142,
    AOT_D3D_SIG_TOPOLOGY=143, AOT_D3D_SIG_VS_SET=144, AOT_D3D_SIG_PS_SET=145, AOT_D3D_SIG_DRAW=146 };

/* Callsite slot is static; interface kind and signature are resolved from the
 * registered guest object before committing the real guest CALL. */
typedef struct { uint32_t call_rva,base_register,slot; } AotVirtualCall;
/* Register CALL metadata contains no fabricated static target or signature. */
typedef struct { uint32_t call_rva,operand_register; } AotRegisterCall;
typedef struct { uint32_t target_rva,signature; } AotImportTarget;
typedef struct {
    uint64_t proxy_base;
    uint32_t proxy_count,reserved;
    uint64_t vtable_va[AOT_D3D_KIND_COUNT],method_targets[AOT_D3D_METHOD_COUNT];
    uint64_t map_base,map_capacity;
} AotD3DConfig;
typedef struct {
    uint64_t create_device_calls,create_texture_calls,create_rtv_calls;
    uint64_t clear_calls,copy_calls,map_calls,unmap_calls,get_removed_calls;
    uint64_t release_calls,exit_calls,this_checks,created,guest_released;
    uint64_t cleanup_releases,cleanup_unmaps,map_bytes_copied,map_postcall_failures;
    uint64_t create_vs_calls,create_ps_calls,create_rasterizer_calls;
    uint64_t om_set_calls,rs_set_calls,viewport_calls,topology_calls,vs_set_calls,ps_set_calls,draw_calls;
    uint32_t live_objects,active_maps,last_native_release,reserved;
} AotD3DStats;
typedef struct __attribute__((aligned(16))) { uint8_t bytes[AOT_STATE_SIZE]; } AotState;
typedef struct { uint32_t rva; uint16_t length; uint8_t kind,reserved;
    uint64_t target_rva; } AotInstruction;
typedef struct { uint32_t status,access; uint64_t pc,address,width; } AotFault;
typedef struct { AotFault fault; uint64_t steps; uint32_t call_depth,returned; } AotResult;
typedef struct AotContext AotContext;
typedef void *(*AotEntry)(void *,uint64_t,void *);

#ifdef __cplusplus
extern "C" {
#endif
AotState *aot_state_create(void);
void aot_state_destroy(AotState *);
uint64_t aot_get_register(const AotState *,uint32_t);
void aot_set_register(AotState *,uint32_t,uint64_t);
uint32_t aot_get_flags(const AotState *);
AotContext *aot_context_create(uint64_t,const AotInstruction *,size_t,uint64_t,uint64_t,uint64_t);
void aot_context_destroy(AotContext *);
uint32_t aot_add_region(AotContext *,const GuestMemory *);
void aot_result(const AotContext *,AotResult *);
uint32_t aot_execute(AotEntry,AotState *,AotContext *,uint64_t);
uint32_t aot_begin(void *,uint64_t,void *);
uint32_t aot_commit(void *,uint64_t,void *);
uint32_t aot_should_exit(void *);
uint32_t aot_d3d_session_begin(AotContext *,const AotD3DConfig *);
/* Returns native Release calls added by this end operation. Stats remain
 * cumulative, including cleanup after earlier failed API calls. The context
 * must stay alive until session_end completes, then context_destroy frees its
 * privately owned map permission overlay. */
uint32_t aot_d3d_session_end(void);
void aot_d3d_stats(AotD3DStats *);
uint32_t aot_process_exit_requested(void);
uint32_t aot_process_exit_code(void);
uint64_t aot_process_exit_pc(void);
uint64_t aot_process_exit_rsp(void);
uint32_t aot_process_exit_depth(void);
/* Shared LastError and real files for the single guest/UI thread. */
uint32_t aot_file_session_begin(const char *);
uint32_t aot_file_session_end(void);
uint32_t aot_file_last_error(void);
uint32_t aot_file_open_handles(void);
uint64_t aot_file_api_calls(uint32_t);
uint64_t aot_file_bytes_read(void);
uint64_t aot_file_bytes_written(void);
uint32_t aot_file_cleanup_closes(void);
uint32_t aot_file_cleanup_errors(void);
#ifdef __cplusplus
}
#endif
#endif
