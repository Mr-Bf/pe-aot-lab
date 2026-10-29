/* Restricted synchronous guest D3D11 boundary. Native pointers stay in the
 * private host object table; guest COM and Map pointers are explicit VAs. */
#include "runtime.h"
#include "../native_backend_window.h"
#include "../../graphics_stage5/shaders/draw_shaders.h"
#include <stdbool.h>
static bool d3d_validate_call(AotState *,AotContext *,uint64_t);
static bool import_validate_call(AotState *,AotContext *,uint64_t);
/* Implemented by the separately versioned User32 include. A live guest HWND
 * is the same checked numeric token used by the native WSI registry. */
static bool wui_window_contract(AotContext *,uint64_t,uint32_t,uint32_t);
#define __remill_function_call aot_rejected_function_call
#define aot_execute aot_execute_engine
#define aot_should_exit aot_engine_should_exit
#define aot_begin aot_engine_begin
#define aot_commit aot_engine_commit
#include "transaction_v1.c"
#undef aot_commit
#undef aot_begin
#undef aot_should_exit
#undef aot_execute
#undef __remill_function_call

typedef struct { uint32_t call_rva,iat_rva,target_rva,signature; } AotImportCall;
#include "native_imports.h"
#ifndef AOT_REGISTER_CALL_COUNT
#define AOT_REGISTER_CALL_COUNT 0
static const AotRegisterCall aot_register_calls[]={{0,0}};
#endif
#ifndef AOT_IMPORT_TARGET_COUNT
#define AOT_IMPORT_TARGET_COUNT 0
static const AotImportTarget aot_import_targets[]={{0,0}};
#endif
#include "../file_api.inc"
extern void *aot_import_ret(void *,uint64_t,void *);
typedef struct {
    uint64_t proxy;
    void *native;
    uint32_t kind,device,resource,desc[11];
    uint32_t buffer_acquired; /* one successful GetBuffer for this chain's lifetime */
    uint32_t swapchain_plus_one,context_index;
    uint64_t window_handle;
} ObjectSlot;
typedef struct {
    uint32_t active,object,context,reserved;
    uint64_t offset,size;
} MapSlot;
typedef struct {
    uint32_t flags,rtv,vs,ps,rasterizer;
    /* Present invalidates the admitted OM state. Keep a separate conservative
     * native binding record until ClearState/rebind; do not infer native COM
     * reference release from the profile's Draw-validity bit. */
    uint32_t native_rtv_bound;
} PipelineState;
typedef struct {
    uint32_t configured,running,used,next_slot,map_count;
    uintptr_t context_identity,state_identity; /* compared, not dereferenced */
    AotD3DConfig config;
    AotD3DStats stats;
    ObjectSlot objects[AOT_D3D_MAX_OBJECTS];
    MapSlot maps[AOT_D3D_MAX_MAPS];
    PipelineState pipelines[AOT_D3D_MAX_OBJECTS];
    uint64_t arena_next;
    uint8_t *cleanup_permissions; /* separate allocation, used only outside execute */
    size_t cleanup_page_count;
    uint32_t exit_requested,exit_code,exit_depth;
    uint64_t exit_pc,exit_rsp;
} D3DSession;
static _Thread_local D3DSession session;
static _Thread_local uint32_t window_files_ready;
static const uint32_t method_signatures[AOT_D3D_METHOD_COUNT]={101,110,111,112,120,121,122,123,130,131,132,140,141,142,143,144,145,146,150,151,152,153};
static const uint32_t vtable_slots[AOT_D3D_KIND_COUNT]={43,115,11,9,7,7,8,18};

uint32_t aot_file_session_begin(const char *directory) {
    if(session.running || window_files_ready)return WFILE_INVALID_PARAMETER;
    uint32_t error=wfile_begin(directory);if(!error)window_files_ready=1;return error;
}
uint32_t aot_file_session_end(void) {
    if(session.running || !window_files_ready)return 0;
    uint32_t count=wfile_end();window_files_ready=0;return count;
}
uint32_t aot_file_last_error(void){return wfile_get_last_error();}
uint32_t aot_file_open_handles(void){return wfile_open_handles();}
uint64_t aot_file_api_calls(uint32_t signature){return wfile_api_calls(signature);}
uint64_t aot_file_bytes_read(void){return wfile_bytes_read();}
uint64_t aot_file_bytes_written(void){return wfile_bytes_written();}
uint32_t aot_file_cleanup_closes(void){return wfile_cleanup_closes();}
uint32_t aot_file_cleanup_errors(void){return wfile_cleanup_errors();}

static bool overlap64(uint64_t a,uint64_t n,uint64_t b,uint64_t m) {
    return n && m && (a<=b?b-a<n:a-b<m);
}
static bool host_overlap(uintptr_t a,size_t n,uintptr_t b,size_t m) {
    return n && m && (a<=b?b-a<n:a-b<m);
}
static bool bridge_memory_valid(AotState *s,AotContext *ctx) {
    uintptr_t state=(uintptr_t)s,context=(uintptr_t)ctx,table=(uintptr_t)ctx->instructions;
    size_t table_size=ctx->instruction_count*sizeof(AotInstruction);
    if(host_overlap(state,sizeof *s,context,sizeof *ctx) || host_overlap(state,sizeof *s,table,table_size))return false;
    for(size_t i=0;i<ctx->region_count;i++) {
        GuestMemory *r=&ctx->regions[i];if(!gm_valid(r))return false;
        uintptr_t bytes=(uintptr_t)r->bytes,perms=(uintptr_t)r->permissions;
        if(r->size>UINTPTR_MAX-bytes || r->page_count>UINTPTR_MAX-perms)return false;
        if(host_overlap(bytes,r->size,state,sizeof *s) || host_overlap(bytes,r->size,context,sizeof *ctx) ||
           host_overlap(bytes,r->size,table,table_size) || host_overlap(perms,r->page_count,state,sizeof *s) ||
           host_overlap(perms,r->page_count,context,sizeof *ctx) || host_overlap(perms,r->page_count,table,table_size))return false;
        for(size_t p=0;p<r->page_count;p++)if((r->permissions[p]&~7u) ||
            (r->permissions[p]&(GM_WRITE|AOT_EXEC))==(GM_WRITE|AOT_EXEC))return false;
        for(size_t j=0;j<ctx->region_count;j++)if(host_overlap(bytes,r->size,(uintptr_t)ctx->regions[j].permissions,ctx->regions[j].page_count))return false;
    }
    return true;
}
/* Pure configuration/identity read. Never alters first-fault state. Every byte
 * must have exactly the requested guest permission, not merely a superset. */
static bool exact_plan(AotContext *ctx,uint64_t address,unsigned width,uint8_t permissions,AccessPlan *plan) {
    if(!ctx || !width || width>16 || address>UINT64_MAX-(width-1))return false;
    for(unsigned i=0;i<width;i++) {
        const GuestMemory *found=NULL;
        for(size_t j=0;j<ctx->region_count;j++) {
            const GuestMemory *r=&ctx->regions[j];
            if(address+i>=r->base && address+i-r->base<r->size){found=r;break;}
        }
        if(!found)return false;
        size_t off=(size_t)(address+i-found->base);
        if(found->permissions[off/GM_PAGE]!=permissions)return false;
        plan->byte[i]=found->bytes+off;
    }
    return true;
}
static uint64_t plan_u64(const AccessPlan *p) {
    uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)*p->byte[i]<<(8*i);return v;
}
static void put_plan(const AccessPlan *p,uint64_t v) {
    for(unsigned i=0;i<8;i++)*p->byte[i]=(uint8_t)(v>>(8*i));
}
static bool read_u64(AotContext *ctx,uint64_t address,uint64_t *v) {
    AccessPlan p;if(!plan_access(ctx,address,8,GM_READ,&p))return false;*v=plan_u64(&p);return true;
}


static void plan_write(const AccessPlan *plan,const void *bytes,unsigned size) {
    const uint8_t *data=bytes;for(unsigned i=0;i<size;i++)*plan->byte[i]=data[i];
}
static bool read_bytes(AotContext *ctx,uint64_t address,void *out,unsigned size) {
    if(address>UINT64_MAX-size){fault(ctx,AOT_BOUNDS,address,size,GM_READ);return false;}
    uint8_t *data=out;
    for(unsigned offset=0;offset<size;) {
        unsigned n=size-offset;if(n>16)n=16;
        AccessPlan plan;if(!plan_access(ctx,address+offset,n,GM_READ,&plan))return false;
        for(unsigned i=0;i<n;i++)data[offset+i]=*plan.byte[i];offset+=n;
    }
    return true;
}
static int method_index(uint32_t kind,uint32_t slot) {
    if(kind<1 || kind>AOT_D3D_KIND_COUNT)return -1;
    if(slot==2)return AOT_D3D_RELEASE;
    if(kind==AOT_D3D_DEVICE) {
        if(slot==5)return AOT_D3D_CREATE_TEXTURE;
        if(slot==9)return AOT_D3D_CREATE_RTV;
        if(slot==39)return AOT_D3D_GET_REMOVED;
        if(slot==12)return AOT_D3D_CREATE_VS;
        if(slot==15)return AOT_D3D_CREATE_PS;
        if(slot==22)return AOT_D3D_CREATE_RASTER;
    }
    if(kind==AOT_D3D_CONTEXT) {
        if(slot==14)return AOT_D3D_MAP;
        if(slot==15)return AOT_D3D_UNMAP;
        if(slot==47)return AOT_D3D_COPY;
        if(slot==50)return AOT_D3D_CLEAR;
        if(slot==33)return AOT_D3D_OM_SET;
        if(slot==43)return AOT_D3D_RS_SET;
        if(slot==44)return AOT_D3D_VIEWPORT;
        if(slot==24)return AOT_D3D_TOPOLOGY;
        if(slot==11)return AOT_D3D_VS_SET;
        if(slot==9)return AOT_D3D_PS_SET;
        if(slot==13)return AOT_D3D_DRAW;
        if(slot==110)return AOT_D3D_CLEAR_STATE;
        if(slot==111)return AOT_D3D_FLUSH;
    }
    if(kind==AOT_D3D_SWAPCHAIN) {
        if(slot==8)return AOT_D3D_PRESENT;
        if(slot==9)return AOT_D3D_GET_BUFFER;
    }
    return -1;
}
static GuestMemory *arena_region(AotContext *ctx) {
    for(size_t i=0;i<ctx->region_count;i++) {
        GuestMemory *r=&ctx->regions[i];
        if(r->base==session.config.map_base && r->size==session.config.map_capacity &&
           r->permissions==ctx->d3d_map_permissions)return r;
    }
    return NULL;
}
static bool output_plan(AotContext *ctx,uint64_t out,unsigned size,uint64_t rsp,unsigned stack_size,
                        uint64_t input,uint64_t input_size,AccessPlan *plan) {
    if(!plan_access(ctx,out,size,GM_WRITE,plan))return false;
    if(overlap64(out,size,rsp,stack_size) || overlap64(out,size,input,input_size) ||
       overlap64(out,size,session.config.map_base,session.config.map_capacity)) {
        fault(ctx,AOT_UNSUPPORTED,out,size,GM_WRITE);return false;
    }
    return true;
}
static int object_index(AotContext *ctx,uint64_t proxy,uint32_t kind) {
    for(uint32_t i=0;i<session.next_slot;i++)if(session.objects[i].proxy==proxy) {
        ObjectSlot *object=&session.objects[i];
        if(object->native && (!kind || object->kind==kind))return (int)i;
        break;
    }
    fault(ctx,AOT_BAD_OBJECT,proxy,8,GM_READ);return -1;
}
static bool has_map(unsigned object) {
    for(unsigned i=0;i<session.map_count;i++)if(session.maps[i].active && session.maps[i].object==object)return true;
    return false;
}
static bool reserve_objects(AotContext *ctx,unsigned count) {
    if(count>session.config.proxy_count-session.next_slot) {
        fault(ctx,AOT_CAPACITY,session.config.proxy_base,0,0);return false;
    }
    for(unsigned i=0;i<count;i++) {
        AccessPlan p;uint64_t va=session.config.proxy_base+(session.next_slot+i)*AOT_D3D_PROXY_STRIDE;
        if(!exact_plan(ctx,va,16,GM_READ,&p)){fault(ctx,AOT_BAD_OBJECT,va,16,GM_READ);return false;}
    }
    return true;
}
static uint64_t publish_object(AotContext *ctx,uint32_t kind,void *native,uint32_t device,uint32_t resource,const uint32_t *desc) {
    unsigned index=session.next_slot++;ObjectSlot *object=&session.objects[index];
    object->proxy=session.config.proxy_base+(uint64_t)index*AOT_D3D_PROXY_STRIDE;
    object->native=native;object->kind=kind;object->device=device;object->resource=resource;
    if(desc)memcpy(object->desc,desc,sizeof object->desc);
    AccessPlan p;bool valid=exact_plan(ctx,object->proxy,16,GM_READ,&p);
    if(!valid)abort(); /* proven immediately before opaque native call, immutable host mappings */
    uint64_t data[2]={session.config.vtable_va[kind-1],index+1};plan_write(&p,data,16);
    session.stats.created++;session.stats.live_objects++;return object->proxy;
}
static uint32_t release_native(uint32_t kind,void *native) {
    return kind==AOT_D3D_SWAPCHAIN?aot_window_native_release_swap(native):aot_d3d_native_release(kind,native);
}
static void cleanup_native(uint32_t kind,void *native) {
    if(native){session.stats.last_native_release=release_native(kind,native);session.stats.cleanup_releases++;}
}
uint32_t aot_d3d_session_begin(AotContext *ctx,const AotD3DConfig *config) {
    if(session.configured || session.running || !ctx || !config || ctx->result.steps || ctx->result.fault.status ||
       ctx->in_instruction || ctx->result.returned || ctx->d3d_map_permissions || config->reserved ||
       !config->proxy_count || config->proxy_count>AOT_D3D_MAX_OBJECTS || (config->proxy_base&15) ||
       config->proxy_base>UINT64_MAX-(uint64_t)config->proxy_count*AOT_D3D_PROXY_STRIDE ||
       !config->map_capacity || config->map_capacity>AOT_D3D_MAX_MAP_BYTES ||
       ((config->map_base|config->map_capacity)&(GM_PAGE-1)) || config->map_base>UINT64_MAX-config->map_capacity)return AOT_INVALID;
    GuestMemory *arena=NULL;
    for(size_t i=0;i<ctx->region_count;i++)if(ctx->regions[i].base==config->map_base && ctx->regions[i].size==config->map_capacity)arena=&ctx->regions[i];
    if(!arena || !gm_valid(arena))return AOT_INVALID;
    for(size_t i=0;i<arena->page_count;i++)if(arena->permissions[i])return AOT_INVALID;
    for(uint32_t i=0;i<config->proxy_count;i++) {
        AccessPlan p;if(!exact_plan(ctx,config->proxy_base+(uint64_t)i*AOT_D3D_PROXY_STRIDE,16,GM_READ,&p))return AOT_INVALID;
    }
    for(unsigned kind=1;kind<=AOT_D3D_KIND_COUNT;kind++) {
        uint64_t vt=config->vtable_va[kind-1],size=(uint64_t)vtable_slots[kind-1]*8;
        if((vt&7) || vt>UINT64_MAX-size || overlap64(vt,size,config->proxy_base,(uint64_t)config->proxy_count*16) ||
           overlap64(vt,size,config->map_base,config->map_capacity))return AOT_INVALID;
        for(unsigned j=1;j<kind;j++)if(overlap64(vt,size,config->vtable_va[j-1],(uint64_t)vtable_slots[j-1]*8))return AOT_INVALID;
        for(unsigned slot=0;slot<vtable_slots[kind-1];slot++) {
            AccessPlan p;int m=method_index(kind,slot);
            if(!exact_plan(ctx,vt+8*slot,8,GM_READ,&p) || plan_u64(&p)!=(m<0?0:config->method_targets[m]))return AOT_INVALID;
        }
    }
    for(unsigned i=0;i<AOT_D3D_METHOD_COUNT;i++) {
        AccessPlan p;const AotInstruction *ins=instruction(ctx,config->method_targets[i]);
        if(!ins || ins->kind!=AOT_RET || ins->length!=1 ||
           !exact_plan(ctx,config->method_targets[i],1,GM_READ|AOT_EXEC,&p) || *p.byte[0]!=0xc3)return AOT_INVALID;
        for(unsigned j=0;j<i;j++)if(config->method_targets[i]==config->method_targets[j])return AOT_INVALID;
    }
    uint8_t *permissions=calloc(arena->page_count,1);if(!permissions)return AOT_CAPACITY;
    ctx->d3d_map_permissions=permissions;arena->permissions=permissions;
    memset(&session,0,sizeof session);session.configured=1;session.context_identity=(uintptr_t)ctx;session.config=*config;
    session.cleanup_permissions=permissions;session.cleanup_page_count=arena->page_count;return AOT_OK;
}
uint32_t aot_d3d_session_end(void) {
    if(!session.configured || session.running)return 0;
    uint64_t previous_releases=session.stats.cleanup_releases;
    for(unsigned i=0;i<session.map_count;i++)if(session.maps[i].active) {
        MapSlot *map=&session.maps[i];
        aot_d3d_native_unmap(session.objects[map->context].native,session.objects[map->object].native);
        map->active=0;session.stats.active_maps--;session.stats.cleanup_unmaps++;
    }
    memset(session.cleanup_permissions,0,session.cleanup_page_count);
    /* Terminal cleanup only: release context-held bindings and submit pending
     * commands before releasing any remaining application reference. Flush is
     * asynchronous. The pinned swapchain destructor waits for GPU idle before
     * releasing its Metal view; lifetime-r2 also joins device/cache work. */
    for(unsigned i=0;i<session.next_slot;i++) {
        ObjectSlot *object=&session.objects[i];
        if(object->kind==AOT_D3D_CONTEXT && object->native) {
            aot_window_native_clear_state(object->native);session.stats.cleanup_clear_state_calls++;
            aot_window_native_flush(object->native);session.stats.cleanup_flush_calls++;
            memset(&session.pipelines[i],0,sizeof session.pipelines[i]);
        }
    }
    for(unsigned n=session.next_slot;n;n--) {
        ObjectSlot *object=&session.objects[n-1];
        if(object->native){cleanup_native(object->kind,object->native);object->native=NULL;session.stats.live_objects--;}
    }
    session.configured=0;return (uint32_t)(session.stats.cleanup_releases-previous_releases);
}
void aot_d3d_stats(AotD3DStats *out){if(out)*out=session.stats;}
uint32_t aot_process_exit_requested(void){return session.exit_requested;}
uint32_t aot_process_exit_code(void){return session.exit_code;}
uint64_t aot_process_exit_pc(void){return session.exit_pc;}
uint64_t aot_process_exit_rsp(void){return session.exit_rsp;}
uint32_t aot_process_exit_depth(void){return session.exit_depth;}
static bool process_stopped(void *ctx){return session.exit_requested && session.context_identity==(uintptr_t)ctx;}
uint32_t aot_should_exit(void *ctx){return process_stopped(ctx) || aot_engine_should_exit(ctx);}
uint32_t aot_begin(void *s,uint64_t pc,void *ctx){return process_stopped(ctx)?1:aot_engine_begin(s,pc,ctx);}
uint32_t aot_commit(void *s,uint64_t pc,void *ctx){return process_stopped(ctx)?1:aot_engine_commit(s,pc,ctx);}
uint32_t aot_execute(AotEntry entry,AotState *s,AotContext *ctx,uint64_t pc) {
#ifdef AOT_WINDOW_SWITCH_V1
    if(!ctx || !ctx->switch_bound)return AOT_INVALID;
#endif
    if(!session.configured || session.running || session.used || session.context_identity!=(uintptr_t)ctx ||
       !entry || !s || !ctx || ((uintptr_t)s&15) || !bridge_memory_valid(s,ctx) || !arena_region(ctx) ||
       ctx->result.steps || ctx->in_instruction || ctx->result.returned || ctx->result.fault.status)return AOT_INVALID;
    session.running=1;session.used=1;session.state_identity=(uintptr_t)s;
    entry(s,pc,ctx);uint32_t status=ctx->result.fault.status;
    if(!status && session.exit_requested) {
        if(ctx->in_instruction || ctx->pending_size || ctx->result.returned ||
           session.exit_pc!=aot_get_register(s,AOT_RIP) || session.exit_rsp!=aot_get_register(s,AOT_RSP) ||
           session.exit_depth!=ctx->result.call_depth) {fault(ctx,AOT_INVALID,aot_get_register(s,AOT_RIP),0,0);status=ctx->result.fault.status;}
        else status=AOT_PROCESS_EXITED;
    } else if(!status && (!ctx->result.returned || ctx->result.call_depth)) {
        ctx->current_pc=aot_get_register(s,AOT_RIP);fault(ctx,AOT_NOT_RETURNED,ctx->current_pc,0,0);status=ctx->result.fault.status;
    }
    session.running=0;return status;
}
#include "../callback_v1.inc"
#include "../user32_v1.inc"

static bool d3d_validate_call(AotState *s,AotContext *ctx,uint64_t next_pc) {
    if(!session.running || session.context_identity!=(uintptr_t)ctx || session.state_identity!=(uintptr_t)s) {
        fault(ctx,AOT_INVALID,next_pc,0,AOT_EXEC);return false;
    }
    const AotVirtualCall *call=NULL;
    for(size_t i=0;i<AOT_VIRTUAL_CALL_COUNT;i++)if(aot_virtual_calls[i].call_rva==ctx->current->rva) {
        if(call){fault(ctx,AOT_BAD_METHOD,next_pc,0,AOT_EXEC);return false;}call=&aot_virtual_calls[i];
    }
    if(!call || call->base_register>=16 || call->base_register==AOT_RSP || ctx->current->target_rva) {
        fault(ctx,AOT_BAD_METHOD,next_pc,0,AOT_EXEC);return false;
    }
    uint64_t this_va=aot_get_register(&ctx->snapshot,AOT_RCX);int index=object_index(ctx,this_va,0);if(index<0)return false;
    ObjectSlot *object=&session.objects[index];int m=method_index(object->kind,call->slot);
    if(m<0){fault(ctx,AOT_BAD_METHOD,next_pc,0,AOT_EXEC);return false;}
    uint64_t vtable=session.config.vtable_va[object->kind-1];AccessPlan proxy,slot;
    if(!exact_plan(ctx,this_va,8,GM_READ,&proxy) || plan_u64(&proxy)!=vtable ||
       aot_get_register(&ctx->snapshot,call->base_register)!=vtable ||
       !exact_plan(ctx,vtable+8*call->slot,8,GM_READ,&slot) ||
       plan_u64(&slot)!=session.config.method_targets[m] || next_pc!=session.config.method_targets[m]) {
        fault(ctx,AOT_BAD_METHOD,next_pc,0,AOT_EXEC);return false;
    }
    ctx->d3d_binding_valid=1;ctx->d3d_object_index=(uint32_t)index;ctx->d3d_signature=method_signatures[m];
    ctx->d3d_binding_pc=ctx->current_pc;ctx->d3d_binding_target=next_pc;return true;
}

/* Validate the actual register value before committing the Remill CALL's stack
 * write. Cached IAT pointers do not require rereading the original IAT slot;
 * they do require an exact member of this image's registered import closure. */
static bool import_validate_call(AotState *s,AotContext *ctx,uint64_t next_pc) {
    if(!session.running || session.context_identity!=(uintptr_t)ctx || session.state_identity!=(uintptr_t)s) {
        fault(ctx,AOT_INVALID,next_pc,0,AOT_EXEC);return false;
    }
    const AotRegisterCall *call=NULL;
    for(size_t i=0;i<AOT_REGISTER_CALL_COUNT;i++)if(aot_register_calls[i].call_rva==ctx->current->rva) {
        if(call){fault(ctx,AOT_BAD_METHOD,next_pc,0,AOT_EXEC);return false;}call=&aot_register_calls[i];
    }
    if(!call || call->operand_register>=16 || call->operand_register==AOT_RSP || ctx->current->target_rva ||
       aot_get_register(&ctx->snapshot,call->operand_register)!=next_pc) {
        fault(ctx,AOT_BAD_METHOD,next_pc,0,AOT_EXEC);return false;
    }
    const AotImportTarget *target=NULL;
    for(size_t i=0;i<AOT_IMPORT_TARGET_COUNT;i++)if(ctx->module_base<=UINT64_MAX-aot_import_targets[i].target_rva &&
       next_pc==ctx->module_base+aot_import_targets[i].target_rva) {
        if(target){fault(ctx,AOT_BAD_METHOD,next_pc,0,AOT_EXEC);return false;}target=&aot_import_targets[i];
    }
    if(!target || !target->signature) {fault(ctx,AOT_BAD_METHOD,next_pc,0,AOT_EXEC);return false;}
    /* COM targets cannot be promoted into this IAT-only call form. */
    for(unsigned i=0;i<AOT_D3D_METHOD_COUNT;i++)if(target->signature==method_signatures[i]) {
        fault(ctx,AOT_BAD_METHOD,next_pc,0,AOT_EXEC);return false;
    }
    const AotInstruction *ret=instruction(ctx,next_pc);AccessPlan code;
    if(!ret || ret->kind!=AOT_RET || ret->length!=1) {fault(ctx,AOT_BAD_INSTRUCTION,next_pc,1,AOT_EXEC);return false;}
    if(!plan_access(ctx,next_pc,1,AOT_EXEC,&code))return false;
    if(*code.byte[0]!=0xc3) {fault(ctx,AOT_BAD_INSTRUCTION,next_pc,1,AOT_EXEC);return false;}
    ctx->import_binding_valid=1;ctx->import_signature=target->signature;
    ctx->import_binding_pc=ctx->current_pc;ctx->import_binding_target=next_pc;return true;
}

static uint32_t create_device(AotState *s,AotContext *ctx,uint64_t rsp) {
    uint64_t args[6];
    if(aot_get_register(s,AOT_RCX) || (uint32_t)aot_get_register(s,AOT_RDX)!=1 ||
       aot_get_register(s,AOT_R8) || (uint32_t)aot_get_register(s,AOT_R9)) {
        fault(ctx,AOT_UNSUPPORTED,ctx->current_pc,0,0);return 0;
    }
    for(unsigned i=0;i<6;i++)if(!read_u64(ctx,rsp+40+8*i,&args[i]))return 0;
    uint32_t requested;
    if((uint32_t)args[1]!=1 || (uint32_t)args[2]!=7) {fault(ctx,AOT_UNSUPPORTED,args[0],0,0);return 0;}
    if(!read_bytes(ctx,args[0],&requested,4))return 0;
    if(requested!=0xb000) {fault(ctx,AOT_UNSUPPORTED,args[0],4,GM_READ);return 0;}
    AccessPlan device_out,feature_out,context_out;
    if(!output_plan(ctx,args[3],8,rsp,88,args[0],4,&device_out) ||
       !output_plan(ctx,args[4],4,rsp,88,args[0],4,&feature_out) ||
       !output_plan(ctx,args[5],8,rsp,88,args[0],4,&context_out))return 0;
    if(overlap64(args[3],8,args[4],4) || overlap64(args[3],8,args[5],8) || overlap64(args[4],4,args[5],8)) {
        fault(ctx,AOT_UNSUPPORTED,args[3],8,GM_WRITE);return 0;
    }
    if(!reserve_objects(ctx,2))return 0;
    void *device=NULL,*context=NULL;uint32_t feature=0;
    session.stats.create_device_calls++;
    uint32_t hr=aot_d3d_native_create_device(&device,&context,&feature);
    if((int32_t)hr<0) {
        cleanup_native(AOT_D3D_CONTEXT,context);cleanup_native(AOT_D3D_DEVICE,device);
        put_plan(&device_out,0);put_plan(&context_out,0);uint32_t zero=0;plan_write(&feature_out,&zero,4);return hr;
    }
    if(!device || !context || feature!=0xb000) {
        cleanup_native(AOT_D3D_CONTEXT,context);cleanup_native(AOT_D3D_DEVICE,device);
        fault(ctx,AOT_BACKEND,ctx->current_pc,0,0);return 0;
    }
    unsigned device_index=session.next_slot;
    uint64_t dv=publish_object(ctx,AOT_D3D_DEVICE,device,device_index,0,NULL);
    uint64_t cv=publish_object(ctx,AOT_D3D_CONTEXT,context,device_index,0,NULL);
    put_plan(&device_out,dv);put_plan(&context_out,cv);plan_write(&feature_out,&feature,4);return hr;
}
static bool window_backbuffer_profile(const uint32_t desc[11]) {
    /* Pinned DXMT backbuffer_desc_: RT binding only for RT_OUTPUT usage.
     * CreateMTLTextureDescriptor copies this descriptor, only normalizing
     * MipLevels. GetDesc must report this exact native result. */
    static const uint32_t expected[11]={640,360,1,1,28,1,0,0,32,0,0};
    return !memcmp(desc,expected,sizeof expected);
}
static uint32_t create_swapchain(AotState *s,AotContext *ctx,uint64_t rsp) {
    uint64_t args[8];
    if(aot_get_register(s,AOT_RCX) || (uint32_t)aot_get_register(s,AOT_RDX)!=1 ||
       aot_get_register(s,AOT_R8) || (uint32_t)aot_get_register(s,AOT_R9)) {
        fault(ctx,AOT_UNSUPPORTED,ctx->current_pc,0,0);return 0;
    }
    for(unsigned i=0;i<8;i++)if(!read_u64(ctx,rsp+40+8*i,&args[i]))return 0;
    if((uint32_t)args[1]!=1 || (uint32_t)args[2]!=7) {
        fault(ctx,AOT_UNSUPPORTED,args[0],0,0);return 0;
    }
    uint32_t feature_requested,words[18];uint64_t hwnd;
    if(!read_bytes(ctx,args[0],&feature_requested,4) || !read_bytes(ctx,args[3],words,sizeof words))return 0;
    memcpy(&hwnd,words+12,8);
    if(feature_requested!=0xb000 || words[0]!=640 || words[1]!=360 || words[2] || words[3]!=1 ||
       words[4]!=28 || words[5] || words[6] || words[7]!=1 || words[8] || words[9]!=32 ||
       words[10]!=2 || !hwnd || words[14]!=1 || words[15]!=4 || words[16]) {
        fault(ctx,AOT_UNSUPPORTED,args[3],sizeof words,GM_READ);return 0;
    }
    /* Descriptor padding words 11/17 carry no API meaning. All fields are
     * decoded explicitly; no guest object is cast to a native C++ pointer. */
    AotWindowNativeSwapDesc desc={.width=words[0],.height=words[1],
        .refresh_numerator=words[2],.refresh_denominator=words[3],.format=words[4],
        .scanline_ordering=words[5],.scaling=words[6],.sample_count=words[7],.sample_quality=words[8],
        .buffer_usage=words[9],.buffer_count=words[10],.hwnd_token=hwnd,
        .windowed=words[14],.swap_effect=words[15],.flags=words[16]};
    AccessPlan output[4];const unsigned sizes[4]={8,8,4,8};
    for(unsigned i=0;i<4;i++) {
        if(!output_plan(ctx,args[4+i],sizes[i],rsp,104,args[0],4,&output[i]))return 0;
        if(overlap64(args[4+i],sizes[i],args[3],sizeof words)) {
            fault(ctx,AOT_UNSUPPORTED,args[4+i],sizes[i],GM_WRITE);return 0;
        }
        for(unsigned j=0;j<i;j++)if(overlap64(args[4+i],sizes[i],args[4+j],sizes[j])) {
            fault(ctx,AOT_UNSUPPORTED,args[4+i],sizes[i],GM_WRITE);return 0;
        }
    }
    if(!reserve_objects(ctx,3))return 0;
    if(!wui_window_contract(ctx,hwnd,640,360)) {
        fault(ctx,AOT_UNSUPPORTED,hwnd,0,0);return 0;
    }
    for(unsigned i=0;i<session.next_slot;i++)if(session.objects[i].native &&
       session.objects[i].kind==AOT_D3D_SWAPCHAIN && session.objects[i].window_handle==hwnd) {
        fault(ctx,AOT_UNSUPPORTED,hwnd,0,0);return 0;
    }
    void *swap=NULL,*device=NULL,*context=NULL;uint32_t feature=0;
    session.stats.create_swapchain_calls++;
    uint32_t hr=aot_window_native_create_device_swapchain(&desc,&swap,&device,&feature,&context);
    if((int32_t)hr<0 || !swap || !device || !context || feature!=0xb000) {
        cleanup_native(AOT_D3D_SWAPCHAIN,swap);cleanup_native(AOT_D3D_CONTEXT,context);cleanup_native(AOT_D3D_DEVICE,device);
        if((int32_t)hr<0) {
            put_plan(&output[0],0);put_plan(&output[1],0);put_plan(&output[3],0);
            uint32_t zero=0;plan_write(&output[2],&zero,4);return hr;
        }
        fault(ctx,AOT_BACKEND,ctx->current_pc,0,0);return 0;
    }
    unsigned device_index=session.next_slot,context_index=device_index+1,swap_index=device_index+2;
    uint64_t dv=publish_object(ctx,AOT_D3D_DEVICE,device,device_index,0,NULL);
    uint64_t cv=publish_object(ctx,AOT_D3D_CONTEXT,context,device_index,0,NULL);
    uint64_t sv=publish_object(ctx,AOT_D3D_SWAPCHAIN,swap,device_index,0,NULL);
    session.objects[swap_index].window_handle=hwnd;session.objects[swap_index].context_index=context_index;
    put_plan(&output[0],sv);put_plan(&output[1],dv);plan_write(&output[2],&feature,4);put_plan(&output[3],cv);
    return hr;
}
static uint32_t get_backbuffer(AotState *s,AotContext *ctx,ObjectSlot *chain,uint64_t rsp) {
    static const uint8_t expected_iid[16]={0xf2,0xaa,0x15,0x6f,0x08,0xd2,0x89,0x4e,
                                         0x9a,0xb4,0x48,0x95,0x35,0xd3,0x4f,0x9c};
    uint64_t iid_va=aot_get_register(s,AOT_R8),out=aot_get_register(s,AOT_R9);uint8_t iid[16];
    if((uint32_t)aot_get_register(s,AOT_RDX) || chain->buffer_acquired) {
        fault(ctx,AOT_UNSUPPORTED,chain->proxy,0,0);return 0;
    }
    if(!read_bytes(ctx,iid_va,iid,sizeof iid))return 0;
    if(memcmp(iid,expected_iid,sizeof iid)){fault(ctx,AOT_UNSUPPORTED,iid_va,sizeof iid,GM_READ);return 0;}
    AccessPlan output;
    if(!output_plan(ctx,out,8,rsp,40,iid_va,sizeof iid,&output) || !reserve_objects(ctx,1))return 0;
    void *texture=NULL;uint32_t actual_desc[11]={0};
    session.stats.this_checks++;session.stats.get_buffer_calls++;
    uint32_t hr=aot_window_native_get_buffer(chain->native,0,iid,&texture,actual_desc);
    if((int32_t)hr<0){cleanup_native(AOT_D3D_TEXTURE2D,texture);put_plan(&output,0);return hr;}
    if(!texture || !window_backbuffer_profile(actual_desc)) {
        cleanup_native(AOT_D3D_TEXTURE2D,texture);fault(ctx,AOT_BACKEND,out,8,GM_WRITE);return 0;
    }
    unsigned index=session.next_slot;
    uint64_t proxy=publish_object(ctx,AOT_D3D_TEXTURE2D,texture,chain->device,0,actual_desc);
    session.objects[index].swapchain_plus_one=ctx->d3d_object_index+1;
    chain->buffer_acquired=1;put_plan(&output,proxy);return hr;
}
static bool pipeline_holds_chain(const PipelineState *pipeline,unsigned chain) {
    if(!pipeline->native_rtv_bound || pipeline->rtv>=session.next_slot)return false;
    const ObjectSlot *view=&session.objects[pipeline->rtv];
    return view->kind==AOT_D3D_RTV && view->resource<session.next_slot &&
        session.objects[view->resource].swapchain_plus_one==chain+1;
}
static bool texture_profile(const uint32_t desc[11]) {
    return desc[0]==32 && desc[1]==32 && desc[2]==1 && desc[3]==1 && desc[4]==28 && desc[5]==1 && !desc[6] && !desc[10] &&
        ((!desc[7] && desc[8]==32 && !desc[9]) || (desc[7]==3 && !desc[8] && desc[9]==0x20000));
}
static uint32_t map_texture(AotState *s,AotContext *ctx,ObjectSlot *context,uint64_t rsp) {
    int resource=object_index(ctx,aot_get_register(s,AOT_RDX),AOT_D3D_TEXTURE2D);if(resource<0)return 0;
    ObjectSlot *texture=&session.objects[resource];uint64_t flags,out;
    if(!read_u64(ctx,rsp+40,&flags) || !read_u64(ctx,rsp+48,&out))return 0;
    if(texture->device!=context->device || !texture_profile(texture->desc) || texture->swapchain_plus_one ||
       texture->desc[7]!=3 || (uint32_t)aot_get_register(s,AOT_R8) ||
       (uint32_t)aot_get_register(s,AOT_R9)!=1 || (uint32_t)flags) {fault(ctx,AOT_UNSUPPORTED,texture->proxy,0,0);return 0;}
    if(has_map((unsigned)resource)) {fault(ctx,AOT_MAP_STATE,texture->proxy,0,0);return 0;}
    if(session.map_count==AOT_D3D_MAX_MAPS || session.arena_next==session.config.map_capacity) {
        fault(ctx,AOT_CAPACITY,session.config.map_base,0,0);return 0;
    }
    AccessPlan output;if(!output_plan(ctx,out,16,rsp,56,0,0,&output))return 0;
    GuestMemory *arena=arena_region(ctx);
    if(!arena){fault(ctx,AOT_INVALID,session.config.map_base,0,0);return 0;}
    for(size_t i=(size_t)session.arena_next/GM_PAGE;i<arena->page_count;i++)if(arena->permissions[i]) {
        fault(ctx,AOT_INVALID,arena->base,0,0);return 0;
    }
    AotD3DNativeMap mapped={0};session.stats.map_calls++;session.stats.this_checks++;
    uint32_t hr=aot_d3d_native_map(context->native,texture->native,&mapped);
    if((int32_t)hr<0)return hr;
    uint64_t span=(uint64_t)mapped.row_pitch*31+128;
    uint64_t size=(span+GM_PAGE-1)&~(uint64_t)(GM_PAGE-1);
    bool invalid_mapping=!mapped.data || mapped.row_pitch<128 || span>UINTPTR_MAX-(uintptr_t)mapped.data;
    if(invalid_mapping ||
       size>session.config.map_capacity-session.arena_next) {
        aot_d3d_native_unmap(context->native,texture->native);session.stats.cleanup_unmaps++;
        session.stats.map_postcall_failures++;
        fault(ctx,invalid_mapping?AOT_BACKEND:AOT_CAPACITY,session.config.map_base+session.arena_next,size,GM_READ);return 0;
    }
    uint64_t offset=session.arena_next;uint8_t *destination=arena->bytes+(size_t)offset;
    memset(destination,0,(size_t)size);
    for(unsigned y=0;y<32;y++)memcpy(destination+(size_t)y*mapped.row_pitch,(const uint8_t*)mapped.data+(size_t)y*mapped.row_pitch,128);
    uint64_t guest=arena->base+offset;uint8_t descriptor[16];
    memcpy(descriptor,&guest,8);memcpy(descriptor+8,&mapped.row_pitch,4);memcpy(descriptor+12,&mapped.depth_pitch,4);
    session.maps[session.map_count++]=(MapSlot){1,(uint32_t)resource,ctx->d3d_object_index,0,offset,size};
    session.arena_next+=size;session.stats.active_maps++;session.stats.map_bytes_copied+=4096;
    plan_write(&output,descriptor,16);
    memset(ctx->d3d_map_permissions+(size_t)offset/GM_PAGE,GM_READ,(size_t)size/GM_PAGE);
    return hr;
}
/* Exact fixture shader bytes are an explicit first-profile limit. Read and
 * pass the actual guest copy to DXMT; never substitute a host rendering path. */
static uint32_t create_shader(AotState *s,AotContext *ctx,ObjectSlot *device,uint64_t rsp,uint32_t kind) {
    const uint8_t *expected=kind==AOT_D3D_VS?kTriangleVsDxbc:kTrianglePsDxbc;
    const unsigned size=kind==AOT_D3D_VS?sizeof kTriangleVsDxbc:sizeof kTrianglePsDxbc;
    uint64_t source=aot_get_register(s,AOT_RDX),out;
    uint8_t bytes[sizeof kTriangleVsDxbc];
    if(aot_get_register(s,AOT_R8)!=size || aot_get_register(s,AOT_R9)) {
        fault(ctx,AOT_UNSUPPORTED,source,0,GM_READ);return 0;
    }
    if(!read_u64(ctx,rsp+40,&out) || !read_bytes(ctx,source,bytes,size))return 0;
    if(memcmp(bytes,expected,size)){fault(ctx,AOT_UNSUPPORTED,source,size,GM_READ);return 0;}
    AccessPlan output;
    if(!output_plan(ctx,out,8,rsp,48,source,size,&output) || !reserve_objects(ctx,1))return 0;
    void *native=NULL;session.stats.this_checks++;
    if(kind==AOT_D3D_VS)session.stats.create_vs_calls++;else session.stats.create_ps_calls++;
    uint32_t hr=aot_d3d_native_create_shader(kind,device->native,bytes,size,&native);
    if((int32_t)hr<0){cleanup_native(kind,native);put_plan(&output,0);return hr;}
    if(!native){fault(ctx,AOT_BACKEND,out,8,GM_WRITE);return 0;}
    put_plan(&output,publish_object(ctx,kind,native,ctx->d3d_object_index,0,NULL));return hr;
}
static uint32_t draw_method(AotState *s,AotContext *ctx,ObjectSlot *context,uint32_t signature) {
    PipelineState *pipeline=&session.pipelines[ctx->d3d_object_index];
    uint64_t arg=aot_get_register(s,AOT_RDX);
    if(signature==AOT_D3D_SIG_VIEWPORT) {
        uint32_t bits[6];static const uint32_t offscreen[6]={0,0,0x42000000,0x42000000,0,0x3f800000};
        static const uint32_t xbits[8]={0,0x42a00000,0x43200000,0x43700000,
                                       0x43a00000,0x43c80000,0x43f00000,0x440c0000};
        if((uint32_t)arg!=1){fault(ctx,AOT_UNSUPPORTED,arg,0,0);return 0;}
        if(!read_bytes(ctx,aot_get_register(s,AOT_R8),bits,sizeof bits))return 0;
        bool admitted=!memcmp(bits,offscreen,sizeof bits);
        if(bits[1]==0x430c0000 && bits[2]==0x42a00000 && bits[3]==0x42a00000 && !bits[4] && bits[5]==0x3f800000)
            for(unsigned i=0;i<8;i++)if(bits[0]==xbits[i])admitted=true;
        if(!admitted){fault(ctx,AOT_UNSUPPORTED,aot_get_register(s,AOT_R8),sizeof bits,GM_READ);return 0;}
        session.stats.this_checks++;session.stats.viewport_calls++;
        aot_d3d_native_viewport(context->native,bits);pipeline->flags|=4;return 0;
    }
    if(signature==AOT_D3D_SIG_TOPOLOGY) {
        if((uint32_t)arg!=4){fault(ctx,AOT_UNSUPPORTED,arg,0,0);return 0;}
        session.stats.this_checks++;session.stats.topology_calls++;
        aot_d3d_native_topology(context->native);pipeline->flags|=8;return 0;
    }
    if(signature==AOT_D3D_SIG_DRAW) {
        if((uint32_t)arg!=3 || (uint32_t)aot_get_register(s,AOT_R8) || pipeline->flags!=63) {
            fault(ctx,AOT_UNSUPPORTED,ctx->current_pc,0,0);return 0;
        }
        /* OM/VS/PS/RS setters cause the real native context to retain its own
         * references. Guest Release removes only the application's reference;
         * it does not invalidate bindings. Slots and their metadata are never
         * reused within a session, so no native pointer must be resurrected. */
        if(has_map(session.objects[pipeline->rtv].resource)) {
            fault(ctx,AOT_MAP_STATE,session.objects[pipeline->rtv].proxy,0,0);return 0;
        }
        session.stats.this_checks++;session.stats.draw_calls++;aot_d3d_native_draw(context->native);return 0;
    }
    uint32_t kind;
    if(signature==AOT_D3D_SIG_OM_SET) {
        if((uint32_t)arg!=1 || aot_get_register(s,AOT_R9)){fault(ctx,AOT_UNSUPPORTED,arg,0,0);return 0;}
        if(!read_u64(ctx,aot_get_register(s,AOT_R8),&arg))return 0;
        kind=AOT_D3D_RTV;
    } else if(signature==AOT_D3D_SIG_RS_SET)kind=AOT_D3D_RASTER;
    else {
        if(aot_get_register(s,AOT_R8) || (uint32_t)aot_get_register(s,AOT_R9)) {
            fault(ctx,AOT_UNSUPPORTED,ctx->current_pc,0,0);return 0;
        }
        kind=signature==AOT_D3D_SIG_VS_SET?AOT_D3D_VS:AOT_D3D_PS;
    }
    int index=object_index(ctx,arg,kind);if(index<0)return 0;
    ObjectSlot *bound=&session.objects[index];
    if(bound->device!=context->device){fault(ctx,AOT_BAD_OBJECT,arg,8,GM_READ);return 0;}
    if(kind==AOT_D3D_RTV && has_map(bound->resource)){fault(ctx,AOT_MAP_STATE,arg,0,0);return 0;}
    session.stats.this_checks++;
    if(kind==AOT_D3D_RTV) {
        session.stats.om_set_calls++;aot_d3d_native_om_set(context->native,bound->native);
        pipeline->rtv=(uint32_t)index;pipeline->flags|=1;pipeline->native_rtv_bound=1;
    } else if(kind==AOT_D3D_RASTER) {
        session.stats.rs_set_calls++;aot_d3d_native_rs_set(context->native,bound->native);
        pipeline->rasterizer=(uint32_t)index;pipeline->flags|=2;
    } else {
        aot_d3d_native_shader_set(kind,context->native,bound->native);
        if(kind==AOT_D3D_VS){session.stats.vs_set_calls++;pipeline->vs=(uint32_t)index;pipeline->flags|=16;}
        else {session.stats.ps_set_calls++;pipeline->ps=(uint32_t)index;pipeline->flags|=32;}
    }
    return 0;
}
static uint32_t invoke_method(AotState *s,AotContext *ctx,uint32_t signature,uint64_t rsp,bool *has_result) {
    ObjectSlot *object=&session.objects[ctx->d3d_object_index];
    if(!object->native || object->proxy!=aot_get_register(s,AOT_RCX)) {fault(ctx,AOT_BAD_OBJECT,aot_get_register(s,AOT_RCX),8,GM_READ);return 0;}
    if(signature==AOT_D3D_SIG_GET_BUFFER) {
        if(object->kind!=AOT_D3D_SWAPCHAIN){fault(ctx,AOT_BAD_METHOD,object->proxy,0,0);return 0;}
        return get_backbuffer(s,ctx,object,rsp);
    }
    if(signature==AOT_D3D_SIG_PRESENT) {
        if(object->kind!=AOT_D3D_SWAPCHAIN || (uint32_t)aot_get_register(s,AOT_RDX) ||
           (uint32_t)aot_get_register(s,AOT_R8)) {fault(ctx,AOT_UNSUPPORTED,object->proxy,0,0);return 0;}
        if(!wui_window_contract(ctx,object->window_handle,640,360)) {
            fault(ctx,AOT_UNSUPPORTED,object->window_handle,0,0);return 0;
        }
        session.stats.this_checks++;session.stats.present_calls++;
        uint32_t hr=aot_window_native_present(object->native,0,0);
        if((int32_t)hr>=0)for(unsigned i=0;i<session.next_slot;i++)
            if(pipeline_holds_chain(&session.pipelines[i],ctx->d3d_object_index))session.pipelines[i].flags&=~1u;
        return hr;
    }
    if(signature==AOT_D3D_SIG_CLEAR_STATE || signature==AOT_D3D_SIG_FLUSH) {
        if(object->kind!=AOT_D3D_CONTEXT){fault(ctx,AOT_BAD_METHOD,object->proxy,0,0);return 0;}
        session.stats.this_checks++;*has_result=false;
        if(signature==AOT_D3D_SIG_CLEAR_STATE) {
            session.stats.clear_state_calls++;aot_window_native_clear_state(object->native);
            memset(&session.pipelines[ctx->d3d_object_index],0,sizeof session.pipelines[ctx->d3d_object_index]);
        } else {session.stats.flush_calls++;aot_window_native_flush(object->native);}
        return 0;
    }
    if(signature==AOT_D3D_SIG_CREATE_VS || signature==AOT_D3D_SIG_CREATE_PS)
        return create_shader(s,ctx,object,rsp,signature==AOT_D3D_SIG_CREATE_VS?AOT_D3D_VS:AOT_D3D_PS);
    if(signature==AOT_D3D_SIG_CREATE_RASTER) {
        uint64_t desc_va=aot_get_register(s,AOT_RDX),out=aot_get_register(s,AOT_R8);uint32_t desc[10];
        static const uint32_t expected[10]={3,1,0,0,0,0,1,0,0,0};AccessPlan output;
        if(!read_bytes(ctx,desc_va,desc,sizeof desc))return 0;
        if(memcmp(desc,expected,sizeof desc)){fault(ctx,AOT_UNSUPPORTED,desc_va,sizeof desc,GM_READ);return 0;}
        if(!output_plan(ctx,out,8,rsp,40,desc_va,sizeof desc,&output) || !reserve_objects(ctx,1))return 0;
        void *native=NULL;session.stats.this_checks++;session.stats.create_rasterizer_calls++;
        uint32_t hr=aot_d3d_native_create_raster(object->native,desc,&native);
        if((int32_t)hr<0){cleanup_native(AOT_D3D_RASTER,native);put_plan(&output,0);return hr;}
        if(!native){fault(ctx,AOT_BACKEND,out,8,GM_WRITE);return 0;}
        put_plan(&output,publish_object(ctx,AOT_D3D_RASTER,native,ctx->d3d_object_index,0,NULL));return hr;
    }
    if(signature>=AOT_D3D_SIG_OM_SET && signature<=AOT_D3D_SIG_DRAW) {
        *has_result=false;return draw_method(s,ctx,object,signature);
    }
    if(signature==AOT_D3D_SIG_RELEASE) {
        for(unsigned i=0;i<session.map_count;i++)if(session.maps[i].active &&
           (session.maps[i].object==ctx->d3d_object_index || session.maps[i].context==ctx->d3d_object_index)) {
            fault(ctx,AOT_MAP_STATE,object->proxy,0,0);return 0;
        }
        if(object->kind==AOT_D3D_SWAPCHAIN) {
            /* v1 requires explicit release of backbuffer/view application
             * references and ClearState of any context binding before the
             * swapchain application reference is released. */
            for(unsigned i=0;i<session.next_slot;i++) {
                const ObjectSlot *other=&session.objects[i];
                bool child=other->kind==AOT_D3D_TEXTURE2D && other->swapchain_plus_one==ctx->d3d_object_index+1;
                if(other->kind==AOT_D3D_RTV && other->resource<session.next_slot)
                    child=session.objects[other->resource].swapchain_plus_one==ctx->d3d_object_index+1;
                if((other->native && child) || pipeline_holds_chain(&session.pipelines[i],ctx->d3d_object_index)) {
                    fault(ctx,AOT_UNSUPPORTED,object->proxy,0,0);return 0;
                }
            }
        }
        if(object->kind==AOT_D3D_CONTEXT)for(unsigned i=0;i<session.next_slot;i++)
            if(session.objects[i].kind==AOT_D3D_SWAPCHAIN &&
               pipeline_holds_chain(&session.pipelines[ctx->d3d_object_index],i)) {
                fault(ctx,AOT_UNSUPPORTED,object->proxy,0,0);return 0;
            }
        session.stats.this_checks++;session.stats.release_calls++;
        uint32_t result=release_native(object->kind,object->native);object->native=NULL;
        session.stats.last_native_release=result;session.stats.guest_released++;session.stats.live_objects--;return result;
    }
    if(signature==AOT_D3D_SIG_CREATE_TEXTURE) {
        uint64_t desc_va=aot_get_register(s,AOT_RDX),out=aot_get_register(s,AOT_R9);uint32_t desc[11];AccessPlan output;
        if(aot_get_register(s,AOT_R8)){fault(ctx,AOT_UNSUPPORTED,aot_get_register(s,AOT_R8),0,0);return 0;}
        if(!read_bytes(ctx,desc_va,desc,sizeof desc))return 0;
        if(!texture_profile(desc)){fault(ctx,AOT_UNSUPPORTED,desc_va,sizeof desc,GM_READ);return 0;}
        if(!output_plan(ctx,out,8,rsp,40,desc_va,sizeof desc,&output) || !reserve_objects(ctx,1))return 0;
        void *native=NULL;session.stats.this_checks++;session.stats.create_texture_calls++;
        uint32_t hr=aot_d3d_native_create_texture(object->native,desc,&native);
        if((int32_t)hr<0){cleanup_native(AOT_D3D_TEXTURE2D,native);put_plan(&output,0);return hr;}
        if(!native){fault(ctx,AOT_BACKEND,out,8,GM_WRITE);return 0;}
        put_plan(&output,publish_object(ctx,AOT_D3D_TEXTURE2D,native,ctx->d3d_object_index,0,desc));return hr;
    }
    if(signature==AOT_D3D_SIG_CREATE_RTV) {
        int resource=object_index(ctx,aot_get_register(s,AOT_RDX),AOT_D3D_TEXTURE2D);if(resource<0)return 0;
        ObjectSlot *texture=&session.objects[resource];
        if(aot_get_register(s,AOT_R8) || texture->device!=ctx->d3d_object_index || texture->desc[7] || texture->desc[8]!=32) {
            fault(ctx,AOT_UNSUPPORTED,texture->proxy,0,0);return 0;
        }
        AccessPlan output;uint64_t out=aot_get_register(s,AOT_R9);
        if(!output_plan(ctx,out,8,rsp,40,0,0,&output) || !reserve_objects(ctx,1))return 0;
        void *native=NULL;session.stats.this_checks++;session.stats.create_rtv_calls++;
        uint32_t hr=aot_d3d_native_create_rtv(object->native,texture->native,&native);
        if((int32_t)hr<0){cleanup_native(AOT_D3D_RTV,native);put_plan(&output,0);return hr;}
        if(!native){fault(ctx,AOT_BACKEND,out,8,GM_WRITE);return 0;}
        put_plan(&output,publish_object(ctx,AOT_D3D_RTV,native,ctx->d3d_object_index,(uint32_t)resource,NULL));return hr;
    }
    if(signature==AOT_D3D_SIG_GET_REMOVED) {session.stats.this_checks++;session.stats.get_removed_calls++;return aot_d3d_native_get_removed(object->native);}
    if(signature==AOT_D3D_SIG_MAP)return map_texture(s,ctx,object,rsp);
    if(signature==AOT_D3D_SIG_UNMAP) {
        int resource=object_index(ctx,aot_get_register(s,AOT_RDX),AOT_D3D_TEXTURE2D);if(resource<0)return 0;
        if((uint32_t)aot_get_register(s,AOT_R8)){fault(ctx,AOT_UNSUPPORTED,session.objects[resource].proxy,0,0);return 0;}
        MapSlot *map=NULL;
        for(unsigned i=0;i<session.map_count;i++)if(session.maps[i].active && session.maps[i].object==(uint32_t)resource &&
           session.maps[i].context==ctx->d3d_object_index)map=&session.maps[i];
        if(!map){fault(ctx,AOT_MAP_STATE,session.objects[resource].proxy,0,0);return 0;}
        session.stats.this_checks++;session.stats.unmap_calls++;
        aot_d3d_native_unmap(object->native,session.objects[resource].native);
        memset(ctx->d3d_map_permissions+(size_t)map->offset/GM_PAGE,0,(size_t)map->size/GM_PAGE);
        map->active=0;session.stats.active_maps--;*has_result=false;return 0;
    }
    if(signature==AOT_D3D_SIG_CLEAR) {
        int view=object_index(ctx,aot_get_register(s,AOT_RDX),AOT_D3D_RTV);if(view<0)return 0;
        ObjectSlot *rtv=&session.objects[view];uint32_t bits[4];float color[4];
        if(rtv->device!=object->device || has_map(rtv->resource)){fault(ctx,AOT_MAP_STATE,rtv->proxy,0,0);return 0;}
        if(!read_bytes(ctx,aot_get_register(s,AOT_R8),bits,16))return 0;
        for(unsigned i=0;i<4;i++)if((bits[i]&0x7f800000)==0x7f800000) {fault(ctx,AOT_UNSUPPORTED,aot_get_register(s,AOT_R8),16,GM_READ);return 0;}
        memcpy(color,bits,16);session.stats.this_checks++;session.stats.clear_calls++;
        aot_d3d_native_clear(object->native,rtv->native,color);*has_result=false;return 0;
    }
    if(signature==AOT_D3D_SIG_COPY) {
        int dst=object_index(ctx,aot_get_register(s,AOT_RDX),AOT_D3D_TEXTURE2D);
        int src=object_index(ctx,aot_get_register(s,AOT_R8),AOT_D3D_TEXTURE2D);if(dst<0 || src<0)return 0;
        ObjectSlot *a=&session.objects[dst],*b=&session.objects[src];
        if(dst==src || a->device!=object->device || b->device!=object->device || has_map((unsigned)dst) || has_map((unsigned)src) ||
           memcmp(a->desc,b->desc,7*sizeof(uint32_t))) {fault(ctx,AOT_UNSUPPORTED,a->proxy,0,0);return 0;}
        session.stats.this_checks++;session.stats.copy_calls++;aot_d3d_native_copy(object->native,a->native,b->native);*has_result=false;return 0;
    }
    fault(ctx,AOT_BAD_METHOD,signature,0,0);return 0;
}
void *__remill_function_call(void *state,uint64_t pc,void *opaque) {
    AotState *s=state;AotContext *ctx=opaque;if(!s || !ctx || aot_should_exit(ctx))return opaque;
    if(!session.running || session.context_identity!=(uintptr_t)ctx || session.state_identity!=(uintptr_t)s) {
        fault(ctx,AOT_INVALID,pc,0,0);return opaque;
    }
    uint32_t signature=0;
    if(ctx->current && !ctx->in_instruction && ctx->result.call_depth && aot_get_register(s,AOT_RIP)==pc) {
        if(ctx->current->kind==AOT_CALL) {
            for(size_t i=0;i<AOT_IMPORT_CALL_COUNT;i++)if(aot_import_calls[i].call_rva==ctx->current->rva &&
               ctx->module_base<=UINT64_MAX-aot_import_calls[i].target_rva && pc==ctx->module_base+aot_import_calls[i].target_rva)
                signature=aot_import_calls[i].signature;
        } else if(ctx->current->kind==AOT_VTABLE_CALL && ctx->d3d_binding_valid &&
                  ctx->d3d_binding_pc==ctx->module_base+ctx->current->rva && ctx->d3d_binding_target==pc &&
                  ctx->d3d_object_index<session.next_slot)signature=ctx->d3d_signature;
        else if(ctx->current->kind==AOT_REGISTER_CALL && ctx->import_binding_valid &&
                ctx->import_binding_pc==ctx->module_base+ctx->current->rva && ctx->import_binding_target==pc)
            signature=ctx->import_signature;
    }
    ctx->current_pc=pc;
    bool user32_supported=signature==201 || (signature>=210 && signature<=222);
    bool import_supported=(signature>=4 && signature<=9) || signature==100 || signature==AOT_D3D_SIG_CREATE_SWAPCHAIN || user32_supported;
    bool supported=import_supported;
    for(unsigned i=0;i<AOT_D3D_METHOD_COUNT;i++)if(signature==method_signatures[i])supported=true;
    if(!supported || !ctx->current ||
       ((ctx->current->kind==AOT_CALL || ctx->current->kind==AOT_REGISTER_CALL) && !import_supported)) {
        fault(ctx,AOT_UNSUPPORTED,pc,0,AOT_EXEC);return opaque;
    }
    uint64_t rsp=aot_get_register(s,AOT_RSP),return_pc;
    if((rsp&15)!=8 || rsp>UINT64_MAX-104 || s->bytes[2075]) {fault(ctx,AOT_INVALID,rsp,0,0);return opaque;}
    if(ctx->result.steps>ctx->budget || (signature!=9 && ctx->result.steps==ctx->budget)) {fault(ctx,AOT_BUDGET,pc,0,0);return opaque;}
    const AotInstruction *ret=instruction(ctx,pc);AccessPlan code;
    if(!ret || ret->kind!=AOT_RET || ret->length!=1){fault(ctx,AOT_BAD_INSTRUCTION,pc,1,AOT_EXEC);return opaque;}
    if(!plan_access(ctx,pc,1,AOT_EXEC,&code))return opaque;
    if(*code.byte[0]!=0xc3){fault(ctx,AOT_BAD_INSTRUCTION,pc,1,AOT_EXEC);return opaque;}
    if(signature!=9) {
        if(!read_u64(ctx,rsp,&return_pc))return opaque;
        ReturnFrame frame=ctx->frames[ctx->result.call_depth-1];
        if(return_pc!=frame.pc || rsp+8!=frame.rsp){fault(ctx,AOT_BAD_RETURN,return_pc,0,AOT_EXEC);return opaque;}
    }
    for(unsigned i=0;i<4;i++){AccessPlan shadow;if(!plan_access(ctx,rsp+8+8*i,8,GM_READ|GM_WRITE,&shadow))return opaque;}
    if(signature==9) {
        session.exit_requested=1;session.exit_code=(uint32_t)aot_get_register(s,AOT_RCX);
        session.exit_pc=pc;session.exit_rsp=rsp;session.exit_depth=ctx->result.call_depth;session.stats.exit_calls++;return opaque;
    }
    bool has_result=true;uint64_t value=0;
    if(signature>=4 && signature<=8) {
        if(!window_files_ready){fault(ctx,AOT_INVALID,pc,0,0);return opaque;}
        uint64_t args[7]={aot_get_register(s,AOT_RCX),aot_get_register(s,AOT_RDX),
                         aot_get_register(s,AOT_R8),aot_get_register(s,AOT_R9),0,0,0};
        unsigned count=signature==4?7:(signature==5 || signature==6?5:0);
        for(unsigned i=4;i<count;i++)if(!read_u64(ctx,rsp+40+(i-4)*8,&args[i]))return opaque;
        if(signature==4)value=wfile_create(ctx,args);
        else if(signature==5 || signature==6)value=wfile_transfer(ctx,args,signature==6);
        else if(signature==7)value=wfile_close(args[0]);
        else value=wfile_get_last_error();
        if(!ctx->result.fault.status && !wfile_record_call(signature)){fault(ctx,AOT_INVALID,pc,0,0);return opaque;}
    } else if(signature==100)value=create_device(s,ctx,rsp);
    else if(signature==AOT_D3D_SIG_CREATE_SWAPCHAIN)value=create_swapchain(s,ctx,rsp);
    else if(user32_supported)value=wui_invoke(s,ctx,signature,rsp,&has_result);
    else value=invoke_method(s,ctx,signature,rsp,&has_result);
    /* Future synchronous User32 callbacks may ExitProcess. Preserve that
     * callback's terminal State/frames and never run an outer synthetic RET. */
    if(aot_should_exit(ctx))return opaque;
    ctx->d3d_binding_valid=0;ctx->import_binding_valid=0;if(has_result)aot_set_register(s,AOT_RAX,value);
    aot_import_ret(state,pc,opaque);return opaque;
}
