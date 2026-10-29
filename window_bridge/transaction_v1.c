/* Window profile: real kind 3 COM CALL and kind 4 register IAT CALL.
 * Every indirect target is resolved before instruction effects commit. */
#include "runtime.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* Validated against the pinned Remill State on four target triples. These are
 * guest register byte offsets, not a claim that State is a Darwin C ABI. */
static const uint16_t reg_offsets[17] = {
    2216,2248,2264,2232,2312,2328,2280,2296,
    2344,2360,2376,2392,2408,2424,2440,2456,2472
};
typedef struct { uint8_t *byte[16]; } AccessPlan;
typedef struct { uint64_t pc, rsp; } ReturnFrame;
struct AotContext {
    uint64_t module_base, budget, exit_pc, initial_rsp;
    AotInstruction *instructions;
    size_t instruction_count, region_count;
    GuestMemory regions[AOT_MAX_REGIONS];
    AotResult result;
    uint64_t current_pc;
    const AotInstruction *current;
    uint32_t in_instruction, pending_size;
    AccessPlan pending;
    uint64_t pending_value;
    ReturnFrame frames[AOT_MAX_CALLS];
    /* Separate storage, never a pointer to the live State (which is noalias). */
    AotState snapshot;
    uint32_t d3d_binding_valid,d3d_object_index,d3d_signature;
    uint64_t d3d_binding_pc,d3d_binding_target;
    uint32_t import_binding_valid,import_signature;
    uint64_t import_binding_pc,import_binding_target;
    uint8_t *d3d_map_permissions; /* owned arena permission overlay */
};

AotState *aot_state_create(void) { return (AotState *)calloc(1,sizeof(AotState)); }
void aot_state_destroy(AotState *s) { free(s); }
uint64_t aot_get_register(const AotState *s,uint32_t reg) {
    uint64_t value=0;
    if(s && reg<17) memcpy(&value,s->bytes+reg_offsets[reg],8);
    return value;
}
void aot_set_register(AotState *s,uint32_t reg,uint64_t value) {
    if(s && reg<17) memcpy(s->bytes+reg_offsets[reg],&value,8);
}
uint32_t aot_get_flags(const AotState *s) {
    const unsigned offsets[]={2065,2067,2069,2071,2073,2077};
    const unsigned bits[]={0,2,4,6,7,11}; uint32_t value=0;
    for(unsigned i=0;i<6;i++) value|=(uint32_t)(s->bytes[offsets[i]]!=0)<<bits[i];
    return value;
}
static int compare_instruction(const void *a,const void *b) {
    uint32_t x=((const AotInstruction*)a)->rva,y=((const AotInstruction*)b)->rva;
    return (x>y)-(x<y);
}
AotContext *aot_context_create(uint64_t base,const AotInstruction *instructions,
    size_t count,uint64_t budget,uint64_t exit_pc,uint64_t rsp) {
    if(!instructions || !count || count>1048576 || !budget || rsp>UINT64_MAX-8) return NULL;
    AotContext *ctx=(AotContext*)calloc(1,sizeof *ctx); if(!ctx)return NULL;
    ctx->instructions=(AotInstruction*)malloc(count*sizeof *instructions);
    if(!ctx->instructions){free(ctx);return NULL;}
    memcpy(ctx->instructions,instructions,count*sizeof *instructions);
    qsort(ctx->instructions,count,sizeof *instructions,compare_instruction);
    for(size_t i=0;i<count;i++) {
        AotInstruction *ins=&ctx->instructions[i];
        uint64_t end=(uint64_t)ins->rva+ins->length;
        if(!ins->length || ins->length>15 || ins->kind>AOT_REGISTER_CALL || end>UINT32_MAX ||
           base>UINT64_MAX-end || (i && (uint64_t)ctx->instructions[i-1].rva+
           ctx->instructions[i-1].length>ins->rva)) {aot_context_destroy(ctx);return NULL;}
    }
    ctx->module_base=base;ctx->instruction_count=count;ctx->budget=budget;
    ctx->exit_pc=exit_pc;ctx->initial_rsp=rsp;return ctx;
}
void aot_context_destroy(AotContext *ctx) {if(ctx){free(ctx->d3d_map_permissions);free(ctx->instructions);free(ctx);}}
uint32_t aot_add_region(AotContext *ctx,const GuestMemory *region) {
    if(!ctx || !gm_valid(region) || ctx->region_count==AOT_MAX_REGIONS)return AOT_INVALID;
    uintptr_t host=(uintptr_t)region->bytes;
    if(region->size>UINTPTR_MAX-host)return AOT_INVALID;
    for(size_t i=0;i<region->page_count;i++)
        if((region->permissions[i]&~7u) ||
           ((region->permissions[i]&(GM_WRITE|AOT_EXEC))==(GM_WRITE|AOT_EXEC)))return AOT_INVALID;
    for(size_t i=0;i<ctx->region_count;i++) {
        const GuestMemory *r=&ctx->regions[i];
        if(region->base<r->base+r->size && r->base<region->base+region->size)return AOT_INVALID;
        uintptr_t other=(uintptr_t)r->bytes;
        if(host<other+r->size && other<host+region->size)return AOT_INVALID;
    }
    ctx->regions[ctx->region_count++]=*region;return AOT_OK;
}
static void fault(AotContext *ctx,uint32_t status,uint64_t address,uint64_t width,uint32_t access) {
    if(!ctx->result.fault.status) ctx->result.fault=(AotFault){status,access,ctx->current_pc,address,width};
}
static bool plan_access(AotContext *ctx,uint64_t address,unsigned width,uint32_t access,AccessPlan *plan) {
    if(ctx->result.fault.status)return false;
    if(!width || width>16 || address>UINT64_MAX-(width-1)) {
        fault(ctx,AOT_BOUNDS,address,width,access);return false;
    }
    /* Validate every byte before any read or committed write. Adjacent guest
     * mappings can have unrelated host allocations; never form a spanning ptr. */
    uint8_t permissions[16];
    for(unsigned i=0;i<width;i++) {
        uint64_t a=address+i;const GuestMemory *found=NULL;
        for(size_t j=0;j<ctx->region_count;j++) {
            const GuestMemory *r=&ctx->regions[j];
            if(a>=r->base && a-r->base<r->size){found=r;break;}
        }
        if(!found){fault(ctx,AOT_BOUNDS,address,width,access);return false;}
        size_t off=(size_t)(a-found->base);
        permissions[i]=found->permissions[off/GM_PAGE];
        plan->byte[i]=found->bytes+off;
    }
    /* Match the address-space contract: resolve the entire range before checking
     * permissions. Mixed unmapped/protected accesses report BOUNDS consistently. */
    for(unsigned i=0;i<width;i++)if((permissions[i]&access)!=access) {
        fault(ctx,AOT_PROTECTION,address,width,access);return false;
    }
    return true;
}
static const AotInstruction *instruction(AotContext *ctx,uint64_t pc) {
    if(pc<ctx->module_base || pc-ctx->module_base>UINT32_MAX)return NULL;
    AotInstruction key={(uint32_t)(pc-ctx->module_base),0,0,0,0};
    return bsearch(&key,ctx->instructions,ctx->instruction_count,sizeof key,compare_instruction);
}
uint32_t aot_should_exit(void *opaque) {
    AotContext *ctx=(AotContext*)opaque;
    return !ctx || ctx->result.fault.status || ctx->result.returned;
}
uint32_t aot_begin(void *state,uint64_t pc,void *opaque) {
    AotState *s=(AotState*)state;AotContext *ctx=(AotContext*)opaque;
    if(aot_should_exit(ctx))return 1; /* Preserve a callee's exact failure state. */
    ctx->current_pc=pc;
    aot_set_register(s,AOT_RIP,pc);
    if(ctx->in_instruction){fault(ctx,AOT_INVALID,pc,0,0);return 1;}
    if(ctx->result.steps>=ctx->budget){fault(ctx,AOT_BUDGET,pc,0,0);return 1;}
    ctx->current=instruction(ctx,pc);
    if(!ctx->current){fault(ctx,AOT_BAD_INSTRUCTION,pc,0,AOT_EXEC);return 1;}
    AccessPlan executable;
    if(!plan_access(ctx,pc,ctx->current->length,AOT_EXEC,&executable))return 1;
    memcpy(&ctx->snapshot,s,sizeof *s);ctx->pending_size=0;ctx->d3d_binding_valid=0;ctx->import_binding_valid=0;
    ctx->in_instruction=1;ctx->result.steps++;
    return 0;
}
uint32_t aot_commit(void *state,uint64_t next_pc,void *opaque) {
    AotState *s=(AotState*)state;AotContext *ctx=(AotContext*)opaque;
    if(!ctx || !ctx->in_instruction)return 1;
    uint32_t depth=ctx->result.call_depth;
    if(!ctx->result.fault.status && (ctx->current->kind==AOT_CALL || ctx->current->kind==AOT_VTABLE_CALL || ctx->current->kind==AOT_REGISTER_CALL)) {
        if(depth==AOT_MAX_CALLS)fault(ctx,AOT_CALL_DEPTH,next_pc,0,AOT_EXEC);
        else if(ctx->current->kind==AOT_VTABLE_CALL) {
            if(!d3d_validate_call(s,ctx,next_pc) && !ctx->result.fault.status)
                fault(ctx,AOT_BAD_INSTRUCTION,next_pc,0,AOT_EXEC);
        } else if(ctx->current->kind==AOT_REGISTER_CALL) {
            if(!import_validate_call(s,ctx,next_pc) && !ctx->result.fault.status)
                fault(ctx,AOT_BAD_INSTRUCTION,next_pc,0,AOT_EXEC);
        } else if(ctx->current->target_rva>UINT64_MAX-ctx->module_base ||
            next_pc!=ctx->module_base+ctx->current->target_rva)
            fault(ctx,AOT_BAD_INSTRUCTION,next_pc,0,AOT_EXEC);
    }
    if(!ctx->result.fault.status && ctx->current->kind==AOT_RET) {
        uint64_t expected_pc=depth?ctx->frames[depth-1].pc:ctx->exit_pc;
        uint64_t expected_rsp=depth?ctx->frames[depth-1].rsp:ctx->initial_rsp+8;
        if(next_pc!=expected_pc || aot_get_register(s,AOT_RSP)!=expected_rsp)
            fault(ctx,AOT_BAD_RETURN,next_pc,0,AOT_EXEC);
    }
    if(ctx->result.fault.status) {
        memcpy(s,&ctx->snapshot,sizeof *s);ctx->pending_size=0;ctx->in_instruction=0;ctx->d3d_binding_valid=0;ctx->import_binding_valid=0;
        return 1;
    }
    for(unsigned i=0;i<ctx->pending_size;i++)*ctx->pending.byte[i]=(uint8_t)(ctx->pending_value>>(8*i));
    if((ctx->current->kind==AOT_CALL || ctx->current->kind==AOT_VTABLE_CALL || ctx->current->kind==AOT_REGISTER_CALL)) {
        ctx->frames[depth]=(ReturnFrame){ctx->current_pc+ctx->current->length,aot_get_register(&ctx->snapshot,AOT_RSP)};
        ctx->result.call_depth++;
    } else if(ctx->current->kind==AOT_RET) {
        if(depth)ctx->result.call_depth--;else ctx->result.returned=1;
    }
    aot_set_register(s,AOT_RIP,next_pc);ctx->pending_size=0;ctx->in_instruction=0;
    return 0;
}
static uint64_t read_value(AotContext *ctx,uint64_t address,unsigned width) {
    AccessPlan plan;uint64_t value=0;
    if(!ctx->in_instruction){fault(ctx,AOT_INVALID,address,width,GM_READ);return 0;}
    if(!plan_access(ctx,address,width,GM_READ,&plan))return 0;
    for(unsigned i=0;i<width;i++)value|=(uint64_t)*plan.byte[i]<<(8*i);
    return value;
}
static void *write_value(AotContext *ctx,uint64_t address,uint64_t value,unsigned width) {
    if(!ctx->in_instruction){fault(ctx,AOT_INVALID,address,width,GM_WRITE);return ctx;}
    if(ctx->pending_size){fault(ctx,AOT_MULTIWRITE,address,width,GM_WRITE);return ctx;}
    if(plan_access(ctx,address,width,GM_WRITE,&ctx->pending)) {
        ctx->pending_size=width;ctx->pending_value=value;
    }
    return ctx;
}
#define MEMORY_INTRINSICS(bits,type) \
type __remill_read_memory_##bits(void *ctx,uint64_t address) {return (type)read_value(ctx,address,sizeof(type));} \
void *__remill_write_memory_##bits(void *ctx,uint64_t address,type value) {return write_value(ctx,address,value,sizeof(type));}
MEMORY_INTRINSICS(8,uint8_t)
MEMORY_INTRINSICS(16,uint16_t)
MEMORY_INTRINSICS(32,uint32_t)
MEMORY_INTRINSICS(64,uint64_t)

void *__remill_function_return(void *state,uint64_t pc,void *opaque) {
    (void)state;(void)pc;return opaque; /* RET transaction already checked the real guest stack result. */
}
#define REJECT_CONTROL(name) \
void *name(void *state,uint64_t pc,void *opaque) { \
 (void)state;AotContext *ctx=(AotContext*)opaque;fault(ctx,AOT_UNSUPPORTED,pc,0,AOT_EXEC);return opaque;}
REJECT_CONTROL(__remill_error)
REJECT_CONTROL(__remill_missing_block)
REJECT_CONTROL(__remill_jump)
REJECT_CONTROL(__remill_function_call)

/* An architecturally undefined flag receives a defined arbitrary value. The
 * supported instruction profile must not treat undefined AF as a contract. */
uint8_t __remill_undefined_8(void) {return 0;}
#define FLAG(name) bool name(bool value,...) {return value;}
FLAG(__remill_flag_computation_zero)
FLAG(__remill_flag_computation_sign)
FLAG(__remill_flag_computation_overflow)
FLAG(__remill_flag_computation_carry)
#define COMPARE(name) bool name(bool value) {return value;}
COMPARE(__remill_compare_sle) COMPARE(__remill_compare_slt)
COMPARE(__remill_compare_sge) COMPARE(__remill_compare_sgt)
COMPARE(__remill_compare_ule) COMPARE(__remill_compare_ult)
COMPARE(__remill_compare_uge) COMPARE(__remill_compare_ugt)
COMPARE(__remill_compare_eq) COMPARE(__remill_compare_neq)

uint32_t aot_execute(AotEntry entry,AotState *state,AotContext *ctx,uint64_t pc) {
    if(!entry || !state || !ctx || ((uintptr_t)state&15))return AOT_INVALID;
    if(ctx->result.steps || ctx->in_instruction || ctx->result.returned || ctx->result.fault.status)return AOT_INVALID;
    entry(state,pc,ctx);
    if(!ctx->result.fault.status && (!ctx->result.returned || ctx->result.call_depth)) {
        ctx->current_pc=aot_get_register(state,AOT_RIP);fault(ctx,AOT_NOT_RETURNED,ctx->current_pc,0,0);
    }
    return ctx->result.fault.status;
}
void aot_result(const AotContext *ctx,AotResult *result) {if(ctx && result)*result=ctx->result;}
