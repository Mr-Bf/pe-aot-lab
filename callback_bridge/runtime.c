/* Real synchronous host -> registered guest callback extension.
 * Reuses the frozen stage3 transaction engine and audited v1 memory checks.
 * Compatibility frame setup is explicit; callback instructions/RET are lifted.
 */
#define __remill_function_call aot_rejected_function_call
#define aot_execute aot_execute_base
#include "../integration_stage3/runtime.c"
#undef aot_execute
#undef __remill_function_call
#include "runtime.h"
#include <unistd.h>

typedef struct { uint32_t call_rva,iat_rva,target_rva,signature; } AotImportCall;
typedef struct { uint32_t rva,signature; AotEntry entry; } AotCallback;
#include "native_imports.h"
#include "callbacks.h"
extern void *aot_import_ret(void *,uint64_t,void *);

enum { MAX_CALLBACK_DEPTH=16 };
typedef struct {
    uintptr_t context_identity,state_identity; /* comparison only, never dereferenced */
    uint64_t api_calls,callback_calls,callback_returns;
    uint32_t depth,max_depth;
} BridgeSession;
static _Thread_local BridgeSession *active_session;
static _Thread_local BridgeSession last_session;
static const BridgeSession *statistics(void) {return active_session?active_session:&last_session;}
uint64_t aot_bridge_api_calls(void){return statistics()->api_calls;}
uint64_t aot_bridge_callback_calls(void){return statistics()->callback_calls;}
uint64_t aot_bridge_callback_returns(void){return statistics()->callback_returns;}
uint32_t aot_bridge_max_callback_depth(void){return statistics()->max_depth;}
uint64_t __attribute__((noinline)) aot_bridge_native_six(
    uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f) {
    return a+b*3+c*5+d*7+e*11+f*13;
}
static bool host_overlap(uintptr_t a,size_t an,uintptr_t b,size_t bn) {
    return an && bn && a<b+bn && b<a+an;
}
static bool bridge_memory_valid(AotState *s,AotContext *ctx) {
    /* C allocations/descriptors themselves are trusted. Reject backing aliases
     * which would violate Remill State noalias or mutate metadata mid-call. */
    uintptr_t state=(uintptr_t)s,context=(uintptr_t)ctx;
    uintptr_t table=(uintptr_t)ctx->instructions;
    size_t table_size=ctx->instruction_count*sizeof(AotInstruction);
    if(host_overlap(state,sizeof *s,context,sizeof *ctx) ||
       host_overlap(state,sizeof *s,table,table_size))return false;
    for(size_t i=0;i<ctx->region_count;i++) {
        GuestMemory *r=&ctx->regions[i];
        if(!gm_valid(r))return false;
        uintptr_t bytes=(uintptr_t)r->bytes,perms=(uintptr_t)r->permissions;
        if(r->size>UINTPTR_MAX-bytes || r->page_count>UINTPTR_MAX-perms)return false;
        if(host_overlap(bytes,r->size,state,sizeof *s) ||
           host_overlap(bytes,r->size,context,sizeof *ctx) ||
           host_overlap(bytes,r->size,table,table_size) ||
           host_overlap(perms,r->page_count,state,sizeof *s) ||
           host_overlap(perms,r->page_count,context,sizeof *ctx) ||
           host_overlap(perms,r->page_count,table,table_size))return false;
        for(size_t p=0;p<r->page_count;p++)
            if((r->permissions[p]&~7u) ||
               (r->permissions[p]&(GM_WRITE|AOT_EXEC))==(GM_WRITE|AOT_EXEC))return false;
        for(size_t j=0;j<ctx->region_count;j++) {
            GuestMemory *other=&ctx->regions[j];
            if(host_overlap(bytes,r->size,(uintptr_t)other->permissions,other->page_count))return false;
        }
    }
    return true;
}
uint32_t aot_execute(AotEntry entry,AotState *s,AotContext *ctx,uint64_t pc) {
    /* Nested guest callbacks use the private registered entry, never this API.
     * Reject public reentry without resetting the outer session's counters. */
    if(active_session)return AOT_INVALID;
    memset(&last_session,0,sizeof last_session);
    if(!entry || !s || !ctx || ((uintptr_t)s&15))return AOT_INVALID;
    if(!bridge_memory_valid(s,ctx))return AOT_INVALID;
    BridgeSession session={.context_identity=(uintptr_t)ctx,.state_identity=(uintptr_t)s};
    active_session=&session;
    uint32_t status=aot_execute_base(entry,s,ctx,pc);
    last_session=session;last_session.context_identity=0;last_session.state_identity=0;
    active_session=NULL;
    return status;
}
static bool bridge_read(AotContext *ctx,uint64_t address,uint64_t *value) {
    AccessPlan plan;
    if(!plan_access(ctx,address,8,GM_READ,&plan))return false;
    *value=0;
    for(unsigned i=0;i<8;i++)*value|=(uint64_t)*plan.byte[i]<<(8*i);
    return true;
}

typedef struct {
    BridgeSession *session;
    AotContext *ctx; AotState *state; /* derived from the actual helper arguments */
    const AotCallback *binding;
    uint64_t pc,rsp,return_pc,args[6];
    AccessPlan frame[7]; /* Return, four shadow slots, arguments five/six. */
    uint32_t expected_depth,used;
} CallbackRequest;
typedef struct {
    AotState state,snapshot;
    uint64_t current_pc,pending_value;
    const AotInstruction *current;
    uint32_t in_instruction,pending_size;
    AccessPlan pending;
} SavedBoundary;

static bool prepare_callback(CallbackRequest *request,AotState *s,AotContext *ctx,uint64_t pc,const uint64_t args[6]) {
    BridgeSession *session=active_session;
    if(!session)return false;
    memset(request,0,sizeof *request);request->session=session;request->pc=pc;
    request->ctx=ctx;request->state=s;
    for(size_t i=0;i<sizeof(callbacks)/sizeof(callbacks[0]);i++)
        if(callbacks[i].signature==1 && callbacks[i].entry &&
           ctx->module_base<=UINT64_MAX-callbacks[i].rva && pc==ctx->module_base+callbacks[i].rva) {
            request->binding=&callbacks[i];break;
        }
    if(!request->binding){fault(ctx,AOT_BAD_INSTRUCTION,pc,0,AOT_EXEC);return false;}
    if(session->depth>=MAX_CALLBACK_DEPTH || ctx->result.call_depth>=AOT_MAX_CALLS) {
        fault(ctx,AOT_CALL_DEPTH,pc,0,AOT_EXEC);return false;
    }
    if(ctx->result.steps>=ctx->budget){fault(ctx,AOT_BUDGET,pc,0,0);return false;}
    uint64_t outer_rsp=aot_get_register(s,AOT_RSP);
    if(outer_rsp<64 || (outer_rsp&15)!=8 || s->bytes[2075]) {
        fault(ctx,AOT_INVALID,outer_rsp,0,0);return false;
    }
    uint64_t marker_rva=UINT64_C(0xe0000000)+(session->depth+1)*16;
    if(ctx->module_base>UINT64_MAX-marker_rva){fault(ctx,AOT_INVALID,pc,0,0);return false;}
    request->return_pc=ctx->module_base+marker_rva;
    if(request->return_pc==ctx->exit_pc || instruction(ctx,request->return_pc)) {
        fault(ctx,AOT_INVALID,request->return_pc,0,AOT_EXEC);return false;
    }
    for(uint32_t i=0;i<ctx->result.call_depth;i++)if(ctx->frames[i].pc==request->return_pc) {
        fault(ctx,AOT_INVALID,request->return_pc,0,AOT_EXEC);return false;
    }
    const AotInstruction *first=instruction(ctx,pc);AccessPlan code;
    if(!first){fault(ctx,AOT_BAD_INSTRUCTION,pc,0,AOT_EXEC);return false;}
    if(!plan_access(ctx,pc,first->length,AOT_EXEC,&code))return false;
    request->rsp=outer_rsp-64;request->expected_depth=ctx->result.call_depth;
    /* Resolve every write before any State, shadow frame or guest byte changes.
     * Each slot can span independent adjacent host mappings. */
    for(unsigned i=0;i<7;i++)
        if(!plan_access(ctx,request->rsp+8*i,8,GM_READ|GM_WRITE,&request->frame[i]))return false;
    memcpy(request->args,args,sizeof request->args);
    return true;
}
static void store_planned(const AccessPlan *plan,uint64_t value) {
    for(unsigned i=0;i<8;i++)*plan->byte[i]=(uint8_t)(value>>(8*i));
}
typedef bool (*NativeCallback)(void *,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t *);
/* Ordinary Darwin ABI native function really invokes a typed host trampoline.
 * All arguments are forwarded unchanged; a callback fault returns no result. */
static __attribute__((noinline)) bool native_invoke(NativeCallback callback,void *opaque,
        uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,uint64_t *out) {
    uint64_t value=0;
    if(!callback(opaque,a,b,c,d,e,f,&value))return false;
    *out=value+23;
    return true;
}
static bool callback_trampoline(void *opaque,uint64_t a,uint64_t b,uint64_t c,
        uint64_t d,uint64_t e,uint64_t f,uint64_t *out) {
    CallbackRequest *request=opaque;
    BridgeSession *session=active_session;
    if(!request || session!=request->session || request->used)return false;
    AotContext *ctx=request->ctx;AotState *s=request->state;
    uint64_t args[6]={a,b,c,d,e,f};
    if(ctx->result.fault.status)return false;
    if(memcmp(args,request->args,sizeof args) || ctx->result.call_depth!=request->expected_depth ||
       ctx->in_instruction || ctx->pending_size || ctx->result.returned) {
        fault(ctx,AOT_INVALID,request->pc,0,0);return false;
    }
    SavedBoundary saved={.state=*s,.snapshot=ctx->snapshot,.current_pc=ctx->current_pc,
        .pending_value=ctx->pending_value,.current=ctx->current,
        .in_instruction=ctx->in_instruction,.pending_size=ctx->pending_size,.pending=ctx->pending};
    request->used=1;
    for(unsigned i=0;i<7;i++)store_planned(&request->frame[i],i==0?request->return_pc:(i>=5?args[i-1]:0));
    ctx->frames[ctx->result.call_depth++]=(ReturnFrame){request->return_pc,request->rsp+8};
    aot_set_register(s,AOT_RSP,request->rsp);
    aot_set_register(s,AOT_RCX,a);aot_set_register(s,AOT_RDX,b);
    aot_set_register(s,AOT_R8,c);aot_set_register(s,AOT_R9,d);
    aot_set_register(s,AOT_RIP,request->pc);
    session->depth++;session->callback_calls++;
    if(session->depth>session->max_depth)session->max_depth=session->depth;
    request->binding->entry(s,request->pc,ctx);
    session->depth--;
    /* Retain the exact fault State, first fault and committed guest memory when
     * unwinding native frames; never manufacture a successful outer return. */
    if(ctx->result.fault.status)return false;
    if(ctx->result.returned || ctx->in_instruction || ctx->pending_size ||
       ctx->result.call_depth!=request->expected_depth ||
       aot_get_register(s,AOT_RIP)!=request->return_pc ||
       aot_get_register(s,AOT_RSP)!=request->rsp+8) {
        fault(ctx,AOT_BAD_RETURN,aot_get_register(s,AOT_RIP),0,AOT_EXEC);return false;
    }
    static const unsigned preserved[]={AOT_RBX,AOT_RBP,AOT_RSI,AOT_RDI,AOT_R12,AOT_R13,AOT_R14,AOT_R15};
    for(unsigned i=0;i<sizeof(preserved)/sizeof(preserved[0]);i++)
        if(aot_get_register(s,preserved[i])!=aot_get_register(&saved.state,preserved[i])) {
            fault(ctx,AOT_INVALID,request->pc,0,0);return false;
        }
    if(s->bytes[2075]){fault(ctx,AOT_INVALID,request->pc,0,0);return false;}
    uint64_t value=aot_get_register(s,AOT_RAX);
    *s=saved.state;ctx->snapshot=saved.snapshot;ctx->current_pc=saved.current_pc;
    ctx->current=saved.current;ctx->pending_value=saved.pending_value;
    ctx->in_instruction=saved.in_instruction;ctx->pending_size=saved.pending_size;ctx->pending=saved.pending;
    session->callback_returns++;
    *out=value;
    return true;
}

void *__remill_function_call(void *state,uint64_t pc,void *opaque) {
    AotState *s=state;AotContext *ctx=opaque;
    if(!s || !ctx || aot_should_exit(ctx))return opaque;
    if(!active_session || active_session->context_identity!=(uintptr_t)ctx || active_session->state_identity!=(uintptr_t)s) {
        fault(ctx,AOT_INVALID,pc,0,0);return opaque;
    }
    const AotImportCall *binding=NULL;
    if(ctx->current && ctx->current->kind==AOT_CALL && !ctx->in_instruction &&
       ctx->result.call_depth && aot_get_register(s,AOT_RIP)==pc) {
        for(size_t i=0;i<sizeof(aot_import_calls)/sizeof(aot_import_calls[0]);i++)
            if(aot_import_calls[i].call_rva==ctx->current->rva &&
               ctx->module_base<=UINT64_MAX-aot_import_calls[i].target_rva &&
               pc==ctx->module_base+aot_import_calls[i].target_rva) {
                binding=&aot_import_calls[i];break;
            }
    }
    ctx->current_pc=pc;
    if(!binding){fault(ctx,AOT_UNSUPPORTED,pc,0,AOT_EXEC);return opaque;}
    uint64_t rsp=aot_get_register(s,AOT_RSP),return_pc=0;
    if((rsp&15)!=8 || rsp>UINT64_MAX-64){fault(ctx,AOT_INVALID,rsp,0,0);return opaque;}
    if(ctx->result.steps>=ctx->budget){fault(ctx,AOT_BUDGET,pc,0,0);return opaque;}
    const AotInstruction *ret_ins=instruction(ctx,pc);
    if(!ret_ins || ret_ins->kind!=AOT_RET || ret_ins->length!=1) {
        fault(ctx,AOT_BAD_INSTRUCTION,pc,1,AOT_EXEC);return opaque;
    }
    AccessPlan executable;
    if(!plan_access(ctx,pc,1,AOT_EXEC,&executable))return opaque;
    if(*executable.byte[0]!=0xc3){fault(ctx,AOT_BAD_INSTRUCTION,pc,1,AOT_EXEC);return opaque;}
    if(!bridge_read(ctx,rsp,&return_pc))return opaque;
    ReturnFrame frame=ctx->frames[ctx->result.call_depth-1];
    if(return_pc!=frame.pc || rsp+8!=frame.rsp) {
        fault(ctx,AOT_BAD_RETURN,return_pc,0,AOT_EXEC);return opaque;
    }
    for(unsigned i=0;i<4;i++) {
        AccessPlan shadow;
        if(!plan_access(ctx,rsp+8+8*i,8,GM_READ|GM_WRITE,&shadow))return opaque;
    }
    uint64_t result=0;
    switch(binding->signature) {
        case 1:active_session->api_calls++;result=(uint32_t)getpid();break;
        case 2: {
            uint64_t fifth,sixth;
            if(!bridge_read(ctx,rsp+40,&fifth) || !bridge_read(ctx,rsp+48,&sixth))return opaque;
            active_session->api_calls++;
            result=aot_bridge_native_six(aot_get_register(s,AOT_RCX),aot_get_register(s,AOT_RDX),
                    aot_get_register(s,AOT_R8),aot_get_register(s,AOT_R9),fifth,sixth);
            break;
        }
        case 3: {
            uint64_t args[6]={aot_get_register(s,AOT_RDX),aot_get_register(s,AOT_R8),aot_get_register(s,AOT_R9),0,0,0};
            if(!bridge_read(ctx,rsp+40,&args[3]) || !bridge_read(ctx,rsp+48,&args[4]) ||
               !bridge_read(ctx,rsp+56,&args[5]))return opaque;
            CallbackRequest request;
            if(!prepare_callback(&request,s,ctx,aot_get_register(s,AOT_RCX),args))return opaque;
            active_session->api_calls++;
            if(!native_invoke(callback_trampoline,&request,args[0],args[1],args[2],args[3],args[4],args[5],&result)) {
                if(!ctx->result.fault.status)fault(ctx,AOT_INVALID,pc,0,0);
                return opaque;
            }
            break;
        }
        default:fault(ctx,AOT_UNSUPPORTED,pc,0,AOT_EXEC);return opaque;
    }
    aot_set_register(s,AOT_RAX,result);
    aot_import_ret(s,pc,ctx);
    return opaque;
}
