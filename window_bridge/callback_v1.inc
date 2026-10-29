/* Included after transaction_v1.c and the owner session/process-stop helpers.
 * No independently retained State/Context pointer: live pointers descend from
 * the actual helper arguments (Remill marks those arguments noalias). TLS
 * stores only numeric owner identity, copied immutable roots and statistics. */
#include "callback_v1.h"
typedef struct {
    uintptr_t owner;
    uint32_t configured;
    size_t count;
    AotWindowCallback entries[AOT_WINDOW_MAX_CALLBACKS];
    AotWindowCallbackStats stats;
} WindowCallbackSession;
static _Thread_local WindowCallbackSession window_callbacks;

static bool wnd_host_storage(AotContext *ctx,const void *pointer,size_t size) {
    uintptr_t p=(uintptr_t)pointer;
    if(!pointer || size>UINTPTR_MAX-p ||
       host_overlap(p,size,(uintptr_t)ctx,sizeof *ctx) ||
       host_overlap(p,size,(uintptr_t)ctx->instructions,ctx->instruction_count*sizeof *ctx->instructions) ||
       host_overlap(p,size,(uintptr_t)&window_callbacks,sizeof window_callbacks) ||
       host_overlap(p,size,(uintptr_t)&session,sizeof session))return false;
    for(size_t i=0;i<ctx->region_count;i++) {
        const GuestMemory *r=&ctx->regions[i];
        if(host_overlap(p,size,(uintptr_t)r->bytes,r->size) ||
           host_overlap(p,size,(uintptr_t)r->permissions,r->page_count))return false;
    }
    return true;
}
/* Pure setup validation. It must not write a fault into a pristine Context. */
static bool wnd_entry_rx(AotContext *ctx,uint64_t pc) {
    const AotInstruction *first=instruction(ctx,pc);
    if(!first || !first->length || pc>UINT64_MAX-(first->length-1))return false;
    for(unsigned i=0;i<first->length;i++) {
        const GuestMemory *found=NULL;uint64_t address=pc+i;
        for(size_t j=0;j<ctx->region_count;j++) {
            const GuestMemory *r=&ctx->regions[j];
            if(address>=r->base && address-r->base<r->size){found=r;break;}
        }
        if(!found || found->permissions[(size_t)(address-found->base)/GM_PAGE]!=(GM_READ|AOT_EXEC))return false;
    }
    return true;
}
uint32_t aot_window_callbacks_begin(AotContext *ctx,const AotWindowCallback *bindings,size_t count) {
    if(!ctx || !session.configured || session.running || session.used ||
       session.context_identity!=(uintptr_t)ctx || window_callbacks.configured ||
       count>AOT_WINDOW_MAX_CALLBACKS || (count && !wnd_host_storage(ctx,bindings,count*sizeof *bindings)) ||
       ctx->result.steps || ctx->result.call_depth || ctx->result.returned ||
       ctx->result.fault.status || ctx->in_instruction || ctx->pending_size)return AOT_INVALID;
    AotWindowCallback copy[AOT_WINDOW_MAX_CALLBACKS];
    if(count)memcpy(copy,bindings,count*sizeof *bindings);
    for(size_t i=0;i<count;i++) {
        if(copy[i].signature!=AOT_WINDOW_WNDPROC || !copy[i].entry ||
           ctx->module_base>UINT64_MAX-copy[i].rva ||
           !wnd_entry_rx(ctx,ctx->module_base+copy[i].rva))return AOT_INVALID;
        for(size_t j=0;j<i;j++)
            if(copy[j].rva==copy[i].rva || copy[j].entry==copy[i].entry)return AOT_INVALID;
    }
    memset(&window_callbacks,0,sizeof window_callbacks);
    window_callbacks.owner=(uintptr_t)ctx;window_callbacks.configured=1;window_callbacks.count=count;
    if(count)memcpy(window_callbacks.entries,copy,count*sizeof *copy);
    return AOT_OK;
}
uint32_t aot_window_callbacks_end(AotContext *ctx) {
    if(!ctx || !window_callbacks.configured || window_callbacks.owner!=(uintptr_t)ctx ||
       session.running || window_callbacks.stats.depth)return AOT_INVALID;
    memset(window_callbacks.entries,0,sizeof window_callbacks.entries);
    window_callbacks.configured=0;window_callbacks.owner=0;window_callbacks.count=0;
    return AOT_OK;
}
void aot_window_callback_stats(AotWindowCallbackStats *out) {
    if(out)*out=window_callbacks.stats;
}
typedef struct {
    AotState state,snapshot;
    ReturnFrame frames[AOT_MAX_CALLS];
    uint64_t current_pc,pending_value;
    const AotInstruction *current;
    uint32_t in_instruction,pending_size;
    AccessPlan pending;
    uint32_t d3d_binding_valid,d3d_object_index,d3d_signature;
    uint64_t d3d_binding_pc,d3d_binding_target;
    uint32_t import_binding_valid,import_signature;
    uint64_t import_binding_pc,import_binding_target;
} WindowCallbackBoundary;
static void wnd_save(WindowCallbackBoundary *b,const AotState *s,const AotContext *ctx) {
    b->state=*s;b->snapshot=ctx->snapshot;memcpy(b->frames,ctx->frames,sizeof b->frames);
    b->current_pc=ctx->current_pc;b->current=ctx->current;b->pending_value=ctx->pending_value;
    b->in_instruction=ctx->in_instruction;b->pending_size=ctx->pending_size;b->pending=ctx->pending;
    b->d3d_binding_valid=ctx->d3d_binding_valid;b->d3d_object_index=ctx->d3d_object_index;
    b->d3d_signature=ctx->d3d_signature;b->d3d_binding_pc=ctx->d3d_binding_pc;b->d3d_binding_target=ctx->d3d_binding_target;
    b->import_binding_valid=ctx->import_binding_valid;b->import_signature=ctx->import_signature;
    b->import_binding_pc=ctx->import_binding_pc;b->import_binding_target=ctx->import_binding_target;
}
static void wnd_restore(const WindowCallbackBoundary *b,AotState *s,AotContext *ctx) {
    *s=b->state;ctx->snapshot=b->snapshot;memcpy(ctx->frames,b->frames,sizeof b->frames);
    ctx->current_pc=b->current_pc;ctx->current=b->current;ctx->pending_value=b->pending_value;
    ctx->in_instruction=b->in_instruction;ctx->pending_size=b->pending_size;ctx->pending=b->pending;
    ctx->d3d_binding_valid=b->d3d_binding_valid;ctx->d3d_object_index=b->d3d_object_index;
    ctx->d3d_signature=b->d3d_signature;ctx->d3d_binding_pc=b->d3d_binding_pc;ctx->d3d_binding_target=b->d3d_binding_target;
    ctx->import_binding_valid=b->import_binding_valid;ctx->import_signature=b->import_signature;
    ctx->import_binding_pc=b->import_binding_pc;ctx->import_binding_target=b->import_binding_target;
}
static uint32_t wnd_reject(AotContext *ctx,uint32_t status,uint64_t address,uint64_t width,uint32_t access) {
    window_callbacks.stats.rejections++;fault(ctx,status,address,width,access);return ctx->result.fault.status;
}
static void wnd_write64(const AccessPlan *plan,uint64_t value) {
    for(unsigned i=0;i<8;i++)*plan->byte[i]=(uint8_t)(value>>(8*i));
}
uint32_t aot_wndproc_invoke(AotState *s,AotContext *ctx,uint64_t target,
        uint64_t hwnd,uint32_t message,uint64_t wparam,uint64_t lparam,uint64_t *out) {
    if(!s || !ctx)return AOT_INVALID;
    if(ctx->result.fault.status)return ctx->result.fault.status;
    if(process_stopped(ctx))return AOT_PROCESS_EXITED;
    if(!session.running || session.context_identity!=(uintptr_t)ctx || session.state_identity!=(uintptr_t)s ||
       !window_callbacks.configured || window_callbacks.owner!=(uintptr_t)ctx ||
       !out || !wnd_host_storage(ctx,out,sizeof *out) || host_overlap((uintptr_t)out,sizeof *out,(uintptr_t)s,sizeof *s) ||
       ctx->in_instruction || ctx->pending_size || ctx->result.returned || !ctx->current ||
       !ctx->result.call_depth || ctx->result.call_depth>AOT_MAX_CALLS)
        return wnd_reject(ctx,AOT_INVALID,target,0,0);
    uint64_t api_pc=aot_get_register(s,AOT_RIP);
    bool import_boundary=ctx->current->kind==AOT_CALL &&
        ctx->current->target_rva<=UINT64_MAX-ctx->module_base && api_pc==ctx->module_base+ctx->current->target_rva;
    if(ctx->current->kind==AOT_REGISTER_CALL)
        import_boundary=ctx->import_binding_valid && ctx->import_binding_pc==ctx->module_base+ctx->current->rva &&
            ctx->import_binding_target==api_pc;
    if(!import_boundary)return wnd_reject(ctx,AOT_INVALID,api_pc,0,AOT_EXEC);
    const AotWindowCallback *binding=NULL;
    for(size_t i=0;i<window_callbacks.count;i++)
        if(ctx->module_base<=UINT64_MAX-window_callbacks.entries[i].rva &&
           target==ctx->module_base+window_callbacks.entries[i].rva){binding=&window_callbacks.entries[i];break;}
    if(!binding || binding->signature!=AOT_WINDOW_WNDPROC || !binding->entry)
        return wnd_reject(ctx,AOT_BAD_INSTRUCTION,target,0,AOT_EXEC);
    if(window_callbacks.stats.depth>=AOT_WINDOW_MAX_CALLBACK_DEPTH || ctx->result.call_depth>=AOT_MAX_CALLS)
        return wnd_reject(ctx,AOT_CALL_DEPTH,target,0,AOT_EXEC);
    if(ctx->result.steps>=ctx->budget)return wnd_reject(ctx,AOT_BUDGET,target,0,0);
    uint64_t outer_rsp=aot_get_register(s,AOT_RSP);
    if(outer_rsp<48 || (outer_rsp&15)!=8 || s->bytes[2075])return wnd_reject(ctx,AOT_INVALID,outer_rsp,0,0);
    uint64_t marker_rva=UINT64_C(0xe0000000)+(window_callbacks.stats.depth+1)*16;
    if(ctx->module_base>UINT64_MAX-marker_rva)return wnd_reject(ctx,AOT_INVALID,target,0,0);
    uint64_t marker=ctx->module_base+marker_rva,entry_rsp=outer_rsp-48;
    if(marker==ctx->exit_pc || instruction(ctx,marker))return wnd_reject(ctx,AOT_INVALID,marker,0,AOT_EXEC);
    for(uint32_t i=0;i<ctx->result.call_depth;i++)if(ctx->frames[i].pc==marker)
        return wnd_reject(ctx,AOT_INVALID,marker,0,AOT_EXEC);
    const AotInstruction *first=instruction(ctx,target);AccessPlan code,frame[5];
    if(!first)return wnd_reject(ctx,AOT_BAD_INSTRUCTION,target,0,AOT_EXEC);
    if(!plan_access(ctx,target,first->length,AOT_EXEC,&code)){window_callbacks.stats.rejections++;return ctx->result.fault.status;}
    /* Five independent 8-byte operands, fully preflighted before all writes.
     * Each operand retains the engine's bounds-before-permission rule. */
    for(unsigned i=0;i<5;i++)if(!plan_access(ctx,entry_rsp+8*i,8,GM_READ|GM_WRITE,&frame[i])) {
        window_callbacks.stats.rejections++;return ctx->result.fault.status;
    }
    WindowCallbackBoundary saved;wnd_save(&saved,s,ctx);
    uint32_t expected_depth=ctx->result.call_depth;
    for(unsigned i=0;i<5;i++)wnd_write64(&frame[i],i?0:marker);
    ctx->frames[ctx->result.call_depth++]=(ReturnFrame){marker,entry_rsp+8};
    aot_set_register(s,AOT_RSP,entry_rsp);aot_set_register(s,AOT_RIP,target);
    aot_set_register(s,AOT_RCX,hwnd);aot_set_register(s,AOT_RDX,message);
    aot_set_register(s,AOT_R8,wparam);aot_set_register(s,AOT_R9,lparam);
    window_callbacks.stats.calls++;window_callbacks.stats.depth++;
    if(window_callbacks.stats.depth>window_callbacks.stats.max_depth)window_callbacks.stats.max_depth=window_callbacks.stats.depth;
    binding->entry(s,target,ctx);
    window_callbacks.stats.depth--;
    /* Unwind only native frames on a fault/Exit. The exact failing callback
     * State, guest call frames, committed memory and exit latch stay visible. */
    if(ctx->result.fault.status)return ctx->result.fault.status;
    if(process_stopped(ctx))return AOT_PROCESS_EXITED;
    if(ctx->result.returned || ctx->in_instruction || ctx->pending_size || ctx->result.call_depth!=expected_depth ||
       aot_get_register(s,AOT_RIP)!=marker || aot_get_register(s,AOT_RSP)!=entry_rsp+8 ||
       memcmp(ctx->frames,saved.frames,expected_depth*sizeof *ctx->frames))
        return wnd_reject(ctx,AOT_BAD_RETURN,aot_get_register(s,AOT_RIP),0,AOT_EXEC);
    static const unsigned preserved[]={AOT_RBX,AOT_RBP,AOT_RSI,AOT_RDI,AOT_R12,AOT_R13,AOT_R14,AOT_R15};
    for(unsigned i=0;i<sizeof preserved/sizeof preserved[0];i++)
        if(aot_get_register(s,preserved[i])!=aot_get_register(&saved.state,preserved[i]))
            return wnd_reject(ctx,AOT_INVALID,target,0,0);
    /* Pinned Remill State: vec starts at 16, stride 64, XMM low 128 bits.
     * test_callback.py compiles offsetof/sizeof assertions against that exact
     * State header. No SIMD instruction is admitted by this integer profile. */
    for(unsigned i=6;i<=15;i++)if(memcmp(s->bytes+16+64*i,saved.state.bytes+16+64*i,16))
        return wnd_reject(ctx,AOT_INVALID,target,0,0);
    if(s->bytes[2075])return wnd_reject(ctx,AOT_INVALID,target,0,0);
    uint64_t value=aot_get_register(s,AOT_RAX);
    wnd_restore(&saved,s,ctx);window_callbacks.stats.returns++;*out=value;return AOT_OK;
}
