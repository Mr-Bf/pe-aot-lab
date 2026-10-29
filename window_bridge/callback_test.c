/* Component acceptance only: actual window-profile Remill main/callback/RET
 * modules plus the exact transaction and callback include. This deliberately
 * supplies a closed test import dispatcher; it is NOT User32 or a GUI host. */
#include "runtime.h"
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
static bool d3d_validate_call(AotState *,AotContext *,uint64_t);
static bool import_validate_call(AotState *,AotContext *,uint64_t);
#define __remill_function_call callback_rejected_call
#define aot_execute callback_engine_execute
#define aot_should_exit callback_engine_stop
#define aot_begin callback_engine_begin
#define aot_commit callback_engine_commit
#include "transaction_v1.c"
#undef aot_commit
#undef aot_begin
#undef aot_should_exit
#undef aot_execute
#undef __remill_function_call
#include "callback_fixture.h"
typedef struct {uint32_t configured,running,used,exit_requested;uintptr_t context_identity,state_identity;} TestOwner;
static _Thread_local TestOwner session;
static uint64_t exit_pc,exit_rsp;static uint32_t exit_code,exit_depth;
static bool process_stopped(void *ctx){return session.exit_requested && session.context_identity==(uintptr_t)ctx;}
static bool host_overlap(uintptr_t a,size_t n,uintptr_t b,size_t m){return n&&m&&(a<=b?b-a<n:a-b<m);}
uint32_t aot_should_exit(void *p){return process_stopped(p)||callback_engine_stop(p);}
uint32_t aot_begin(void*s,uint64_t pc,void*p){return process_stopped(p)?1:callback_engine_begin(s,pc,p);}
uint32_t aot_commit(void*s,uint64_t pc,void*p){return process_stopped(p)?1:callback_engine_commit(s,pc,p);}
#include "callback_v1.inc"
extern void *aot_entry(void *,uint64_t,void *);
extern void *CALLBACK_SYMBOL(void *,uint64_t,void *);
extern void *aot_import_ret(void *,uint64_t,void *);
static unsigned hook,api_calls,boundary_checks,executions,checks,lowlevel_checks,registry_checks;
static uint8_t *stack_permissions;
static FILE *records;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"check failed %s:%d: %s (fixture=%d hook=%u)\n",__FILE__,__LINE__,#x,kVariant,hook);exit(90);}}while(0)
static uint64_t get64(const uint8_t*p){uint64_t n;memcpy(&n,p,8);return n;}
static void put64(uint8_t*p,uint64_t n){memcpy(p,&n,8);}
static uint64_t random64(uint64_t *x){*x^=*x<<13;*x^=*x>>7;*x^=*x<<17;return *x;}
static bool d3d_validate_call(AotState*s,AotContext*c,uint64_t pc){(void)s;fault(c,AOT_UNSUPPORTED,pc,0,0);return false;}
static bool import_validate_call(AotState*s,AotContext*c,uint64_t pc){
    const AotRegisterCall *r=NULL;
    for(size_t i=0;i<kRegisterCount;i++)if(kRegisterCalls[i].call_rva==c->current->rva)r=&kRegisterCalls[i];
    if(!r || r->operand_register>=16 || aot_get_register(&c->snapshot,r->operand_register)!=pc || pc!=c->module_base+kGetErrorThunk) {
        fault(c,AOT_BAD_METHOD,pc,0,AOT_EXEC);return false;
    }
    CHECK(session.running && session.state_identity==(uintptr_t)s && session.context_identity==(uintptr_t)c);
    c->import_binding_valid=1;c->import_signature=8;c->import_binding_pc=c->current_pc;c->import_binding_target=pc;return true;
}
static void injected_entry(void *state,uint64_t pc,void *opaque) {
    AotState*s=state;AotContext*c=opaque;CALLBACK_SYMBOL(state,pc,opaque);
    if(c->result.fault.status || process_stopped(c))return;
    if(hook==10)s->bytes[16+64*6]^=1; /* trusted host corruption, not an admitted SIMD instruction */
    if(hook==11)c->frames[0].pc^=16;
}
/* AotEntry returns Memory*. The hook above has a separate correctly typed
 * wrapper; the real root is always called using its exact signature. */
static void *hook_entry(void *state,uint64_t pc,void *opaque){injected_entry(state,pc,opaque);return opaque;}
void *__remill_function_call(void *state,uint64_t pc,void *opaque) {
    AotState*s=state;AotContext*c=opaque;
    if(aot_should_exit(c))return opaque;
    CHECK(session.running && session.context_identity==(uintptr_t)c && session.state_identity==(uintptr_t)s);
    uint32_t signature=0;
    for(size_t i=0;i<kImportCount;i++)if(pc==c->module_base+kImports[i].target_rva)signature=kImports[i].signature;
    CHECK(signature && c->current && !c->in_instruction && !c->pending_size && c->result.call_depth);
    CHECK(c->current->kind==AOT_CALL || c->current->kind==AOT_REGISTER_CALL);
    if(c->current->kind==AOT_REGISTER_CALL)CHECK(c->import_binding_valid && c->import_binding_target==pc);
    c->current_pc=pc;uint64_t rsp=aot_get_register(s,AOT_RSP);AccessPlan p;
    CHECK((rsp&15)==8 && plan_access(c,pc,1,AOT_EXEC,&p) && *p.byte[0]==0xc3);
    if(signature==9){api_calls++;session.exit_requested=1;exit_code=(uint32_t)aot_get_register(s,AOT_RCX);
        exit_pc=pc;exit_rsp=rsp;exit_depth=c->result.call_depth;return opaque;}
    CHECK(signature==8);
    if(c->result.steps>=c->budget){fault(c,AOT_BUDGET,pc,0,0);return opaque;}
    CHECK(plan_access(c,rsp,8,GM_READ,&p));uint64_t ret=0;for(unsigned j=0;j<8;j++)ret|=(uint64_t)*p.byte[j]<<(8*j);
    CHECK(ret==c->frames[c->result.call_depth-1].pc && rsp+8==c->frames[c->result.call_depth-1].rsp);
    api_calls++;
    uint64_t value=13;
    if(!window_callbacks.stats.depth || kVariant==2) {
        uint64_t target=c->module_base+kCallbackRva;
        uint32_t msg=(uint32_t)aot_get_register(s,AOT_RDX);
        if(window_callbacks.stats.depth){CHECK(msg>0);msg--;}
        /* Deliberately populate all inactive fields too: restoration must not
         * accidentally depend on just one active CALL form. */
        c->d3d_binding_valid=1;c->d3d_object_index=7;c->d3d_signature=0x1234;
        c->d3d_binding_pc=0xabc;c->d3d_binding_target=0xdef;
        if(c->current->kind==AOT_CALL){c->import_binding_valid=1;c->import_signature=8;c->import_binding_pc=c->module_base+c->current->rva;c->import_binding_target=pc;}
        c->pending_value=UINT64_C(0xfedcba9876543210);
        WindowCallbackBoundary before={0},after={0};wnd_save(&before,s,c);
        uint8_t saved_stack[40];AccessPlan slots[5];
        for(unsigned i=0;i<5;i++){CHECK(plan_access(c,rsp-48+8*i,8,GM_READ|GM_WRITE,&slots[i]));for(unsigned j=0;j<8;j++)saved_stack[i*8+j]=*slots[i].byte[j];}
        if(hook==1)target++;
        if(hook==2)window_callbacks.entries[0].signature=99;
        if(hook==3)stack_permissions[(rsp-48+32-UINT64_C(0x70000000))/4096]=GM_READ;
        if(hook==4)c->budget=c->result.steps;
        if(hook==5)s->bytes[2075]=1;
        if(hook==6)window_callbacks.stats.depth=AOT_WINDOW_MAX_CALLBACK_DEPTH;
        if(hook==7)c->frames[0].pc=c->module_base+UINT64_C(0xe0000010);
        if(hook==8)c->import_binding_target^=8;
        if(hook==12){ /* Last of five operands unmapped; first four still valid. */
            for(size_t i=0;i<c->region_count;i++)if(c->regions[i].base==UINT64_C(0x70000000)) {
                c->regions[i].size=(size_t)(rsp-48+32-c->regions[i].base);
                c->regions[i].page_count=(c->regions[i].size+4095)/4096;
            }
        }
        uint64_t output=UINT64_C(0xaabbaabbccddccdd);
        uint64_t *destination=hook==9?(uint64_t*)(s->bytes+reg_offsets[AOT_RAX]):&output;
        uint32_t status=aot_wndproc_invoke(s,c,target,aot_get_register(s,AOT_RCX),msg,aot_get_register(s,AOT_R8),aot_get_register(s,AOT_R9),destination);
        if(hook==6)window_callbacks.stats.depth=0; /* unwind only the host-injected sentinel */
        if(status!=AOT_OK){
            CHECK(output==UINT64_C(0xaabbaabbccddccdd));
            CHECK(status==(c->result.fault.status?c->result.fault.status:AOT_PROCESS_EXITED));
            if(hook && hook!=10 && hook!=11){for(unsigned i=0;i<5;i++)for(unsigned j=0;j<8;j++)CHECK(*slots[i].byte[j]==saved_stack[i*8+j]);lowlevel_checks++;}
            return opaque;
        }
        CHECK(!hook);wnd_save(&after,s,c);CHECK(!memcmp(&before,&after,sizeof before));boundary_checks++;
        value=output;
    }
    aot_set_register(s,AOT_RAX,value);c->d3d_binding_valid=0;c->import_binding_valid=0;
    aot_import_ret(s,pc,c);return opaque;
}
typedef struct {AotState*s;AotContext*c;uint8_t*image,*stack,*thunks;uint8_t sp[16];uint8_t*tp;uint64_t rsp,base,args[4];} Case;
static void destroy(Case*q){aot_context_destroy(q->c);aot_state_destroy(q->s);free(q->image);free(q->stack);free(q->thunks);free(q->tp);free(q);}
static Case *setup(uint64_t seed,uint32_t message,uint64_t budget,unsigned injection) {
    Case*q=calloc(1,sizeof *q);CHECK(q);q->s=aot_state_create();q->image=malloc(sizeof kImage);q->stack=malloc(65536);
    size_t thunk_size=(size_t)(kLastThunk-kFirstThunk)+4096;q->thunks=calloc(1,thunk_size);q->tp=calloc(1,thunk_size/4096);
    CHECK(q->s&&q->image&&q->stack&&q->thunks&&q->tp);q->base=kBase+(seed%3)*UINT64_C(0x20000000);
    q->rsp=UINT64_C(0x70004058); /* callback final shadow slot lies on the next guest page */
    memcpy(q->image,kImage,sizeof kImage);memset(q->stack,0xa5,65536);memset(q->sp,GM_READ|GM_WRITE,sizeof q->sp);stack_permissions=q->sp;
    for(unsigned i=0;i<AOT_STATE_SIZE;i++)q->s->bytes[i]=(uint8_t)random64(&seed);
    for(unsigned i=0;i<16;i++)aot_set_register(q->s,i,random64(&seed));
    const unsigned flags[]={2065,2067,2069,2071,2073,2075,2077};for(unsigned i=0;i<7;i++)q->s->bytes[flags[i]]=0;
    q->args[0]=UINT64_C(0x8000000000000042);q->args[1]=message;q->args[2]=random64(&seed);q->args[3]=random64(&seed);
    aot_set_register(q->s,AOT_RCX,q->args[0]);aot_set_register(q->s,AOT_RDX,UINT64_C(0xabcdef0000000000)|message);
    aot_set_register(q->s,AOT_R8,q->args[2]);aot_set_register(q->s,AOT_R9,q->args[3]);aot_set_register(q->s,AOT_RSP,q->rsp);
    put64(q->stack+(size_t)(q->rsp-UINT64_C(0x70000000)),UINT64_C(0x7fff00000000));
    for(size_t i=0;i<kImportCount;i++) {put64(q->image+kImports[i].iat_rva,q->base+kImports[i].target_rva);
        size_t off=(size_t)(kImports[i].target_rva-kFirstThunk);q->thunks[off]=0xc3;q->tp[off/4096]=GM_READ|AOT_EXEC;}
    q->c=aot_context_create(q->base,kInstructions,sizeof kInstructions/sizeof *kInstructions,budget,UINT64_C(0x7fff00000000),q->rsp);CHECK(q->c);
    GuestMemory image={q->base,sizeof kImage,q->image,kPermissions,sizeof kPermissions},stack={UINT64_C(0x70000000),65536,q->stack,q->sp,16};
    GuestMemory thunks={q->base+kFirstThunk,thunk_size,q->thunks,q->tp,thunk_size/4096};
    CHECK(!aot_add_region(q->c,&image)&&!aot_add_region(q->c,&stack)&&!aot_add_region(q->c,&thunks));
    memset(&session,0,sizeof session);session.configured=1;session.context_identity=(uintptr_t)q->c;
    AotWindowCallback binding={kCallbackRva,AOT_WINDOW_WNDPROC,injection>=10?hook_entry:CALLBACK_SYMBOL};
    if(!executions) {
        AotContext pristine=*q->c;AotWindowCallback invalid[2]={binding,binding};
        CHECK(aot_window_callbacks_begin(q->c,invalid,2)==AOT_INVALID);registry_checks++;
        invalid[0].signature=99;CHECK(aot_window_callbacks_begin(q->c,invalid,1)==AOT_INVALID);registry_checks++;
        invalid[0]=binding;invalid[0].entry=NULL;CHECK(aot_window_callbacks_begin(q->c,invalid,1)==AOT_INVALID);registry_checks++;
        invalid[0]=binding;invalid[0].rva=0xdeadbeef;CHECK(aot_window_callbacks_begin(q->c,invalid,1)==AOT_INVALID);registry_checks++;
        CHECK(aot_window_callbacks_begin(q->c,&binding,AOT_WINDOW_MAX_CALLBACKS+1)==AOT_INVALID);registry_checks++;
        CHECK(aot_window_callbacks_begin(q->c,NULL,1)==AOT_INVALID);registry_checks++;
        CHECK(aot_window_callbacks_begin(q->c,(AotWindowCallback*)q->stack,1)==AOT_INVALID);registry_checks++;
        session.running=1;CHECK(aot_window_callbacks_begin(q->c,&binding,1)==AOT_INVALID);session.running=0;registry_checks++;
        session.used=1;CHECK(aot_window_callbacks_begin(q->c,&binding,1)==AOT_INVALID);session.used=0;registry_checks++;
        CHECK(!memcmp(q->c,&pristine,sizeof pristine) && !window_callbacks.configured);
    }
    CHECK(!aot_window_callbacks_begin(q->c,&binding,1));
    binding.rva++;binding.signature=99;binding.entry=NULL; /* prove the host table was copied */
    hook=injection;api_calls=0;exit_pc=exit_rsp=0;exit_code=exit_depth=0;
    return q;
}
static uint32_t execute(Case*q){session.running=1;session.used=1;session.state_identity=(uintptr_t)q->s;
    CHECK(aot_window_callbacks_end(q->c)==AOT_INVALID);aot_entry(q->s,q->base+kEntryRva,q->c);session.running=0;executions++;
    uint32_t status=q->c->result.fault.status;if(!status && session.exit_requested)status=AOT_PROCESS_EXITED;
    else if(!status && (!q->c->result.returned || q->c->result.call_depth))status=AOT_NOT_RETURNED;
    if(status!=AOT_OK){AotState before=*q->s;AotContext context=*q->c;AotWindowCallbackStats stats=window_callbacks.stats;uint64_t untouched=0xbad;
        CHECK(aot_wndproc_invoke(q->s,q->c,q->base+kCallbackRva,1,2,3,4,&untouched)==status);
        CHECK(untouched==0xbad && !memcmp(&before,q->s,sizeof before) && !memcmp(&context,q->c,sizeof context) && !memcmp(&stats,&window_callbacks.stats,sizeof stats));}
    CHECK(window_callbacks.stats.depth==0);CHECK(!aot_window_callbacks_end(q->c));
    CHECK(fwrite(q->s,1,sizeof *q->s,records)==sizeof *q->s);
    CHECK(fwrite(&q->c->result,1,sizeof q->c->result,records)==sizeof q->c->result);
    CHECK(fwrite(q->c->frames,1,sizeof q->c->frames,records)==sizeof q->c->frames);
    CHECK(fwrite(q->stack+0x3c00,1,0x500,records)==0x500);
    CHECK(fwrite(q->image+kMarkerRva,1,16,records)==16);
    return status;
}
int main(int argc,char**argv){CHECK(argc==2);records=fopen(argv[1],"wb");CHECK(records);unsigned normals=0,cuts=0,hooks=0;uint64_t totalsteps=0;
    unsigned cases=(kVariant==0 || kVariant==8)?32:8;
    for(unsigned i=0;i<cases;i++) {
        uint32_t msg=kVariant==2?(i%4==0?0:i%4==1?1:i%4==2?3:15):((i&1)?UINT32_MAX:0);
        Case*q=setup(UINT64_C(0x937abc023401)+i,msg,10000,0);uint32_t status=execute(q);
        if(kVariant==3){CHECK(status==AOT_PROCESS_EXITED && !q->c->result.returned && !q->c->result.fault.status);
            CHECK(exit_code==UINT32_C(0x87654321)&&exit_pc==aot_get_register(q->s,AOT_RIP)&&exit_rsp==aot_get_register(q->s,AOT_RSP)&&exit_depth==q->c->result.call_depth);
            CHECK(window_callbacks.stats.calls==1 && !window_callbacks.stats.returns);}
        else if(kVariant>=4 && kVariant<=7){CHECK(status==(kVariant==4?AOT_INVALID:kVariant==5?AOT_BAD_RETURN:AOT_BOUNDS));CHECK(window_callbacks.stats.calls==1&&!window_callbacks.stats.returns);
            if(kVariant==4)CHECK(aot_get_register(q->s,AOT_RBX)==q->args[0]);
            if(kVariant==5)CHECK(q->c->result.fault.address==q->args[0] && q->c->result.call_depth==2);
            if(kVariant>=6)CHECK(q->c->result.fault.address==q->args[0] && q->c->result.call_depth==2);}
        else {uint64_t expected=(kVariant==1?13+17:q->args[0]+3*(uint64_t)(kVariant==2?0:msg)+5*q->args[2]+7*q->args[3]+17*(uint64_t)(kVariant==2?msg+1:1))+7;
            CHECK(status==AOT_OK && q->c->result.returned && !q->c->result.call_depth && aot_get_register(q->s,AOT_RAX)==expected);
            CHECK(get64(q->image+kMarkerRva)==expected);CHECK(window_callbacks.stats.calls==window_callbacks.stats.returns);
            CHECK(window_callbacks.stats.calls==(kVariant==2?msg+1:1));}
        if(status!=AOT_OK)CHECK(!get64(q->image+kMarkerRva));
        CHECK(!get64(q->image+kAfterExitRva));if(kVariant==7)CHECK(get64(q->image+kWriteMarkerRva)==0x1234);
        totalsteps+=q->c->result.steps;destroy(q);normals++;
    }
    /* Every actual prefix of one successful/Exit invocation. Post-callback
     * failure must not turn into a successful outer marker write early. */
    if(kVariant<=3 || kVariant==8){Case*baseline=setup(0x12345678,kVariant==2?2:19,10000,0);execute(baseline);uint64_t steps=baseline->c->result.steps;destroy(baseline);
        for(uint64_t budget=1;budget<=steps;budget++){Case*q=setup(0x12345678,kVariant==2?2:19,budget,0);uint32_t status=execute(q);
            CHECK(q->c->result.steps<=budget);if(budget<steps)CHECK(status==AOT_BUDGET);else CHECK(status==(kVariant==3?AOT_PROCESS_EXITED:AOT_OK));destroy(q);cuts++;}
    }
    if(kVariant==0 || kVariant==8){for(unsigned h=1;h<=12;h++){if(h==8&&kVariant!=8)continue;Case*q=setup(0x12345678,4,10000,h);uint32_t status=execute(q);
            CHECK(status!=AOT_OK && status!=AOT_PROCESS_EXITED && !get64(q->image+kMarkerRva));
            if(h!=10 && h!=11)CHECK(!window_callbacks.stats.calls);else CHECK(window_callbacks.stats.calls==1 && !window_callbacks.stats.returns);
            destroy(q);hooks++;}}
    if(kVariant==2){Case*q=setup(0x12345678,16,10000,0);CHECK(execute(q)==AOT_CALL_DEPTH);CHECK(window_callbacks.stats.calls==16&&!window_callbacks.stats.returns&&window_callbacks.stats.max_depth==16);CHECK(!get64(q->image+kMarkerRva));destroy(q);hooks++;}
    CHECK(!fclose(records));printf("{\"status\":\"PASS_COMPONENT_CALLBACK\",\"variant\":%d,\"ordinary_cases\":%u,\"budget_cases\":%u,\"host_injection_cases\":%u,\"registry_rejections\":%u,\"actual_executions\":%u,\"boundary_full_state_checks\":%u,\"preflight_zero_write_checks\":%u,\"checks\":%u,\"ordinary_steps\":%" PRIu64 ",\"gpu_executions\":0,\"windows_executions\":0}\n",kVariant,normals,cuts,hooks,registry_checks,executions,boundary_checks,lowlevel_checks,checks,totalsteps);return 0;
}
