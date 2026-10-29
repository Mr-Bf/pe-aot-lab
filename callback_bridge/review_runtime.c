/* Independent actual-root replay. Include the real implementation once so the
 * trusted C harness can check context lifecycle, without ABI surrogate code. */
#include "runtime.c"
#include <inttypes.h>
#include <stdio.h>
#include "sanitizer_fixture.h"
extern void *aot_entry(void *,uint64_t,void *);
enum {STACK_SIZE=65536,THUNK_SIZE=4096};
static const uint64_t EXIT_PC=UINT64_C(0x7fff00000000),STACK_BASE=UINT64_C(0x70000000);
static unsigned current_case,current_variant,reentry_checks,boundary_checks;
static void failed(const char *text,unsigned line) {
    fprintf(stderr,"callback sanitizer fixture=%d mutant=%d case=%u variant=%u line=%u: %s\n",
            kFixture,kMutant,current_case,current_variant,line,text);exit(2);
}
#define CHECK(value) do {if(!(value))failed(#value,__LINE__);}while(0)
static uint64_t random64(uint64_t *state) {
    uint64_t x=*state;x^=x<<13;x^=x>>7;x^=x<<17;return *state=x;
}
static void put64(uint8_t *bytes,size_t offset,uint64_t value){memcpy(bytes+offset,&value,8);}
static uint64_t weighted(const uint64_t *a){return a[0]+3*a[1]+5*a[2]+7*a[3]+11*a[4]+13*a[5];}
static uint32_t add_flags(uint64_t a,uint64_t b) {
    uint64_t r=a+b;uint32_t parity=0;
    for(unsigned bit=0;bit<8;bit++)parity^=(uint32_t)(r>>bit)&1u;
    return (r<a) | ((parity^1u)<<2) | (uint32_t)((a^b^r)&16u) |
        ((r==0)<<6) | ((uint32_t)(r>>63)<<7) |
        ((uint32_t)((~(a^b)&(a^r))>>63)<<11);
}
typedef struct {
    AotState *state;AotContext *ctx;AotResult result;
    uint8_t *image,*stack,*expected,*thunks[2];
    uint8_t image_permissions[sizeof kImagePermissions],stack_permissions[16],thunk_permissions[2];
    uint64_t base,rsp,cb_rsp,args[6],initial[17];
} Case;
static Case *make_case(unsigned variant,uint64_t budget,uint64_t seed) {
    Case *c=calloc(1,sizeof *c);CHECK(c);
    c->state=aot_state_create();c->image=malloc(sizeof kImage);c->stack=malloc(STACK_SIZE);c->expected=malloc(STACK_SIZE);
    CHECK(c->state && c->image && c->stack && c->expected);
    c->base=kPreferredBase+(seed%8)*UINT64_C(0x100000);c->rsp=STACK_BASE+(variant?0x4068:0x4008);c->cb_rsp=c->rsp-128;
    for(unsigned i=0;i<AOT_STATE_SIZE;i++)c->state->bytes[i]=(uint8_t)random64(&seed);
    for(unsigned i=0;i<17;i++){c->initial[i]=random64(&seed);aot_set_register(c->state,i,c->initial[i]);}
    for(unsigned i=0;i<6;i++)c->args[i]=random64(&seed);
    if(kFixture==3)c->args[0]%=5;
    c->initial[AOT_RBX]=~c->args[0];aot_set_register(c->state,AOT_RBX,c->initial[AOT_RBX]);
    c->state->bytes[2075]=variant==3?1:0;
    const unsigned param[]={AOT_RCX,AOT_RDX,AOT_R8,AOT_R9};
    for(unsigned i=0;i<4;i++){c->initial[param[i]]=c->args[i];aot_set_register(c->state,param[i],c->args[i]);}
    c->initial[AOT_RSP]=c->rsp;aot_set_register(c->state,AOT_RSP,c->rsp);
    memcpy(c->image,kImage,sizeof kImage);memcpy(c->image_permissions,kImagePermissions,sizeof kImagePermissions);
    memset(c->stack,0xa5,STACK_SIZE);memset(c->stack_permissions,GM_READ|GM_WRITE,sizeof c->stack_permissions);
    put64(c->stack,c->rsp-STACK_BASE,EXIT_PC);put64(c->stack,c->rsp-STACK_BASE+40,c->args[4]);
    put64(c->stack,c->rsp-STACK_BASE+48,c->args[5]);memcpy(c->expected,c->stack,STACK_SIZE);
    c->ctx=aot_context_create(c->base,kInstructions,sizeof kInstructions/sizeof kInstructions[0],budget,EXIT_PC,c->rsp);CHECK(c->ctx);
    GuestMemory region={c->base,sizeof kImage,c->image,c->image_permissions,sizeof c->image_permissions};
    CHECK(aot_add_region(c->ctx,&region)==AOT_OK);
    if(variant==1) {
        /* First two callback frame slots are mapped; the third is in an 8B
         * hole. Main CALL/outgoing arguments reside in the upper mapping. */
        region=(GuestMemory){STACK_BASE,0x3ff8,c->stack,c->stack_permissions,4};
        CHECK(aot_add_region(c->ctx,&region)==AOT_OK);
        region=(GuestMemory){STACK_BASE+0x4000,STACK_SIZE-0x4000,c->stack+0x4000,c->stack_permissions+4,12};
    } else {
        if(variant==2)c->stack_permissions[3]=GM_READ;
        region=(GuestMemory){STACK_BASE,STACK_SIZE,c->stack,c->stack_permissions,16};
    }
    CHECK(aot_add_region(c->ctx,&region)==AOT_OK);
    for(unsigned i=0;i<kThunkCount;i++) {
        c->thunks[i]=calloc(1,THUNK_SIZE);CHECK(c->thunks[i]);c->thunks[i][0]=0xc3;c->thunk_permissions[i]=GM_READ|AOT_EXEC;
        put64(c->image,kIatRvas[i],c->base+kThunkRvas[i]);
        region=(GuestMemory){c->base+kThunkRvas[i],THUNK_SIZE,c->thunks[i],&c->thunk_permissions[i],1};
        CHECK(aot_add_region(c->ctx,&region)==AOT_OK);
    }
    return c;
}
static void destroy(Case *c) {
    aot_context_destroy(c->ctx);aot_state_destroy(c->state);free(c->image);free(c->stack);free(c->expected);
    for(unsigned i=0;i<kThunkCount;i++)free(c->thunks[i]);free(c);
}
static void *audited_entry(void *state,uint64_t pc,void *opaque) {
    void *result=aot_entry(state,pc,opaque);
    AotState saved=*(AotState*)state;AotResult prior=((AotContext*)opaque)->result;
    uint64_t api=aot_bridge_api_calls(),calls=aot_bridge_callback_calls(),returns=aot_bridge_callback_returns();
    uint32_t depth=aot_bridge_max_callback_depth();
    CHECK(active_session && aot_execute(aot_entry,state,opaque,pc)==AOT_INVALID);
    CHECK(!memcmp(&saved,state,sizeof saved) && !memcmp(&prior,&((AotContext*)opaque)->result,sizeof prior));
    CHECK(aot_bridge_api_calls()==api && aot_bridge_callback_calls()==calls && aot_bridge_callback_returns()==returns);
    CHECK(aot_bridge_max_callback_depth()==depth);reentry_checks++;
    return result;
}
static uint32_t execute(Case *c) {
    uint32_t status=aot_execute(audited_entry,c->state,c->ctx,c->base+kEntryRva);
    aot_result(c->ctx,&c->result);CHECK(active_session==NULL && !last_session.state_identity && !last_session.context_identity);
    return status;
}
static void main_writes(Case *c) {
    put64(c->expected,c->rsp-STACK_BASE-24,c->args[3]);
    put64(c->expected,c->rsp-STACK_BASE-16,c->args[4]);
    put64(c->expected,c->rsp-STACK_BASE-8,c->args[5]);
    put64(c->expected,c->rsp-STACK_BASE-64,c->base+kMainAfterCallRva);
}
static void callback_frame_writes(Case *c,uint64_t frame,unsigned depth,int recursive) {
    put64(c->expected,frame,c->base+UINT64_C(0xe0000000)+depth*16);
    for(unsigned i=1;i<5;i++)put64(c->expected,frame+8*i,0);
    put64(c->expected,frame+40,c->args[4]);put64(c->expected,frame+48,c->args[5]);
    if(kFixture==1 || kFixture==2 || recursive) {
        put64(c->expected,frame-24,c->args[recursive?3:4]);put64(c->expected,frame-16,c->args[recursive?4:5]);
        if(recursive)put64(c->expected,frame-8,c->args[5]);
        put64(c->expected,frame-64,c->base+kCallbackAfterCallRva);
    }
    if(kMutant==2)put64(c->expected,frame-8,c->args[0]);
}
static void callback_writes(Case *c) {
    unsigned count=kFixture==3?(unsigned)c->args[0]+1:1;
    for(unsigned i=0;i<count;i++)callback_frame_writes(c,c->cb_rsp-STACK_BASE-128*i,i+1,kFixture==3 && i+1<count);
}
static void set_depth(Case *c,uint64_t value) {
    c->args[0]=value;c->initial[AOT_RCX]=value;aot_set_register(c->state,AOT_RCX,value);
}
static uint64_t expected_steps(Case *c) {return kSuccessSteps+(kFixture==3?c->args[0]*kNestedIterationSteps:0);}
static void check_image(Case *c) {
    uint8_t *expected=malloc(sizeof kImage);CHECK(expected);memcpy(expected,kImage,sizeof kImage);
    for(unsigned i=0;i<kThunkCount;i++)put64(expected,kIatRvas[i],c->base+kThunkRvas[i]);
    CHECK(!memcmp(c->image,expected,sizeof kImage));free(expected);
}
static void successful(Case *c) {
    CHECK(execute(c)==AOT_OK && c->result.returned && !c->result.call_depth);
    unsigned count=kFixture==3?(unsigned)c->args[0]+1:1;
    CHECK(c->result.steps==expected_steps(c) && aot_bridge_api_calls()==(kFixture==1?2u:count));
    CHECK(aot_bridge_callback_calls()==count && aot_bridge_callback_returns()==count && aot_bridge_max_callback_depth()==count);
    for(unsigned reg=0;reg<17;reg++) {
        uint64_t expected=c->initial[reg];
        if(reg==AOT_RAX)expected=kFixture==3?weighted(c->args)-c->args[0]+count*40+7:weighted(c->args)+47;
        if(reg==AOT_RCX)expected=c->base+kCallbackRva;
        if(reg==AOT_RDX)expected=c->args[0];
        if(reg==AOT_R8)expected=c->args[1];
        if(reg==AOT_R9)expected=c->args[2];
        if(reg==AOT_R10)expected=c->args[4];
        if(reg==AOT_R11)expected=c->args[5];
        if(reg==AOT_RSP)expected=c->rsp+8;
        if(reg==AOT_RIP)expected=EXIT_PC;
        CHECK(aot_get_register(c->state,reg)==expected);
    }
    CHECK(aot_get_flags(c->state)==add_flags(c->rsp-56,56));
    main_writes(c);callback_writes(c);CHECK(!memcmp(c->stack,c->expected,STACK_SIZE));check_image(c);
    AotState previous=*c->state;
    CHECK(aot_execute(aot_entry,c->state,c->ctx,c->base+kEntryRva)==AOT_INVALID);
    CHECK(!memcmp(c->state,&previous,sizeof previous));CHECK(aot_bridge_api_calls()==0 && aot_bridge_callback_calls()==0);
}
static void preparation_fault(unsigned variant) {
    Case *c=make_case(variant,10000,UINT64_C(0xcafe000)+variant);
    uint32_t status=execute(c);
    CHECK(status==(variant==1?AOT_BOUNDS:(variant==2?AOT_PROTECTION:AOT_INVALID)));
    CHECK(c->result.fault.pc==c->base+kInvokeThunkRva);
    CHECK(c->result.fault.address==(variant==3?c->rsp-64:c->cb_rsp+(variant==1?16:0)));
    CHECK(c->result.fault.width==(variant==3?0u:8u) && c->result.fault.access==(variant==3?0u:GM_READ|GM_WRITE));
    CHECK(c->result.steps==kMainCallStep && c->result.call_depth==1 && !c->result.returned);
    CHECK(aot_bridge_api_calls()==0 && aot_bridge_callback_calls()==0 && aot_bridge_callback_returns()==0);
    main_writes(c);CHECK(!memcmp(c->stack,c->expected,STACK_SIZE));check_image(c);destroy(c);
}
static void budget_fault(uint64_t budget) {
    Case *c=make_case(0,budget,UINT64_C(0xbad000)+budget);
    if(kFixture==3)set_depth(c,2);
    CHECK(execute(c)==AOT_BUDGET && c->result.steps==budget && !c->result.returned);
    CHECK(c->result.fault.status==AOT_BUDGET && c->result.fault.width==0 && c->result.fault.access==0);
    unsigned callback_count=budget>kMainCallStep?1u:0u;
    if(kFixture==3 && callback_count) {
        callback_count=(unsigned)((budget-kMainCallStep-1)/kNestedPrefixSteps)+1;
        if(callback_count>3)callback_count=3;
    }
    CHECK(aot_bridge_callback_calls()==callback_count);
    if(kFixture==3)CHECK(aot_bridge_api_calls()==callback_count);
    else if(kFixture==1)CHECK(aot_bridge_api_calls()==(budget>kNestedCallStep?2u:(budget>kMainCallStep?1u:0u)));
    else CHECK(aot_bridge_api_calls()==(budget>kMainCallStep?1u:0u));
    /* First fault identity must survive every native/guest unwind. */
    AotFault first=c->result.fault;AotState state=*c->state;
    CHECK(aot_should_exit(c->ctx));CHECK(aot_begin(c->state,UINT64_C(0xbadc0de),c->ctx)==1);
    CHECK(!memcmp(&first,&c->ctx->result.fault,sizeof first) && !memcmp(&state,c->state,sizeof state));
    if(budget==expected_steps(c)-3) {
        /* Stop immediately after outer compatibility RET, before caller ADDs
         * overwrite arithmetic flags. Compare to the same actual PE stopped
         * at its committed outer CALL, before entering the native API. */
        CHECK(c->result.fault.pc==c->base+kMainAfterCallRva && !c->result.call_depth);
        Case *control=make_case(0,kMainCallStep,UINT64_C(0xbad000)+budget);
        if(kFixture==3)set_depth(control,2);
        CHECK(execute(control)==AOT_BUDGET && aot_bridge_api_calls()==0 && aot_bridge_callback_calls()==0);
        AotState expected=*control->state;
        uint64_t value=kFixture==3?weighted(c->args)-c->args[0]+(c->args[0]+1)*40:weighted(c->args)+40;
        aot_set_register(&expected,AOT_RAX,value);aot_set_register(&expected,AOT_RSP,c->rsp-56);
        aot_set_register(&expected,AOT_RIP,c->base+kMainAfterCallRva);
        CHECK(!memcmp(c->state,&expected,sizeof expected));boundary_checks++;destroy(control);
    }
    destroy(c);
}
static void nested_boundaries(void) {
    Case *c=make_case(0,10000,UINT64_C(0xdee000));set_depth(c,15);successful(c);destroy(c);
    c=make_case(0,10000,UINT64_C(0xdee001));set_depth(c,16);
    CHECK(execute(c)==AOT_CALL_DEPTH && !c->result.returned && c->result.call_depth==33);
    CHECK(c->result.fault.pc==c->base+kInvokeThunkRva && c->result.fault.address==c->base+kCallbackRva);
    CHECK(c->result.steps==kMainCallStep+16*kNestedPrefixSteps);
    CHECK(aot_bridge_api_calls()==16 && aot_bridge_callback_calls()==16 && aot_bridge_callback_returns()==0 && aot_bridge_max_callback_depth()==16);
    CHECK(aot_get_register(c->state,AOT_RSP)==c->cb_rsp-15*128-64);
    main_writes(c);
    for(unsigned i=0;i<16;i++)callback_frame_writes(c,c->cb_rsp-STACK_BASE-i*128,i+1,1);
    CHECK(!memcmp(c->stack,c->expected,STACK_SIZE));check_image(c);destroy(c);
}
static void mutant_fault(Case *c) {
    CHECK(execute(c)==(kMutant==1?AOT_INVALID:AOT_BAD_RETURN));
    CHECK(!c->result.returned && c->result.fault.pc==c->base+kCallbackRetRva);
    CHECK(aot_bridge_api_calls()==1 && aot_bridge_callback_calls()==1 && aot_bridge_callback_returns()==0);
    CHECK(aot_bridge_max_callback_depth()==1);
    if(kMutant==1) {
        CHECK(c->result.fault.address==c->base+kCallbackRva && c->result.fault.access==0);
        CHECK(c->result.call_depth==1 && aot_get_register(c->state,AOT_RSP)==c->cb_rsp+8);
        CHECK(aot_get_register(c->state,AOT_RIP)==c->base+UINT64_C(0xe0000010));
        CHECK(aot_get_register(c->state,AOT_RBX)==c->args[0]);
    } else {
        CHECK(c->result.fault.address==c->args[0] && c->result.fault.access==AOT_EXEC);
        CHECK(c->result.call_depth==2 && aot_get_register(c->state,AOT_RSP)==c->cb_rsp-8);
        CHECK(aot_get_register(c->state,AOT_RIP)==c->base+kCallbackRetRva);
    }
    main_writes(c);callback_writes(c);CHECK(!memcmp(c->stack,c->expected,STACK_SIZE));check_image(c);
}
int main(void) {
    for(current_case=0;current_case<128;current_case++) {
        current_variant=0;Case *c=make_case(0,10000,UINT64_C(20261027)+current_case*101);
        if(kMutant)mutant_fault(c);else successful(c);destroy(c);
    }
    unsigned budgets=0;
    if(!kMutant) {
        for(unsigned variant=1;variant<=3;variant++){current_variant=variant;preparation_fault(variant);}
        for(uint64_t budget=1;budget<kSuccessSteps+(kFixture==3?2*kNestedIterationSteps:0);budget++){current_variant=3;budget_fault(budget);budgets++;}
    }
    if(kFixture==3)nested_boundaries();
    printf("{\"status\":\"PASS\",\"fixture\":%d,\"mutant\":%d,\"random_cases\":128,"
           "\"preparation_faults\":%u,\"budget_cuts\":%u,\"depth_boundaries\":%u,\"public_reentry_rejections\":%u,\"callback_boundary_full_state_checks\":%u,\"actual_lifted_roots\":true,"
           "\"whole_stack_image_check\":true,\"all_GPR_flags_on_success\":%s}\n",
           kFixture,kMutant,kMutant?0:3,budgets,kFixture==3?2:0,reentry_checks,boundary_checks,kMutant?"false":"true");
    return 0;
}
