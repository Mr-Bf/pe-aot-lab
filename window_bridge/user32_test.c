/* Unit harness: real guest-memory planner + User32 implementation, explicitly
 * mocked Cocoa and callback executor. No PE instructions, GUI or GPU run. */
#include "window_runtime/runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
static bool d3d_validate_call(AotState*,AotContext*,uint64_t);
static bool import_validate_call(AotState*,AotContext*,uint64_t);
#define aot_should_exit engine_should_exit
#include "window_runtime/transaction_v1.c"
#undef aot_should_exit
static bool d3d_validate_call(AotState*s,AotContext*c,uint64_t p){(void)s;(void)c;(void)p;return false;}
static bool import_validate_call(AotState*s,AotContext*c,uint64_t p){(void)s;(void)c;(void)p;return false;}
#include "callback_v1.h"
#include "cocoa_host.h"
static struct {unsigned configured,running,used;uintptr_t context_identity,state_identity;} session;
static struct {unsigned configured;uintptr_t owner;size_t count;AotWindowCallback entries[1];} window_callbacks;
static unsigned window_files_ready=1,last_error,exited;
static void wfile_set_last_error(uint32_t error){last_error=error;}
static bool wnd_host_storage(AotContext*c,const void*p,size_t n){(void)c;(void)n;return p!=NULL;}
static bool read_u64(AotContext*c,uint64_t a,uint64_t*out){AccessPlan p;if(!plan_access(c,a,8,GM_READ,&p))return false;*out=0;for(unsigned i=0;i<8;i++)*out|=(uint64_t)*p.byte[i]<<(8*i);return true;}
static bool read_bytes(AotContext*c,uint64_t a,void*out,unsigned n){for(unsigned i=0;i<n;i++){AccessPlan p;if(a>UINT64_MAX-i||!plan_access(c,a+i,1,GM_READ,&p))return false;((uint8_t*)out)[i]=*p.byte[0];}return true;}
uint32_t aot_should_exit(void*p){return exited||engine_should_exit(p);}
static uint64_t wui_defproc(AotState*,AotContext*,uint64_t,uint32_t,uint64_t,uint64_t);
static uint64_t wui_invoke(AotState*,AotContext*,uint32_t,uint64_t,bool*);
#include "user32_v1.inc"
struct WBHost {uint64_t hwnd,next,focus;unsigned visible,created,destroyed,active,gets,validations;WBHostMessage queue[32];unsigned head,tail;};
static WBHost host;
int wb_host_frame_metrics(WBHost*h,WBHostFrameMetrics*m){(void)h;*m=(WBHostFrameMetrics){1,23,1,1,2.0};return 1;}
uint64_t wb_host_create_window(WBHost*h,uint32_t w,uint32_t he,const char*t){if(w!=642||he!=384||strcmp(t,"Test"))return 0;h->created++;h->hwnd=++h->next;return h->hwnd;}
int wb_host_window_rect(WBHost*h,uint64_t hwnd,int32_t*r){if(hwnd!=h->hwnd)return 0;r[0]=100;r[1]=200;r[2]=742;r[3]=584;return 1;}
int wb_host_client_size(WBHost*h,uint64_t hwnd,uint32_t*w,uint32_t*he){if(hwnd!=h->hwnd)return 0;*w=640;*he=360;return 1;}
int wb_host_show_window(WBHost*h,uint64_t hwnd,int show,int*prev,WBHostFocusChange*f){if(hwnd!=h->hwnd)return 0;*prev=h->visible;f->before=h->focus;h->visible=show;h->focus=show?hwnd:0;f->after=h->focus;return 1;}
int wb_host_focus_window(WBHost*h,uint64_t hwnd,WBHostFocusChange*f){if(hwnd!=h->hwnd)return 0;*f=(WBHostFocusChange){h->focus,hwnd};h->focus=hwnd;return 1;}
int wb_host_destroy_window(WBHost*h,uint64_t hwnd){if(hwnd!=h->hwnd||h->active)return 0;h->destroyed++;h->hwnd=0;return 1;}
int wb_host_validate_rect(WBHost*h,uint64_t hwnd){if(hwnd!=h->hwnd)return 0;h->validations++;return 1;}
void wb_host_stats(WBHost*h,WBHostStats*s){memset(s,0,sizeof *s);s->active_views=h->active;}
int wb_host_post_quit(WBHost*h,uint32_t code){if(h->tail==32)return 0;h->queue[h->tail++]=(WBHostMessage){.message=0x12,.origin=WB_ORIGIN_GUEST_QUEUE_API,.wparam=code,.time_ms=555,.screen_x=-20,.screen_y=30};return 1;}
int wb_host_get_message(WBHost*h,WBHostMessage*m){h->gets++;if(h->head==h->tail)return -1;*m=h->queue[h->head++];return m->message==0x12?0:1;}
static unsigned checks,callback_count,fail_message,fail_kind;static uint32_t messages[128];static uint64_t callback_lp[128];
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"check %u line %u: %s\n",checks,__LINE__,#x);exit(1);}}while(0)
uint32_t aot_wndproc_invoke(AotState*s,AotContext*c,uint64_t target,uint64_t hwnd,uint32_t msg,uint64_t wp,uint64_t lp,uint64_t*out){
    CHECK(target==user32.procedure);CHECK(callback_count<128);messages[callback_count]=msg;callback_lp[callback_count++]=lp;
    if(fail_message==msg){if(fail_kind==1){*out=msg==0x81?0:UINT64_MAX;return AOT_OK;}
        aot_set_register(s,AOT_RIP,0xabcdef);c->result.steps+=3;
        if(fail_kind==2){fault(c,AOT_BOUNDS,0xbad,8,GM_READ);return AOT_BOUNDS;}
        if(fail_kind==3){exited=1;return AOT_PROCESS_EXITED;}}
    if(msg==0x81){uint8_t cs[80];CHECK(read_bytes(c,lp,cs,80));CHECK(wui_u32(cs+40)==200&&wui_u32(cs+44)==100);CHECK(wui_u32(cs+32)==384&&wui_u32(cs+36)==642);CHECK(wui_u64(cs+56)==user32.config.scratch_base+128);*out=1;}
    else if(msg==0x83){*out=wui_defproc(s,c,hwnd,msg,wp,lp);if(fail_kind==4)*out=1;}
    else if(msg==0x10)*out=wui_defproc(s,c,hwnd,msg,wp,lp);
    else {*out=0;if(msg==2){bool result;uint64_t saved=aot_get_register(s,AOT_RCX);aot_set_register(s,AOT_RCX,17);wui_invoke(s,c,217,aot_get_register(s,AOT_RSP),&result);CHECK(!result);aot_set_register(s,AOT_RCX,saved);}}
    return c->result.fault.status?c->result.fault.status:AOT_OK;
}
static uint8_t scratch[4096],data[8192],stack[8192],sp[1],dp[2],stp[2];static AotContext*ctx;static AotState state;static const uint64_t DATA=0x20000,STACK=0x30000,SCRATCH=0x50000,RSP=0x31f08;
static void *dummy(void*s,uint64_t pc,void*c){(void)s;(void)pc;return c;}
static void reset(void){
    if(ctx)aot_context_destroy(ctx);memset(&state,0,sizeof state);memset(&host,0,sizeof host);host.next=0x123400;
    memset(&user32,0,sizeof user32);memset(&session,0,sizeof session);memset(&window_callbacks,0,sizeof window_callbacks);
    memset(data,0,sizeof data);memset(stack,0,sizeof stack);memset(scratch,0x5a,sizeof scratch);
    memset(sp,3,sizeof sp);memset(dp,3,sizeof dp);memset(stp,3,sizeof stp);last_error=0;exited=0;fail_message=fail_kind=callback_count=0;
    AotInstruction instruction={0x1000,1,AOT_NORMAL,0,0};ctx=aot_context_create(0x140000000,&instruction,1,10000,0x7ffff000,RSP);CHECK(ctx!=NULL);
    GuestMemory regions[]={{DATA,sizeof data,data,dp,2},{STACK,sizeof stack,stack,stp,2},{SCRATCH,sizeof scratch,scratch,sp,1}};
    for(unsigned i=0;i<3;i++)CHECK(aot_add_region(ctx,&regions[i])==AOT_OK);
    session.configured=1;session.context_identity=(uintptr_t)ctx;window_callbacks.configured=1;window_callbacks.owner=(uintptr_t)ctx;window_callbacks.count=1;
    window_callbacks.entries[0]=(AotWindowCallback){0x1100,AOT_WINDOW_WNDPROC,dummy};
    AotUser32Config config={&host,SCRATCH,4096};CHECK(aot_user32_session_begin(ctx,&config)==AOT_OK);
    session.running=1;session.state_identity=(uintptr_t)&state;aot_set_register(&state,AOT_RSP,RSP);
    memcpy(data+128,"Class",6);memcpy(data+256,"Test",5);
    wui_put(data,80,4);wui_put(data+8,ctx->module_base+0x1100,8);wui_put(data+24,ctx->module_base,8);wui_put(data+64,DATA+128,8);
}
static uint64_t invoke(uint32_t id,uint64_t a,uint64_t b,uint64_t c,uint64_t d){bool result=true;aot_set_register(&state,AOT_RCX,a);aot_set_register(&state,AOT_RDX,b);aot_set_register(&state,AOT_R8,c);aot_set_register(&state,AOT_R9,d);return wui_invoke(&state,ctx,id,RSP,&result);}
static void registration(void){CHECK(invoke(201,0,0,0,0)==ctx->module_base);CHECK(invoke(218,DATA,0,0,0)==WUI_ATOM);CHECK(!ctx->result.fault.status);}
static uint64_t create(void){uint64_t args[]={0x80000000,0x80000000,642,384,0,0,ctx->module_base,0};for(unsigned i=0;i<8;i++)wui_put(stack+(RSP-STACK)+40+i*8,args[i],8);return invoke(211,0,DATA+128,DATA+256,WUI_STYLE);}
static void ready(void){reset();registration();CHECK(create()==host.hwnd);CHECK(user32.stats.window_state==2);CHECK(callback_count==3);CHECK(messages[0]==0x81&&messages[1]==0x83&&messages[2]==1);CHECK(wui_window_contract(ctx,host.hwnd,640,360));}
static void message(uint32_t msg,uint32_t delivery,uint64_t hwnd,uint64_t wp,int64_t lp){CHECK(host.tail<32);host.queue[host.tail++]=(WBHostMessage){.hwnd=hwnd,.message=msg,.origin=WB_ORIGIN_TEST_QUEUE,.wparam=wp,.lparam=lp,.time_ms=1234,.screen_x=-99,.screen_y=111,.delivery=delivery};}
int main(void){
    ready();uint64_t hwnd=host.hwnd;
    CHECK(invoke(220,hwnd,5,0,0)==0);CHECK(messages[3]==7);CHECK(invoke(219,hwnd,0,0,0)==hwnd);CHECK(callback_count==4);
    CHECK(invoke(215,hwnd,DATA+400,0,0)==1);CHECK(wui_u32(data+408)==640&&wui_u32(data+412)==360);
    message(0x100,0,hwnd,0x27,1);message(8,1,hwnd,0,0);message(7,1,hwnd,0,0);
    CHECK(invoke(216,DATA+512,0,0,0)==1); /* mock FIFO: actual priority tested by Cocoa queue suite */
    CHECK(wui_u64(data+512)==hwnd&&wui_u32(data+520)==0x100&&wui_u64(data+528)==0x27);
    CHECK(wui_u32(data+544)==1234&&(int32_t)wui_u32(data+548)==-99&&wui_u32(data+552)==111&&wui_u32(data+556)==0);
    CHECK(invoke(214,DATA+512,0,0,0)==0);CHECK(messages[4]==0x100);
    CHECK(wb_host_post_quit(&host,42));CHECK(invoke(216,DATA+512,0,0,0)==0);CHECK(wui_u32(data+520)==0x12&&wui_u64(data+528)==42);CHECK(user32.stats.sent_notifications==2);
    CHECK(invoke(213,hwnd,0,0,0)==1);CHECK(host.destroyed==1&&user32.stats.window_state==4);CHECK(messages[callback_count-2]==2&&messages[callback_count-1]==0x82);
    CHECK(invoke(221,DATA+128,ctx->module_base,0,0)==1);CHECK(!user32.stats.registered);
    message(7,1,hwnd,0,0);message(0x101,0,hwnd,0x27,0);CHECK(invoke(216,DATA+512,0,0,0)==0);/* pending WM_QUIT */
    CHECK(invoke(216,DATA+512,0,0,0)==1);CHECK(invoke(214,DATA+512,0,0,0)==0);CHECK(user32.stats.discarded_stale==2);
    for(unsigned kind=1;kind<=3;kind++)for(unsigned which=0;which<3;which++){
        reset();registration();fail_kind=kind;fail_message=(uint32_t[]){0x81,0x83,1}[which];
        if(kind==1&&which==1)continue;
        CHECK(create()==0);
        if(kind==1){CHECK(host.destroyed==1&&user32.stats.window_state==4);CHECK(messages[callback_count-1]==0x82);CHECK(!ctx->result.fault.status);}
        else {CHECK(host.destroyed==0);CHECK(aot_get_register(&state,AOT_RIP)==0xabcdef);CHECK(ctx->result.steps==3);CHECK((kind==2&&ctx->result.fault.status==AOT_BOUNDS)||(kind==3&&exited));CHECK(messages[callback_count-1]==fail_message);}
    }
    ready();message(7,1,host.hwnd,0,0);CHECK(wb_host_post_quit(&host,0));unsigned gets=host.gets;dp[1]=GM_READ;
    CHECK(invoke(216,DATA+8192-32,0,0,0)==0);CHECK(ctx->result.fault.status==AOT_PROTECTION&&host.gets==gets);
    for(unsigned kind=2;kind<=3;kind++){ready();memset(data+512,0x89,48);fail_message=7;fail_kind=kind;message(7,1,host.hwnd,0,0);CHECK(wb_host_post_quit(&host,0));CHECK(invoke(216,DATA+512,0,0,0)==0);CHECK(host.head==1);CHECK(data[512]==0x89&&data[559]==0x89);CHECK(aot_get_register(&state,AOT_RIP)==0xabcdef);}
    ready();host.active=1;unsigned cb=callback_count;CHECK(invoke(213,host.hwnd,0,0,0)==0);CHECK(ctx->result.fault.status==AOT_MAP_STATE&&callback_count==cb&&host.destroyed==0);
    reset();registration();sp[0]=GM_READ;uint8_t before[4096];memcpy(before,scratch,sizeof before);CHECK(create()==0);CHECK(ctx->result.fault.status==AOT_PROTECTION&&host.created==0&&!memcmp(before,scratch,sizeof before));
    ready();CHECK(invoke(212,host.hwnd,0xdead,0,0)==0);CHECK(ctx->result.fault.status==AOT_UNSUPPORTED);
    ready();CHECK(invoke(222,host.hwnd,DATA,0,0)==0);CHECK(ctx->result.fault.status==AOT_UNSUPPORTED&&host.validations==0);
    reset();registration();fail_kind=4;CHECK(create()==0);CHECK(ctx->result.fault.status==AOT_UNSUPPORTED&&host.created==1&&host.destroyed==0);CHECK(messages[callback_count-1]==0x83);
    ready();session.running=0;CHECK(aot_user32_session_end(ctx)==AOT_OK);CHECK(aot_user32_session_end(ctx)==AOT_INVALID);
    CHECK(aot_user32_session_begin(ctx,&user32.config)==AOT_OK);CHECK(user32.config.host==&host&&user32.config.scratch_base==SCRATCH);CHECK(aot_user32_session_end(ctx)==AOT_OK);
    aot_context_destroy(ctx);ctx=NULL;
    printf("{\"status\":\"PASS\",\"checks\":%u,\"scope\":\"real_User32_and_memory_mock_host_and_callback\",\"guest_executions\":0,\"gui_executions\":0,\"gpu_executions\":0}\n",checks);return 0;
}
