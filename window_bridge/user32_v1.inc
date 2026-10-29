/* Restricted User32 v1. Source implementation is separate from its validation.
 * Include after callback_v1.inc and the checked guest memory/session helpers.
 * A single guest owner thread drives all callbacks; Cocoa only queues values.
 */
#include "user32_v1.h"
#include <limits.h>
enum { WUI_STYLE=0x00c80000, WUI_ATOM=0xc001, WUI_MAX_STRING=128,
       WUI_INVALID_PARAMETER=87,WUI_INVALID_WINDOW=1400,WUI_CLASS_NOT_FOUND=1407,
       WUI_CLASS_EXISTS=1410,WUI_CLASS_HAS_WINDOWS=1412,WUI_ABORTED=995 };
typedef struct {
    uint32_t configured;
    uintptr_t owner;
    AotUser32Config config;
    AotUser32Stats stats;
    uint64_t instance,procedure,focus;
    char class_name[WUI_MAX_STRING];
    WBHostFrameMetrics frame;
} User32Session;
static _Thread_local User32Session user32;
typedef struct { AccessPlan parts[8];unsigned size; } WuiOutput;
static uint32_t wui_u32(const uint8_t *p) {
    uint32_t value=0;for(unsigned i=0;i<4;i++)value|=(uint32_t)p[i]<<(8*i);return value;
}
static uint64_t wui_u64(const uint8_t *p) {
    uint64_t value=0;for(unsigned i=0;i<8;i++)value|=(uint64_t)p[i]<<(8*i);return value;
}
static void wui_put(uint8_t *p,uint64_t value,unsigned count) {
    for(unsigned i=0;i<count;i++)p[i]=(uint8_t)(value>>(8*i));
}
static bool wui_output(AotContext *ctx,uint64_t address,unsigned size,WuiOutput *out) {
    if(!size || size>WUI_MAX_STRING || address>UINT64_MAX-size){fault(ctx,AOT_BOUNDS,address,size,GM_WRITE);return false;}
    out->size=size;
    for(unsigned offset=0;offset<size;offset+=16) {
        unsigned n=size-offset<16?size-offset:16;
        if(!plan_access(ctx,address+offset,n,GM_WRITE,&out->parts[offset/16]))return false;
    }
    return true;
}
static void wui_store(const WuiOutput *out,const uint8_t *bytes) {
    for(unsigned i=0;i<out->size;i++)*out->parts[i/16].byte[i%16]=bytes[i];
}
static bool wui_string(AotContext *ctx,uint64_t address,char result[WUI_MAX_STRING]) {
    for(unsigned i=0;i<WUI_MAX_STRING;i++) {
        if(address>UINT64_MAX-i){fault(ctx,AOT_BOUNDS,address,i+1,GM_READ);return false;}
        AccessPlan p;if(!plan_access(ctx,address+i,1,GM_READ,&p))return false;
        uint8_t c=*p.byte[0];result[i]=(char)c;
        if(!c)return i!=0;
        if(c<32 || c>126){fault(ctx,AOT_UNSUPPORTED,address+i,1,GM_READ);return false;}
    }
    fault(ctx,AOT_UNSUPPORTED,address,WUI_MAX_STRING,GM_READ);return false;
}
static bool wui_live(uint64_t hwnd) {
    return hwnd && hwnd==user32.stats.hwnd && user32.stats.window_state>=1 && user32.stats.window_state<=3;
}
static uint64_t wui_error(uint32_t error) {wfile_set_last_error(error);return 0;}
static bool wui_callback(AotState *s,AotContext *ctx,uint32_t message,uint64_t wp,uint64_t lp,uint64_t *value) {
    user32.stats.callbacks++;
    return aot_wndproc_invoke(s,ctx,user32.procedure,user32.stats.hwnd,message,wp,lp,value)==AOT_OK;
}
static bool wui_focus_change(AotState *s,AotContext *ctx,const WBHostFocusChange *change) {
    uint64_t ignored=0;
    if(change->before==change->after){user32.focus=change->after;return true;}
    if(change->before && (!wui_live(change->before) || change->before!=user32.stats.hwnd)) {
        fault(ctx,AOT_BACKEND,change->before,0,0);return false;
    }
    if(change->after && !wui_live(change->after)){fault(ctx,AOT_BACKEND,change->after,0,0);return false;}
    user32.focus=change->after;
    if(change->before && !wui_callback(s,ctx,8,change->after,0,&ignored))return false;
    return !change->after || wui_callback(s,ctx,7,change->before,0,&ignored);
}
/* Required by the graphics profile, after it decodes the actual DESC. */
static bool wui_window_contract(AotContext *ctx,uint64_t hwnd,uint32_t width,uint32_t height) {
    if(!user32.configured || user32.owner!=(uintptr_t)ctx || user32.stats.window_state!=2 || !wui_live(hwnd)) {
        fault(ctx,AOT_BAD_OBJECT,hwnd,0,0);return false;
    }
    uint32_t actual_width=0,actual_height=0;
    if(!wb_host_client_size(user32.config.host,hwnd,&actual_width,&actual_height)) {
        fault(ctx,AOT_BACKEND,hwnd,0,0);return false;
    }
    if(width!=640 || height!=360 || width!=actual_width || height!=actual_height) {
        fault(ctx,AOT_UNSUPPORTED,hwnd,0,0);return false;
    }
    return true;
}
uint32_t aot_user32_session_begin(AotContext *ctx,const AotUser32Config *config) {
    if(!ctx || !config || !wnd_host_storage(ctx,config,sizeof *config))return AOT_INVALID;
    /* Copy before resetting TLS: even a trusted config aliasing the previous
     * user32.config must not be erased by the successful setup memset. */
    AotUser32Config copied=*config;config=&copied;
    if(!config->host || session.running || session.used || !session.configured ||
       session.context_identity!=(uintptr_t)ctx || user32.configured || !window_files_ready ||
       !window_callbacks.configured || window_callbacks.owner!=(uintptr_t)ctx ||
       config->scratch_size!=GM_PAGE || config->scratch_base>UINT64_MAX-GM_PAGE ||
       (config->scratch_base&(GM_PAGE-1)))return AOT_INVALID;
    bool region=false;
    for(size_t i=0;i<ctx->region_count;i++) {
        const GuestMemory *r=&ctx->regions[i];
        if(r->base==config->scratch_base && r->size==GM_PAGE && r->permissions[0]==(GM_READ|GM_WRITE)) {
            if(ctx->initial_rsp>=r->base && ctx->initial_rsp-r->base<r->size)return AOT_INVALID;
            region=true;
        }
    }
    if(!region)return AOT_INVALID;
    WBHostFrameMetrics frame={};
    if(!wb_host_frame_metrics(config->host,&frame))return AOT_BACKEND;
    if(frame.left<0 || frame.top<0 || frame.right<0 || frame.bottom<0 ||
       frame.left>4096 || frame.top>4096 || frame.right>4096 || frame.bottom>4096)return AOT_BACKEND;
    memset(&user32,0,sizeof user32);user32.configured=1;user32.owner=(uintptr_t)ctx;
    user32.config=*config;user32.instance=ctx->module_base;user32.frame=frame;return AOT_OK;
}
uint32_t aot_user32_session_end(AotContext *ctx) {
    if(!ctx || !user32.configured || user32.owner!=(uintptr_t)ctx || session.running)return AOT_INVALID;
    /* Host shutdown/forced native cleanup is a separate operation after D3D
     * releases. It never fabricates guest DestroyWindow or save callbacks. */
    user32.configured=0;user32.owner=0;return AOT_OK;
}
void aot_user32_stats(AotUser32Stats *out){if(out)*out=user32.stats;}

static uint64_t wui_register_class(AotContext *ctx,uint64_t address) {
    uint8_t bytes[80];char name[WUI_MAX_STRING]={};
    if(!read_bytes(ctx,address,bytes,sizeof bytes))return 0;
    if(wui_u32(bytes)!=80 || wui_u32(bytes+4) || wui_u32(bytes+16) || wui_u32(bytes+20) ||
       wui_u64(bytes+32) || wui_u64(bytes+40) || wui_u64(bytes+48) || wui_u64(bytes+56) || wui_u64(bytes+72)) {
        fault(ctx,AOT_UNSUPPORTED,address,80,GM_READ);return 0;
    }
    if(wui_u64(bytes+24)!=user32.instance)return wui_error(WUI_INVALID_PARAMETER);
    if(!wui_string(ctx,wui_u64(bytes+64),name))return ctx->result.fault.status?0:wui_error(WUI_INVALID_PARAMETER);
    if(user32.stats.registered)return wui_error(WUI_CLASS_EXISTS);
    uint64_t procedure=wui_u64(bytes+8);bool found=false;
    for(size_t i=0;i<window_callbacks.count;i++) {
        const AotWindowCallback *root=&window_callbacks.entries[i];
        if(ctx->module_base<=UINT64_MAX-root->rva && ctx->module_base+root->rva==procedure &&
           root->signature==AOT_WINDOW_WNDPROC && root->entry)found=true;
    }
    if(!found){fault(ctx,AOT_BAD_INSTRUCTION,procedure,0,AOT_EXEC);return 0;}
    memcpy(user32.class_name,name,sizeof name);user32.procedure=procedure;
    user32.stats.registered=1;user32.stats.classes_registered++;return WUI_ATOM;
}
static uint64_t wui_unregister_class(AotContext *ctx,uint64_t name_address,uint64_t instance) {
    char name[WUI_MAX_STRING]={};
    if(!wui_string(ctx,name_address,name))return ctx->result.fault.status?0:wui_error(WUI_INVALID_PARAMETER);
    if(!user32.stats.registered || instance!=user32.instance || strcmp(name,user32.class_name))
        return wui_error(WUI_CLASS_NOT_FOUND);
    if(user32.stats.window_state>=1 && user32.stats.window_state<=3)return wui_error(WUI_CLASS_HAS_WINDOWS);
    user32.stats.registered=0;user32.stats.classes_unregistered++;user32.procedure=0;return 1;
}
/* invert=false: client -> outer (AdjustWindowRectEx).
 * invert=true: proposed outer -> client (DefWindowProc WM_NCCALCSIZE(FALSE)).
 * Both work in signed screen/device-pixel coordinates and write the real RECT.
 */
static uint64_t wui_adjust_rect(AotContext *ctx,uint64_t address,bool invert) {
    uint8_t bytes[16];WuiOutput output;
    if(!read_bytes(ctx,address,bytes,sizeof bytes) || !wui_output(ctx,address,sizeof bytes,&output))return 0;
    int64_t rect[4];for(unsigned i=0;i<4;i++)rect[i]=(int32_t)wui_u32(bytes+4*i);
    if(rect[2]<=rect[0] || rect[3]<=rect[1])return wui_error(WUI_INVALID_PARAMETER);
    int direction=invert?1:-1;
    rect[0]+=direction*(int64_t)user32.frame.left;rect[1]+=direction*(int64_t)user32.frame.top;
    rect[2]-=direction*(int64_t)user32.frame.right;rect[3]-=direction*(int64_t)user32.frame.bottom;
    for(unsigned i=0;i<4;i++)if(rect[i]<INT32_MIN || rect[i]>INT32_MAX)return wui_error(WUI_INVALID_PARAMETER);
    if(rect[2]<=rect[0] || rect[3]<=rect[1])return wui_error(WUI_INVALID_PARAMETER);
    for(unsigned i=0;i<4;i++)wui_put(bytes+4*i,(uint32_t)rect[i],4);
    wui_store(&output,bytes);return 1;
}
static uint64_t wui_get_client(AotContext *ctx,uint64_t hwnd,uint64_t address) {
    if(!wui_live(hwnd))return wui_error(WUI_INVALID_WINDOW);
    WuiOutput output;if(!wui_output(ctx,address,16,&output))return 0;
    uint32_t width=0,height=0;
    if(!wb_host_client_size(user32.config.host,hwnd,&width,&height))return wui_error(WUI_ABORTED);
    if(width>INT32_MAX || height>INT32_MAX){fault(ctx,AOT_BACKEND,hwnd,0,0);return 0;}
    uint8_t rect[16]={};wui_put(rect+8,width,4);wui_put(rect+12,height,4);wui_store(&output,rect);return 1;
}

/* All input scalars and strings are copied before scratch writes or callbacks.
 * Only this profile's fixed style, one class and one window are admitted. */
static bool wui_overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m) {
    return a<b+m && b<a+n; /* callers supply already bounded spans */
}
static bool wui_scratch(AotContext *ctx,uint64_t rsp,WuiOutput *cs,WuiOutput *rect,
                        WuiOutput *title,WuiOutput *name) {
    uint64_t base=user32.config.scratch_base;
    if(rsp<48 || rsp>UINT64_MAX-104 ||
       wui_overlap(base,GM_PAGE,rsp-48,152)) {
        fault(ctx,AOT_INVALID,base,GM_PAGE,GM_WRITE);return false;
    }
    /* The current import and every live return slot must remain untouched. */
    for(uint32_t i=0;i<ctx->result.call_depth;i++) {
        uint64_t r=ctx->frames[i].rsp;
        if(r<8 || wui_overlap(base,GM_PAGE,r-8,8)) {
            fault(ctx,AOT_INVALID,base,GM_PAGE,GM_WRITE);return false;
        }
    }
    return wui_output(ctx,base,80,cs) && wui_output(ctx,base+80,16,rect) &&
        wui_output(ctx,base+128,WUI_MAX_STRING,title) &&
        wui_output(ctx,base+256,WUI_MAX_STRING,name);
}
static bool wui_native_destroy(AotContext *ctx) {
    if(!wb_host_destroy_window(user32.config.host,user32.stats.hwnd)) {
        fault(ctx,AOT_BACKEND,user32.stats.hwnd,0,0);return false;
    }
    user32.stats.windows_destroyed++;user32.stats.window_state=4;user32.focus=0;return true;
}
static uint64_t wui_create_failure(AotState *s,AotContext *ctx) {
    /* NCCREATE FALSE: MS documents NCDESTROY without DESTROY. CREATE -1:
     * pinned Wine's create_window_ex failure path uses the same NC teardown;
     * no Windows execution oracle is claimed for that latter ordering. */
    uint64_t ignored=0;user32.stats.window_state=3;
    if(!wui_callback(s,ctx,0x82,0,0,&ignored))return 0;
    if(!wui_native_destroy(ctx))return 0;
    return 0; /* preserve the callback's LastError, including zero */
}
static uint64_t wui_create_window(AotState *s,AotContext *ctx,uint64_t rsp) {
    uint64_t a[12]={aot_get_register(s,AOT_RCX),aot_get_register(s,AOT_RDX),
        aot_get_register(s,AOT_R8),aot_get_register(s,AOT_R9)};
    for(unsigned i=4;i<12;i++)if(!read_u64(ctx,rsp+40+8*(i-4),&a[i]))return 0;
    if((uint32_t)a[0] || (uint32_t)a[3]!=WUI_STYLE || (uint32_t)a[4]!=0x80000000u ||
       (uint32_t)a[5]!=0x80000000u || a[8] || a[9] || a[11]) {
        fault(ctx,AOT_UNSUPPORTED,ctx->current_pc,0,0);return 0;
    }
    if(!user32.stats.registered || a[10]!=user32.instance)return wui_error(WUI_CLASS_NOT_FOUND);
    /* Recursive creation would reuse live scratch and cannot be modeled as a
     * generic Windows reentrant CreateWindow. Reject it before any write. */
    if(user32.stats.window_state==1 || user32.stats.window_state==3) {
        fault(ctx,AOT_UNSUPPORTED,ctx->current_pc,0,0);return 0;
    }
    if(user32.stats.window_state==2)return wui_error(WUI_INVALID_PARAMETER);
    char name[WUI_MAX_STRING]={},title[WUI_MAX_STRING]={};
    if(!wui_string(ctx,a[1],name))return ctx->result.fault.status?0:wui_error(WUI_INVALID_PARAMETER);
    if(strcmp(name,user32.class_name))return wui_error(WUI_CLASS_NOT_FOUND);
    if(!wui_string(ctx,a[2],title))return ctx->result.fault.status?0:wui_error(WUI_INVALID_PARAMETER);
    int64_t width=(int32_t)(uint32_t)a[6],height=(int32_t)(uint32_t)a[7];
    if(width!=640+(int64_t)user32.frame.left+user32.frame.right ||
       height!=360+(int64_t)user32.frame.top+user32.frame.bottom || width<=0 || height<=0 ||
       width>INT32_MAX || height>INT32_MAX) {
        fault(ctx,AOT_UNSUPPORTED,ctx->current_pc,0,0);return 0;
    }
    WuiOutput cs_output,rect_output,title_output,name_output;
    if(!wui_scratch(ctx,rsp,&cs_output,&rect_output,&title_output,&name_output))return 0;
    uint64_t hwnd=wb_host_create_window(user32.config.host,(uint32_t)width,(uint32_t)height,title);
    if(!hwnd)return wui_error(WUI_ABORTED);
    user32.stats.hwnd=hwnd;user32.stats.window_state=1;user32.stats.windows_created++;
    int32_t outer[4];uint32_t cw=0,ch=0;
    if(!wb_host_window_rect(user32.config.host,hwnd,outer) ||
       !wb_host_client_size(user32.config.host,hwnd,&cw,&ch) || cw!=640 || ch!=360 ||
       (int64_t)outer[2]-outer[0]!=width || (int64_t)outer[3]-outer[1]!=height) {
        fault(ctx,AOT_BACKEND,hwnd,0,0);return 0;
    }
    uint64_t base=user32.config.scratch_base;uint8_t cs[80]={},rect[16]={};
    wui_put(cs+8,user32.instance,8);wui_put(cs+32,(uint32_t)height,4);wui_put(cs+36,(uint32_t)width,4);
    wui_put(cs+40,(uint32_t)outer[1],4);wui_put(cs+44,(uint32_t)outer[0],4);
    wui_put(cs+48,WUI_STYLE,4);wui_put(cs+56,base+128,8);wui_put(cs+64,base+256,8);
    for(unsigned i=0;i<4;i++)wui_put(rect+4*i,(uint32_t)outer[i],4);
    wui_store(&cs_output,cs);wui_store(&rect_output,rect);
    wui_store(&title_output,(const uint8_t*)title);wui_store(&name_output,(const uint8_t*)name);
    uint64_t value=0;
    if(!wui_callback(s,ctx,0x81,0,base,&value))return 0;
    if(!value)return wui_create_failure(s,ctx);
    if(!wui_callback(s,ctx,0x83,0,base+80,&value))return 0;
    if(value){fault(ctx,AOT_UNSUPPORTED,base+80,16,GM_READ);return 0;}
    /* A custom nonclient layout would disagree with the real Cocoa view and
     * swapchain. Admit only the standard frame result, including its origin. */
    if(!read_bytes(ctx,base+80,rect,sizeof rect))return 0;
    const int64_t expected[]={ (int64_t)outer[0]+user32.frame.left,
        (int64_t)outer[1]+user32.frame.top,(int64_t)outer[2]-user32.frame.right,
        (int64_t)outer[3]-user32.frame.bottom };
    for(unsigned i=0;i<4;i++)if((int32_t)wui_u32(rect+4*i)!=expected[i]) {
        fault(ctx,AOT_UNSUPPORTED,base+80,16,GM_READ);return 0;
    }
    if(!wui_callback(s,ctx,1,0,base,&value))return 0;
    if(value==UINT64_MAX)return wui_create_failure(s,ctx);
    if(value){fault(ctx,AOT_UNSUPPORTED,ctx->current_pc,0,0);return 0;}
    user32.stats.window_state=2;return hwnd;
}
static uint64_t wui_destroy_window(AotState *s,AotContext *ctx,uint64_t hwnd) {
    if(!wui_live(hwnd))return wui_error(WUI_INVALID_WINDOW);
    if(user32.stats.window_state!=2){fault(ctx,AOT_UNSUPPORTED,hwnd,0,0);return 0;}
    WBHostStats host={};wb_host_stats(user32.config.host,&host);
    if(host.active_views){fault(ctx,AOT_MAP_STATE,hwnd,0,0);return 0;}
    user32.stats.window_state=3;
    uint64_t ignored=0;
    /* No remaining native view is allowed. Hide obtains actual focus change,
     * suppressing its native duplicate before synchronous guest KILLFOCUS. */
    int previous=0;WBHostFocusChange focus={};
    if(!wb_host_show_window(user32.config.host,hwnd,0,&previous,&focus)) {
        fault(ctx,AOT_BACKEND,hwnd,0,0);return 0;
    }
    if(!wui_focus_change(s,ctx,&focus) || !wui_callback(s,ctx,2,0,0,&ignored) ||
       !wui_callback(s,ctx,0x82,0,0,&ignored))return 0;
    return wui_native_destroy(ctx)?1:0;
}
static uint64_t wui_validate(AotContext *ctx,uint64_t hwnd,uint64_t rectangle) {
    if(!wui_live(hwnd))return wui_error(WUI_INVALID_WINDOW);
    if(rectangle){fault(ctx,AOT_UNSUPPORTED,rectangle,16,GM_READ);return 0;}
    return wb_host_validate_rect(user32.config.host,hwnd)?1:wui_error(WUI_ABORTED);
}
static uint64_t wui_defproc(AotState *s,AotContext *ctx,uint64_t hwnd,uint32_t msg,uint64_t wp,uint64_t lp) {
    if(!wui_live(hwnd))return wui_error(WUI_INVALID_WINDOW);
    switch(msg) {
    case 0x81: return 1; /* class/text/native resources already established */
    case 1: case 2: case 0x82: return 0;
    case 0x83:
        if(wp){fault(ctx,AOT_UNSUPPORTED,lp,0,0);return 0;}
        if(!wui_adjust_rect(ctx,lp,true))return 0;
        return 0; /* NCCALCSIZE(FALSE) has a zero LRESULT */
    case 7: case 8: /* single window, no caret/IME/child focus support */
        if(lp || (wp && wp!=hwnd)){fault(ctx,AOT_UNSUPPORTED,wp,0,0);return 0;}
        return 0;
    case 5: { /* no ResizeBuffers profile: reject a changed client extent */
        uint32_t width=0,height=0;
        if(wp || !wb_host_client_size(user32.config.host,hwnd,&width,&height) ||
           width!=640 || height!=360 || (uint32_t)lp!=(width|(height<<16))) {
            fault(ctx,AOT_UNSUPPORTED,hwnd,0,0);return 0;
        }
        return 0;
    }
    case 0xf: (void)wui_validate(ctx,hwnd,0);return 0; /* no brush: validate only */
    case 0x14: return 0; /* class has no background brush; no fabricated erase */
    case 0x10: (void)wui_destroy_window(s,ctx,hwnd);return 0;
    case 0x100: case 0x101:
        if(wp!=0x1b && wp!=0x25 && wp!=0x27){fault(ctx,AOT_UNSUPPORTED,wp,0,0);return 0;}
        return 0; /* admitted keys have no system/default action */
    default: fault(ctx,AOT_UNSUPPORTED,msg,0,0);return 0;
    }
}
static bool wui_posted_message(AotContext *ctx,uint32_t msg,uint64_t wp,uint64_t lp) {
    (void)lp;
    if(msg==0xf || msg==0x10 || msg==0x12 || msg==5)return true;
    if((msg==0x100 || msg==0x101) && (wp==0x1b || wp==0x25 || wp==0x27))return true;
    fault(ctx,AOT_UNSUPPORTED,msg,0,0);return false;
}
static uint64_t wui_get_message(AotState *s,AotContext *ctx,uint64_t address,uint64_t hwnd,uint32_t min,uint32_t max) {
    if(hwnd || min || max){fault(ctx,AOT_UNSUPPORTED,hwnd,0,0);return 0;}
    WuiOutput output;if(!wui_output(ctx,address,48,&output))return 0;
    for(;;) {
        WBHostMessage m={};int result=wb_host_get_message(user32.config.host,&m);
        if(result<0){wfile_set_last_error(WUI_ABORTED);return UINT32_MAX;}
        if(m.delivery==WB_DELIVERY_SENT_NOTIFICATION) {
            if(result!=1 || (m.message!=7 && m.message!=8 && m.message!=5)) {
                fault(ctx,AOT_BACKEND,m.message,0,0);return 0;
            }
            user32.stats.sent_notifications++;
            if(!wui_live(m.hwnd)){user32.stats.discarded_stale++;continue;}
            if(m.message==7)user32.focus=m.hwnd;
            if(m.message==8)user32.focus=m.wparam;
            uint64_t ignored=0;
            if(!wui_callback(s,ctx,m.message,m.wparam,(uint64_t)m.lparam,&ignored))return 0;
            /* Callback faults/Exit are terminal, not a GetMessage(-1). Plans
             * are revalidated because nested guest APIs may change mappings. */
            if(aot_should_exit(ctx))return 0;
            if(!wui_output(ctx,address,48,&output))return 0;
            continue;
        }
        if(m.delivery!=WB_DELIVERY_POSTED || (result==0)!=(m.message==0x12) ||
           (m.message==0x12 && m.hwnd) || !wui_posted_message(ctx,m.message,m.wparam,(uint64_t)m.lparam)) {
            if(!ctx->result.fault.status)fault(ctx,AOT_BACKEND,m.message,0,0);return 0;
        }
        uint8_t bytes[48]={};wui_put(bytes,m.hwnd,8);wui_put(bytes+8,m.message,4);
        wui_put(bytes+16,m.wparam,8);wui_put(bytes+24,(uint64_t)m.lparam,8);wui_put(bytes+32,m.time_ms,4);
        wui_put(bytes+36,(uint32_t)m.screen_x,4);wui_put(bytes+40,(uint32_t)m.screen_y,4);
        wui_store(&output,bytes);return result?1:0;
    }
}
static uint64_t wui_dispatch(AotState *s,AotContext *ctx,uint64_t address) {
    uint8_t bytes[48];if(!read_bytes(ctx,address,bytes,sizeof bytes))return 0;
    uint64_t hwnd=wui_u64(bytes),wp=wui_u64(bytes+16),lp=wui_u64(bytes+24);uint32_t msg=wui_u32(bytes+8);
    if(!hwnd || msg==0x12)return 0; /* thread messages/QUIT are never callbacks */
    if(!wui_live(hwnd)){user32.stats.discarded_stale++;return 0;}
    if(!wui_posted_message(ctx,msg,wp,lp))return 0;
    uint64_t result=0;user32.stats.posted_dispatches++;
    if(!wui_callback(s,ctx,msg,wp,lp,&result))return 0;
    return result;
}
static uint64_t wui_invoke(AotState *s,AotContext *ctx,uint32_t signature,uint64_t rsp,bool *has_result) {
    *has_result=true;
    if(!user32.configured || user32.owner!=(uintptr_t)ctx || !session.running ||
       session.context_identity!=(uintptr_t)ctx || session.state_identity!=(uintptr_t)s) {
        fault(ctx,AOT_INVALID,ctx->current_pc,0,0);return 0;
    }
    if(aot_should_exit(ctx))return 0;
    if(signature!=201 && (signature<210 || signature>222)){fault(ctx,AOT_UNSUPPORTED,signature,0,0);return 0;}
    user32.stats.api_calls[signature==201?0:signature-209]++;
    uint64_t a=aot_get_register(s,AOT_RCX),b=aot_get_register(s,AOT_RDX),
        c=aot_get_register(s,AOT_R8),d=aot_get_register(s,AOT_R9);
    switch(signature) {
    case 201: if(a){fault(ctx,AOT_UNSUPPORTED,a,0,0);return 0;}return user32.instance;
    case 210:
        if((uint32_t)b!=WUI_STYLE || (uint32_t)c || (uint32_t)d){fault(ctx,AOT_UNSUPPORTED,ctx->current_pc,0,0);return 0;}
        return wui_adjust_rect(ctx,a,false);
    case 211:return wui_create_window(s,ctx,rsp);
    case 212:return wui_defproc(s,ctx,a,(uint32_t)b,c,d);
    case 213:return wui_destroy_window(s,ctx,a);
    case 214:return wui_dispatch(s,ctx,a);
    case 215:return wui_get_client(ctx,a,b);
    case 216:return wui_get_message(s,ctx,a,b,(uint32_t)c,(uint32_t)d);
    case 217:
        *has_result=false;if(!wb_host_post_quit(user32.config.host,(uint32_t)a))fault(ctx,AOT_BACKEND,a,0,0);return 0;
    case 218:return wui_register_class(ctx,a);
    case 219: {
        if(!wui_live(a) || user32.stats.window_state!=2)return wui_error(WUI_INVALID_WINDOW);
        WBHostFocusChange focus={};int success=wb_host_focus_window(user32.config.host,a,&focus);
        if(!wui_focus_change(s,ctx,&focus))return 0;
        if(!success)return wui_error(WUI_ABORTED);
        return focus.before;
    }
    case 220: {
        if(!wui_live(a) || user32.stats.window_state!=2)return wui_error(WUI_INVALID_WINDOW);
        if((uint32_t)b!=0 && (uint32_t)b!=5){fault(ctx,AOT_UNSUPPORTED,b,0,0);return 0;}
        int previous=0;WBHostFocusChange focus={};
        if(!wb_host_show_window(user32.config.host,a,(uint32_t)b==5,&previous,&focus))return wui_error(WUI_ABORTED);
        if(!wui_focus_change(s,ctx,&focus))return 0;
        return previous?1:0;
    }
    case 221:return wui_unregister_class(ctx,a,b);
    case 222:return wui_validate(ctx,a,b);
    }
    fault(ctx,AOT_UNSUPPORTED,signature,0,0);return 0;
}
