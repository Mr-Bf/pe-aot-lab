// New window_bridge host. Cocoa never owns or calls an AotState / guest callback.
#import <Cocoa/Cocoa.h>
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#include <cmath>
#include <climits>
#include <cstring>
#include <map>
#include "cocoa_host.h"
#include "message_queue.h"

struct WBWindow {
    NSWindow *window=nil;id delegate=nil;bool tombstone=false;
    uintptr_t token=0;bool pressed[3]={};double scale=0;uint32_t screen_id=0;
};
struct WBView { uint64_t hwnd=0;NSView *view=nil;CAMetalLayer *layer=nil;bool tombstone=false; };
struct WBHost {
    WBMessageQueue queue;
    std::map<uint64_t,WBWindow> windows;
    std::map<uintptr_t,WBView> views;
    uint64_t next_hwnd=0x4e570001,focused=0;
    uintptr_t next_view=0x56570001;
    unsigned synchronous_focus=0;
    WBHostStats stats={};
};
static const NSWindowStyleMask style=NSWindowStyleMaskTitled|NSWindowStyleMaskClosable;
static NSScreen *primary_screen(){return [[NSScreen screens] firstObject];}
static uint32_t screen_id(NSScreen *s){return s?[[[s deviceDescription] objectForKey:@"NSScreenNumber"] unsignedIntValue]:0;}
static WBWindow *lookup(WBHost *h,uint64_t hwnd) {
    auto it=h->windows.find(hwnd);return it==h->windows.end() || it->second.tombstone?nullptr:&it->second;
}
static bool worker(WBHost *h){return h && h->queue.is_worker();}
static void on_main(WBHost *h,void (^op)(void)) {
    if([NSThread isMainThread])op();
    else dispatch_sync(dispatch_get_main_queue(),^{h->stats.main_dispatches++;op();});
}
static bool input_metadata(WBHost *h,WBHostMessage &m,double timestamp=-1) {
    NSScreen *screen=primary_screen();double scale=screen?[screen backingScaleFactor]:0;
    NSPoint point=[NSEvent mouseLocation];NSRect bounds=screen?[screen frame]:NSZeroRect;
    double x=(point.x-NSMinX(bounds))*scale,y=(NSMaxY(bounds)-point.y)*scale;
    double time=timestamp<0?[NSProcessInfo processInfo].systemUptime:timestamp;
    if(!screen||!std::isfinite(scale)||scale<=0||!std::isfinite(x)||!std::isfinite(y)||
       x<INT32_MIN||x>INT32_MAX||y<INT32_MIN||y>INT32_MAX||!std::isfinite(time)||time<0||time>1e12) {
        h->queue.fail(WB_HOST_ERROR_BACKING_SCALE);return false;
    }
    m.screen_x=static_cast<int32_t>(std::llround(x));m.screen_y=static_cast<int32_t>(std::llround(y));
    m.time_ms=static_cast<uint32_t>(static_cast<uint64_t>(time*1000.0));return true;
}
static void post(WBHost *h,uint64_t hwnd,uint32_t msg,uint64_t wp,int64_t lp,uint32_t origin,double timestamp=-1) {
    WBHostMessage m={};m.hwnd=hwnd;m.message=msg;m.wparam=wp;m.lparam=lp;m.origin=origin;
    m.delivery=(msg==0x7||msg==0x8||msg==0x5)?WB_DELIVERY_SENT_NOTIFICATION:WB_DELIVERY_POSTED;
    if(input_metadata(h,m,timestamp))h->queue.push(m);
}
static bool dimensions(WBHost *h,WBWindow &w,uint32_t &x,uint32_t &y) {
    double scale=[w.window backingScaleFactor];
    if(!std::isfinite(scale) || scale!=w.scale || screen_id([w.window screen])!=w.screen_id ||
       screen_id(primary_screen())!=w.screen_id){h->queue.fail(WB_HOST_ERROR_BACKING_SCALE);return false;}
    NSView *v=[w.window contentView];NSRect r=[v convertRectToBacking:[v bounds]];
    if(!std::isfinite(r.size.width)||!std::isfinite(r.size.height)||r.size.width<1||r.size.height<1||r.size.width>16384||r.size.height>16384)return false;
    x=static_cast<uint32_t>(std::llround(r.size.width));y=static_cast<uint32_t>(std::llround(r.size.height));return x && y;
}
static int key_index(unsigned short code) {return code==123?0:code==124?1:code==53?2:-1;}
static uint32_t key_vk(int index){return index==0?0x25:index==1?0x27:0x1b;}
static int64_t key_bits(int index,bool up,bool previous) {
    uint32_t scan=index==0?0x4b:index==1?0x4d:0x01;
    return 1u|(scan<<16)|(index<2?1u<<24:0)|(previous?1u<<30:0)|(up?1u<<31:0);
}
static bool key_event(WBHost *h,uint64_t hwnd,NSEvent *e) {
    WBWindow *w=lookup(h,hwnd);int i=key_index([e keyCode]);
    if(!w || ![w->window isKeyWindow] || ![w->window isVisible])return false;
    if(i<0 || ([e modifierFlags]&(NSEventModifierFlagCommand|NSEventModifierFlagControl|NSEventModifierFlagOption))) {h->stats.ignored_keys++;return false;}
    bool up=[e type]==NSEventTypeKeyUp,previous=up||w->pressed[i]||[e isARepeat];
    w->pressed[i]=!up;
    post(h,hwnd,up?0x101:0x100,key_vk(i),key_bits(i,up,previous),WB_ORIGIN_COCOA_KEY,[e timestamp]);return true;
}
@interface WBHostWindow : NSWindow {
@public WBHost *host;uint64_t numeric_hwnd;
}
@end
@implementation WBHostWindow
- (void)sendEvent:(NSEvent *)event {
    if(([event type]==NSEventTypeKeyDown || [event type]==NSEventTypeKeyUp) && key_event(host,numeric_hwnd,event))return;
    [super sendEvent:event];
}
@end
@interface WBHostDelegate : NSObject <NSWindowDelegate> {
@public WBHost *host;uint64_t numeric_hwnd;
}
@end
@implementation WBHostDelegate
- (BOOL)windowShouldClose:(NSWindow *)sender {
    (void)sender;if(!lookup(host,numeric_hwnd))return NO;
    host->stats.close_requests++;post(host,numeric_hwnd,0x10,0,0,WB_ORIGIN_COCOA_WINDOW);return NO;
}
- (void)windowDidBecomeKey:(NSNotification *)note {
    (void)note;if(!lookup(host,numeric_hwnd))return;
    uint64_t previous=host->focused;host->focused=numeric_hwnd;
    if(previous!=numeric_hwnd&&!host->synchronous_focus)post(host,numeric_hwnd,0x7,previous,0,WB_ORIGIN_COCOA_WINDOW);
}
- (void)windowDidResignKey:(NSNotification *)note {
    (void)note;auto *w=lookup(host,numeric_hwnd);if(!w)return;
    for(int i=0;i<3;i++)if(w->pressed[i]) {
        w->pressed[i]=false;post(host,numeric_hwnd,0x101,key_vk(i),key_bits(i,true,true),WB_ORIGIN_FOCUS_RECOVERY);
    }
    if(host->focused==numeric_hwnd){host->focused=0;if(!host->synchronous_focus)post(host,numeric_hwnd,0x8,0,0,WB_ORIGIN_COCOA_WINDOW);}
}
- (void)windowDidResize:(NSNotification *)note {
    (void)note;auto *w=lookup(host,numeric_hwnd);uint32_t x=0,y=0;
    if(w && dimensions(host,*w,x,y)) {
        host->stats.resize_events++;post(host,numeric_hwnd,0x5,0,x|(uint64_t(y)<<16),WB_ORIGIN_COCOA_WINDOW);
        host->queue.invalidate(numeric_hwnd);
    }
}
- (void)windowDidExpose:(NSNotification *)note {
    (void)note;if(lookup(host,numeric_hwnd))host->queue.invalidate(numeric_hwnd);
}
- (void)windowDidChangeBackingProperties:(NSNotification *)note {
    (void)note;auto *w=lookup(host,numeric_hwnd);uint32_t x=0,y=0;if(w)dimensions(host,*w,x,y);
}
- (void)windowDidChangeScreen:(NSNotification *)note {
    (void)note;auto *w=lookup(host,numeric_hwnd);uint32_t x=0,y=0;if(w)dimensions(host,*w,x,y);
}
@end

static bool metrics(WBHostFrameMetrics *m) {
    NSScreen *screen=primary_screen();if(!screen || !m)return false;
    double scale=[screen backingScaleFactor];if(!std::isfinite(scale)||scale<=0)return false;
    NSRect content=NSMakeRect(0,0,640/scale,360/scale);
    NSRect frame=[NSWindow frameRectForContentRect:content styleMask:style];
    m->left=static_cast<int32_t>(std::llround((NSMinX(content)-NSMinX(frame))*scale));
    m->right=static_cast<int32_t>(std::llround((NSMaxX(frame)-NSMaxX(content))*scale));
    m->top=static_cast<int32_t>(std::llround((NSMaxY(frame)-NSMaxY(content))*scale));
    m->bottom=static_cast<int32_t>(std::llround((NSMinY(content)-NSMinY(frame))*scale));
    m->backing_scale=scale;return m->left>=0 && m->right>=0 && m->top>=0 && m->bottom>=0;
}
WBHost *wb_host_create(void) {
    if(![NSThread isMainThread])return nullptr;
    @autoreleasepool {
        [NSApplication sharedApplication];
        if([NSApp activationPolicy]!=NSApplicationActivationPolicyRegular &&
           ![NSApp setActivationPolicy:NSApplicationActivationPolicyRegular])return nullptr;
        if([NSApp activationPolicy]!=NSApplicationActivationPolicyRegular)return nullptr;
        [NSApp finishLaunching];return new WBHost;
    }
}
int wb_host_bind_worker(WBHost *h){return h && ![NSThread isMainThread] && h->queue.bind();}
void wb_host_pump_once(WBHost *h,double seconds) {
    if(!h || ![NSThread isMainThread] || !std::isfinite(seconds) || seconds<0 || seconds>1)return;
    @autoreleasepool {
        h->stats.event_pumps++;
        NSEvent *e=[NSApp nextEventMatchingMask:NSEventMaskAny untilDate:[NSDate dateWithTimeIntervalSinceNow:seconds] inMode:NSDefaultRunLoopMode dequeue:YES];
        if(e)[NSApp sendEvent:e];[NSApp updateWindows];CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.001,true);
    }
}
int wb_host_frame_metrics(WBHost *h,WBHostFrameMetrics *m) {
    if(!worker(h)||!m)return 0;*m={};__block bool result=false;on_main(h,^{result=metrics(m);});return result;
}
uint64_t wb_host_create_window(WBHost *h,uint32_t ow,uint32_t oh,const char *title) {
    if(!worker(h)||!h->queue.running()||!title||!ow||!oh||ow>17000||oh>17000)return 0;
    size_t length=strnlen(title,256);if(!length||length==256)return 0;
    for(size_t i=0;i<length;i++)if(static_cast<unsigned char>(title[i])<32 || static_cast<unsigned char>(title[i])>126)return 0;
    __block uint64_t result=0;on_main(h,^{@autoreleasepool {
        if(!h->queue.running())return;
        for(const auto &p:h->windows)if(!p.second.tombstone)return;
        WBHostFrameMetrics m={};if(!metrics(&m))return;
        int64_t width=int64_t(ow)-m.left-m.right,height=int64_t(oh)-m.top-m.bottom;
        if(width<1||height<1||width>16384||height>16384)return;
        WBHostWindow *window=[[WBHostWindow alloc] initWithContentRect:NSMakeRect(100,100,width/m.backing_scale,height/m.backing_scale)
            styleMask:style backing:NSBackingStoreBuffered defer:NO screen:primary_screen()];
        if(!window)return;
        [window setReleasedWhenClosed:NO];[window setTitle:[NSString stringWithUTF8String:title]];[window center];
        WBHostDelegate *delegate=[[WBHostDelegate alloc] init];
        if(!delegate){[window close];[window release];return;}
        uint64_t hwnd=h->next_hwnd++;window->host=h;window->numeric_hwnd=hwnd;delegate->host=h;delegate->numeric_hwnd=hwnd;
        [window setDelegate:delegate];WBWindow entry;entry.window=window;entry.delegate=delegate;entry.scale=[window backingScaleFactor];entry.screen_id=screen_id(primary_screen());
        h->windows.emplace(hwnd,entry);h->stats.windows_created++;result=hwnd;
    }});return result;
}
int wb_host_show_window(WBHost *h,uint64_t hwnd,int show,int *previous,WBHostFocusChange *focus) {
    if(!worker(h)||!previous||!focus||(show!=0&&show!=1))return 0;*previous=0;*focus={};__block int ok=0;
    on_main(h,^{auto *w=lookup(h,hwnd);if(!w||!h->queue.running())return;*previous=[w->window isVisible];focus->before=h->focused;
        h->synchronous_focus++;
        if(show){[NSApp activate];[w->window makeKeyAndOrderFront:nil];h->queue.invalidate(hwnd);}else [w->window orderOut:nil];
        h->focused=[w->window isKeyWindow]?hwnd:0;focus->after=h->focused;h->synchronous_focus--;
        if(focus->before!=focus->after)h->stats.api_focus_transitions++;ok=1;});return ok;
}
int wb_host_focus_window(WBHost *h,uint64_t hwnd,WBHostFocusChange *focus) {
    if(!worker(h)||!focus)return 0;*focus={};__block int ok=0;
    on_main(h,^{auto *w=lookup(h,hwnd);if(!w||!h->queue.running()||![w->window isVisible])return;
        focus->before=h->focused;h->synchronous_focus++;[NSApp activate];[w->window makeKeyWindow];
        h->focused=[w->window isKeyWindow]?hwnd:0;focus->after=h->focused;h->synchronous_focus--;
        if(focus->before!=focus->after)h->stats.api_focus_transitions++;ok=focus->after==hwnd;});return ok;
}
int wb_host_client_size(WBHost *h,uint64_t hwnd,uint32_t *width,uint32_t *height) {
    if(!worker(h)||!width||!height)return 0;*width=*height=0;__block int ok=0;
    on_main(h,^{auto *w=lookup(h,hwnd);if(w)ok=dimensions(h,*w,*width,*height);});return ok;
}
int wb_host_window_rect(WBHost *h,uint64_t hwnd,int32_t rect[4]) {
    if(!worker(h)||!rect)return 0;std::memset(rect,0,4*sizeof(*rect));__block int ok=0;
    on_main(h,^{auto *w=lookup(h,hwnd);uint32_t width=0,height=0;
        if(!w||!dimensions(h,*w,width,height))return;
        NSRect frame=[w->window frame],screen=[primary_screen() frame];double scale=w->scale;
        double bounds[4]={(NSMinX(frame)-NSMinX(screen))*scale,(NSMaxY(screen)-NSMaxY(frame))*scale,
                          (NSMaxX(frame)-NSMinX(screen))*scale,(NSMaxY(screen)-NSMinY(frame))*scale};
        for(unsigned i=0;i<4;i++)if(!std::isfinite(bounds[i])||bounds[i]<INT32_MIN||bounds[i]>INT32_MAX)return;
        for(unsigned i=0;i<4;i++)rect[i]=static_cast<int32_t>(std::llround(bounds[i]));
        ok=rect[2]>rect[0]&&rect[3]>rect[1];
    });return ok;
}
static bool destroy(WBHost *h,uint64_t hwnd,bool forced) {
    auto *w=lookup(h,hwnd);if(!w||w->token)return false;
    [w->window setDelegate:nil];[w->window orderOut:nil];[w->window close];[w->delegate release];[w->window release];
    w->window=nil;w->delegate=nil;w->tombstone=true;if(h->focused==hwnd)h->focused=0;
    h->queue.remove_window(hwnd);h->stats.windows_destroyed++;h->stats.tombstones++;
    if(forced)h->stats.forced_cleanup_windows++;return true;
}
int wb_host_destroy_window(WBHost *h,uint64_t hwnd) {
    if(!worker(h))return 0;__block int ok=0;on_main(h,^{ok=destroy(h,hwnd,false);});return ok;
}
int wb_host_validate_rect(WBHost *h,uint64_t hwnd) {
    if(!worker(h))return 0;__block int ok=0;on_main(h,^{if(lookup(h,hwnd)){h->queue.validate(hwnd);ok=1;}});return ok;
}
int wb_host_get_message(WBHost *h,WBHostMessage *out) {
    if(!h)return -1;int result=h->queue.take(out);
    // take released its mutex before the synchronous main-thread request.
    if(result==1 && out->message==0xf && out->origin==WB_ORIGIN_COCOA_WINDOW) {
        __block bool ok=false;on_main(h,^{ok=input_metadata(h,*out);});if(!ok)return -1;
    }
    return result;
}
int wb_host_input_snapshot(WBHost *h,uint32_t *time_ms,int32_t point[2]) {
    if(!worker(h)||!time_ms||!point)return 0;__block WBHostMessage m={};__block bool ok=false;
    on_main(h,^{ok=input_metadata(h,m);});if(ok){*time_ms=m.time_ms;point[0]=m.screen_x;point[1]=m.screen_y;}return ok;
}
int wb_host_post_quit(WBHost *h,uint32_t code) {
    if(!worker(h))return 0;__block WBHostMessage m={};m.message=0x12;m.origin=WB_ORIGIN_GUEST_QUEUE_API;m.wparam=code;
    __block int ok=0;on_main(h,^{if(input_metadata(h,m))ok=h->queue.push(m);});return ok;
}
int wb_host_test_post(WBHost *h,uint64_t hwnd,uint32_t msg,uint64_t wp,int64_t lp) {
    if(!h || (msg!=0x100 && msg!=0x101 && msg!=0x10 && msg!=0x5))return 0;
    __block int ok=0;on_main(h,^{if(!lookup(h,hwnd))return;
        WBHostMessage m={};m.hwnd=hwnd;m.message=msg;m.wparam=wp;m.lparam=lp;m.origin=WB_ORIGIN_TEST_QUEUE;
        if(input_metadata(h,m))ok=h->queue.push(m);});return ok;
}
static int wsi_query(void *u,uint64_t hwnd,DXMTNativeWindowInfoV1 *out) {
    auto *h=static_cast<WBHost *>(u);if(!h||!out||out->size!=sizeof(*out))return 0;
    *out={};out->size=sizeof(*out);__block int ok=0;on_main(h,^{auto *w=lookup(h,hwnd);uint32_t x=0,y=0;
        if(!w||!dimensions(h,*w,x,y))return;out->width_pixels=x;out->height_pixels=y;
        if([w->window isVisible])out->flags|=DXMT_WSI_VISIBLE;
        if([w->window isKeyWindow])out->flags|=DXMT_WSI_FOREGROUND;ok=1;});return ok;
}
static int wsi_resize(void *,uint64_t,uint32_t,uint32_t){return 0;} // not an admitted guest API
static uintptr_t wsi_create(void *u,uint64_t hwnd,uintptr_t device,uintptr_t *out_layer) {
    if(out_layer)*out_layer=0;auto *h=static_cast<WBHost *>(u);if(!h||!device||!out_layer)return 0;
    __block uintptr_t token=0;on_main(h,^{auto *w=lookup(h,hwnd);uint32_t x=0,y=0;
        if(!w||w->token||h->stats.active_views||!dimensions(h,*w,x,y))return;
        NSView *content=[w->window contentView];NSView *view=[[NSView alloc] initWithFrame:[content bounds]];
        CAMetalLayer *layer=[[CAMetalLayer alloc] init];if(!view||!layer){[view release];[layer release];return;}
        [layer setDevice:reinterpret_cast<id<MTLDevice>>(device)];[layer setPixelFormat:MTLPixelFormatBGRA8Unorm];
        [layer setOpaque:YES];[layer setFramebufferOnly:NO];[layer setContentsScale:w->scale];[layer setDrawableSize:CGSizeMake(x,y)];
        [layer setDisplaySyncEnabled:NO];[layer setPresentsWithTransaction:NO];
        [view setAutoresizingMask:NSViewWidthSizable|NSViewHeightSizable];[view setWantsLayer:YES];[view setLayer:layer];[content addSubview:view];
        token=h->next_view++;h->views.emplace(token,WBView{hwnd,view,layer,false});w->token=token;
        *out_layer=reinterpret_cast<uintptr_t>(layer);h->stats.views_created++;h->stats.active_views++;
    });return token;
}
static void wsi_release(void *u,uintptr_t token) {
    auto *h=static_cast<WBHost *>(u);if(!h)return;on_main(h,^{auto it=h->views.find(token);
        if(!token||it==h->views.end()||it->second.tombstone)return;
        auto &v=it->second;auto *w=lookup(h,v.hwnd);if(!w||w->token!=token)return;
        [v.view removeFromSuperview];[v.view setLayer:nil];[v.layer release];[v.view release];
        v.view=nil;v.layer=nil;v.tombstone=true;w->token=0;h->stats.views_released++;h->stats.active_views--;
    });
}
void wb_host_callbacks(WBHost *h,DXMTNativeWSIV1 *out) {
    if(h&&out)*out={DXMT_NATIVE_WSI_VERSION,sizeof(*out),h,wsi_query,wsi_resize,wsi_create,wsi_release};
}
void wb_host_stats(WBHost *h,WBHostStats *out) {
    if(!h||!out)return;on_main(h,^{*out=h->stats;h->queue.stats(*out);});
}
void wb_host_session_end(WBHost *h){if(h)h->queue.end();}
int wb_host_finish(WBHost *h) {
    if(!h||![NSThread isMainThread]||h->stats.active_views)return 0;
    h->queue.end();for(auto &p:h->windows)if(!p.second.tombstone && !destroy(h,p.first,true))return 0;return 1;
}
