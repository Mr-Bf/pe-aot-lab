// Project-owned Cocoa host. No guest pointer is interpreted as an ObjC object.
#import <Cocoa/Cocoa.h>
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#include <atomic>
#include <cmath>
#include <map>
#include <cstring>
#include "cocoa_registry.h"

struct WindowEntry {
  NSWindow *window = nil;
  id delegate = nil;
  bool tombstone = false;
  uintptr_t token = 0;
};
struct ViewEntry {
  uint64_t window = 0;
  NSView *view = nil;
  CAMetalLayer *layer = nil;
  bool tombstone = false;
};
struct NWRegistry {
  std::map<uint64_t,WindowEntry> windows;
  std::map<uintptr_t,ViewEntry> views;
  uint64_t next_window = 0x4e570001;
  uintptr_t next_view = 0x56570001;
  std::atomic<bool> stop{false};
  NWRegistryStats stats = {};
};

@interface NWWindowDelegate : NSObject <NSWindowDelegate> {
@public NWRegistry *registry;
}
@end
@implementation NWWindowDelegate
- (BOOL)windowShouldClose:(NSWindow *)sender {
  (void)sender;
  registry->stats.close_requests++;
  registry->stop.store(true);
  // Closing never destroys a view while DXMT can still use its layer.
  return NO;
}
@end

static void on_main(NWRegistry *r, void (^operation)(void)) {
  if ([NSThread isMainThread]) {
    operation();
  } else {
    dispatch_sync(dispatch_get_main_queue(), ^{
      r->stats.main_dispatches++;
      operation();
    });
  }
}
static WindowEntry *lookup(NWRegistry *r,uint64_t handle) {
  auto it=r->windows.find(handle);
  return it==r->windows.end() || it->second.tombstone ? nullptr : &it->second;
}
static bool dimensions(WindowEntry &entry,uint32_t &width,uint32_t &height) {
  NSView *content=[entry.window contentView];
  NSRect pixels=[content convertRectToBacking:[content bounds]];
  if (!std::isfinite(pixels.size.width) || !std::isfinite(pixels.size.height) ||
      pixels.size.width<=0 || pixels.size.height<=0 ||
      pixels.size.width>16384 || pixels.size.height>16384) return false;
  width=static_cast<uint32_t>(std::llround(pixels.size.width));
  height=static_cast<uint32_t>(std::llround(pixels.size.height));
  return width && height;
}
static int query(void *user,uint64_t handle,DXMTNativeWindowInfoV1 *out) {
  auto *r=static_cast<NWRegistry *>(user);
  if (!r || !out || out->size!=sizeof(*out)) return 0;
  std::memset(out,0,sizeof(*out)); out->size=sizeof(*out);
  __block int success=0;
  on_main(r, ^{
    r->stats.queries++;
    WindowEntry *entry=lookup(r,handle);
    uint32_t width=0,height=0;
    if (!entry || !dimensions(*entry,width,height)) { r->stats.query_rejections++; return; }
    out->width_pixels=width; out->height_pixels=height;
    if ([entry->window isVisible]) { out->flags|=DXMT_WSI_VISIBLE; r->stats.visible_observations++; }
    if ([entry->window isMiniaturized]) out->flags|=DXMT_WSI_MINIMIZED;
    if ([entry->window isKeyWindow]) out->flags|=DXMT_WSI_FOREGROUND;
    r->stats.width_pixels=width; r->stats.height_pixels=height;
    r->stats.backing_scale=[entry->window backingScaleFactor];
    success=1;
  });
  return success;
}
static int resize(void *user,uint64_t handle,uint32_t width,uint32_t height) {
  auto *r=static_cast<NWRegistry *>(user);
  if (!r) return 0;
  __block int success=0;
  on_main(r, ^{
    auto *entry=lookup(r,handle);
    if (!entry || !width || !height || width>16384 || height>16384) { r->stats.resize_rejections++; return; }
    CGFloat scale=[entry->window backingScaleFactor];
    if (!std::isfinite(scale) || scale<=0) { r->stats.resize_rejections++; return; }
    [entry->window setContentSize:NSMakeSize(width/scale,height/scale)];
    [entry->window displayIfNeeded];
    uint32_t actual_width=0,actual_height=0;
    if (!dimensions(*entry,actual_width,actual_height) || actual_width!=width || actual_height!=height) {
      r->stats.resize_rejections++; return;
    }
    if (entry->token) {
      auto view=r->views.find(entry->token);
      if (view==r->views.end() || view->second.tombstone) { r->stats.resize_rejections++; return; }
      [view->second.layer setContentsScale:scale];
      [view->second.layer setDrawableSize:CGSizeMake(width,height)];
    }
    r->stats.resizes++;
    r->stats.width_pixels=width; r->stats.height_pixels=height;
    r->stats.backing_scale=scale;
    success=1;
  });
  return success;
}
static uintptr_t create_view(void *user,uint64_t handle,uintptr_t device,uintptr_t *out_layer) {
  if (out_layer) *out_layer=0;
  auto *r=static_cast<NWRegistry *>(user);
  if (!r || !out_layer || !device) return 0;
  __block uintptr_t token=0;
  on_main(r, ^{
    auto *entry=lookup(r,handle);
    uint32_t width=0,height=0;
    if (!entry || entry->token || r->stats.active_views || !dimensions(*entry,width,height)) {
      r->stats.view_rejections++; return;
    }
    NSView *content=[entry->window contentView];
    NSView *view=[[NSView alloc] initWithFrame:[content bounds]];
    CAMetalLayer *layer=[[CAMetalLayer alloc] init];
    if (!view || !layer) { [view release]; [layer release]; r->stats.view_rejections++; return; }
    [layer setDevice:reinterpret_cast<id<MTLDevice>>(device)];
    [layer setPixelFormat:MTLPixelFormatBGRA8Unorm];
    [layer setOpaque:YES];
    [layer setFramebufferOnly:NO];
    [layer setContentsScale:[entry->window backingScaleFactor]];
    [layer setDrawableSize:CGSizeMake(width,height)];
    [layer setDisplaySyncEnabled:NO];
    [layer setPresentsWithTransaction:NO];
    [view setAutoresizingMask:NSViewWidthSizable|NSViewHeightSizable];
    [view setWantsLayer:YES];
    [view setLayer:layer];
    [content addSubview:view];
    token=r->next_view++;
    r->views.emplace(token,ViewEntry{handle,view,layer,false});
    entry->token=token;
    *out_layer=reinterpret_cast<uintptr_t>(layer);
    r->stats.views_created++; r->stats.active_views++;
  });
  return token;
}
static void release_view(void *user,uintptr_t token) {
  auto *r=static_cast<NWRegistry *>(user);
  if (!r) return;
  on_main(r, ^{
    auto found=r->views.find(token);
    if (!token || found==r->views.end() || found->second.tombstone) { r->stats.release_rejections++; return; }
    auto &entry=found->second;
    auto *window=lookup(r,entry.window);
    if (!window || window->token!=token) { r->stats.release_rejections++; return; }
    [entry.view removeFromSuperview];
    [entry.view setLayer:nil];
    [entry.layer release];
    [entry.view release];
    entry.view=nil; entry.layer=nil; entry.tombstone=true;
    window->token=0;
    r->stats.views_released++; r->stats.active_views--;
  });
}

NWRegistry *nw_registry_create(void) {
  if (![NSThread isMainThread]) return nullptr;
  @autoreleasepool {
    [NSApplication sharedApplication];
    if (![NSApp setActivationPolicy:NSApplicationActivationPolicyRegular]) return nullptr;
    [NSApp finishLaunching];
    return new NWRegistry;
  }
}
uint64_t nw_window_create(NWRegistry *r,uint32_t width,uint32_t height) {
  if (!r || ![NSThread isMainThread] || !width || !height || width>16384 || height>16384) return 0;
  @autoreleasepool {
    NSScreen *screen=[NSScreen mainScreen];
    if (!screen) return 0;
    CGFloat scale=[screen backingScaleFactor];
    if (!std::isfinite(scale) || scale<=0) return 0;
    NSWindow *window=[[NSWindow alloc] initWithContentRect:NSMakeRect(100,100,width/scale,height/scale)
        styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskMiniaturizable
        backing:NSBackingStoreBuffered defer:NO screen:screen];
    if (!window) return 0;
    [window setReleasedWhenClosed:NO];
    [window setTitle:@"PE AOT Lab — native DXMT window probe"];
    NWWindowDelegate *delegate=[[NWWindowDelegate alloc] init]; delegate->registry=r;
    [window setDelegate:delegate];
    [window center];
    [window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    uint64_t handle=r->next_window++;
    r->windows.emplace(handle,WindowEntry{window,delegate,false,0});
    r->stats.windows_created++;
    r->stats.window_number=static_cast<uint32_t>([window windowNumber]);
    return handle;
  }
}
int nw_window_destroy(NWRegistry *r,uint64_t handle) {
  if (!r || ![NSThread isMainThread]) return 0;
  auto *entry=lookup(r,handle);
  if (!entry || entry->token) return 0;
  [entry->window setDelegate:nil];
  [entry->window orderOut:nil];
  [entry->window close];
  [entry->delegate release];
  [entry->window release];
  entry->window=nil; entry->delegate=nil; entry->tombstone=true;
  r->stats.windows_destroyed++; r->stats.tombstones++;
  return 1;
}
void nw_callbacks(NWRegistry *r,DXMTNativeWSIV1 *out) {
  if (!out) return;
  *out={DXMT_NATIVE_WSI_VERSION,sizeof(*out),r,query,resize,create_view,release_view};
}
void nw_pump_once(NWRegistry *r,double seconds) {
  if (!r) return;
  if (![NSThread isMainThread]) { r->stats.main_thread_violations++; return; }
  @autoreleasepool {
    r->stats.event_pumps++;
    NSEvent *event=[NSApp nextEventMatchingMask:NSEventMaskAny
        untilDate:[NSDate dateWithTimeIntervalSinceNow:seconds]
        inMode:NSDefaultRunLoopMode dequeue:YES];
    if (event) [NSApp sendEvent:event];
    [NSApp updateWindows];
    CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.001,true);
  }
}
void nw_request_close(NWRegistry *r,uint64_t handle) {
  if (!r) return;
  on_main(r, ^{ auto *entry=lookup(r,handle); if(entry) [entry->window performClose:nil]; });
}
int nw_stop_requested(NWRegistry *r) { return r && r->stop.load(); }
void nw_stats(NWRegistry *r,NWRegistryStats *out) {
  if (r && out) on_main(r, ^{ *out=r->stats; });
}
