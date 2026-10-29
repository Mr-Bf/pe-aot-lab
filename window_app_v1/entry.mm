/* No-argument native App entry. Guest rules/objects remain in the frozen PE.
 * Standard streams are not redirected; LaunchServices may capture pre-main
 * dyld output. Private wrapper diagnostics supplement, not replace, that log. */
#import <Cocoa/Cocoa.h>
#include "noarg_files_v1.h"
#include <cstdio>
#include <cstdlib>
#include <cstdint>
extern "C" int aot_window_main(int,char **);
#include "app_config.h"

static NSData *json_bytes(NSDictionary *record){
    NSError *error=nil;NSData *body=[NSJSONSerialization dataWithJSONObject:record options:NSJSONWritingSortedKeys error:&error];
    if(!body)return nil;
    NSMutableData *data=[NSMutableData dataWithData:body];const char newline='\n';[data appendBytes:&newline length:1];return data;
}
static bool save_record(int directory,const char *name,NSDictionary *record){
    NSData *data=json_bytes(record);return data&&na_write_exclusive(directory,name,[data bytes],[data length])==0;
}
static int failure(NSString *reason,int code){
    NSData *data=json_bytes(@{@"outcome":@"HOST_ERROR",@"error":reason});
    if(data)fwrite([data bytes],1,[data length],stdout);
    fprintf(stderr,"PE_AOT_NOARG_PREPARATION_FAILED errno=%d; no guest entry\n",code);
    return 64;
}

@interface NADelegate : NSObject <NSApplicationDelegate> {
@public
    uint64_t active_notifications,key_notifications,terminate_requests,close_requests;
    bool active_ever,key_ever;
    Class guest_window_class;
}
- (void)observe:(NSNotification *)notification;
@end
@implementation NADelegate
- (void)observe:(NSNotification *)notification {
    if(![NSThread isMainThread])return;
    if([[notification name] isEqualToString:NSApplicationDidBecomeActiveNotification])active_notifications++;
    if([[notification name] isEqualToString:NSWindowDidBecomeKeyNotification])key_notifications++;
    active_ever=active_ever||[NSApp isActive];
    NSWindow *window=[NSApp keyWindow];
    key_ever=key_ever||(window&&[window isKindOfClass:guest_window_class]);
}
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender {
    (void)sender;terminate_requests++;
    /* Never let Dock Quit terminate the process beneath the guest. Native
     * performClose enters WBHostWindow's existing WM_CLOSE path; it does not close
     * the native view or save host-crafted state. During startup/teardown there
     * may be no guest window, so this request is conservatively cancelled. */
    if([NSThread isMainThread])for(NSWindow *window in [NSApp windows]){
        if([window isKindOfClass:guest_window_class]&&[window isVisible]){
            close_requests++;[window performClose:nil];break;
        }
    }
    return NSTerminateCancel;
}
@end

int main(int argc,char **argv){
    @autoreleasepool {
        if(argc!=1||!argv||!argv[0]||![NSThread isMainThread])return failure(@"no-argument main-thread App entry required",EINVAL);
        NSBundle *bundle=[NSBundle mainBundle];
        if(![[bundle bundleIdentifier] isEqualToString:kApplication])return failure(@"configured App bundle identity required",EINVAL);
        Class guestWindowClass=NSClassFromString(@"WBHostWindow");
        if(!guestWindowClass||![guestWindowClass isSubclassOfClass:[NSWindow class]])return failure(@"frozen Cocoa guest window class unavailable",EINVAL);
        NSURL *support=[[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory
            inDomains:NSUserDomainMask] firstObject];
        if(!support||![support isFileURL])return failure(@"Application Support location unavailable",errno);
        NSString *runID=[[NSUUID UUID] UUIDString];NAFileSet files;
        if(na_open_files([[support path] fileSystemRepresentation],[kApplication UTF8String],[runID UTF8String],&files)!=0){
            const int saved=errno;return failure(saved==EWOULDBLOCK?@"another instance holds this App data lock":@"private App directories or lock rejected",saved);
        }
        NSString *dataPath=[[[support path] stringByAppendingPathComponent:kApplication] stringByAppendingPathComponent:@"Data"];
        NSString *runPath=[[[[support path] stringByAppendingPathComponent:kApplication] stringByAppendingPathComponent:@"Runs"] stringByAppendingPathComponent:runID];
        const char *data=[dataPath fileSystemRepresentation];
        if(!data||strlen(data)>=PATH_MAX){na_close(&files);return failure(@"data path is not representable",EINVAL);}
        /* All strings remain owned by this outer autorelease pool until host
         * returns. The trusted host receives only configuration, no guest data. */
        char *hostArgs[]={argv[0],(char *)"--data-dir",(char *)data,(char *)"--budget",(char *)"100000000",nullptr};
        NSDictionary *started=@{@"schema":@1,@"status":@"ENTRY_STARTED_NOT_ACCEPTED",@"pid":@(getpid()),
            @"uid":@(geteuid()),@"run_id":runID,@"bundle_identifier":kApplication,@"bundle_path":[bundle bundlePath],
            @"argument_count":@(argc),@"data_directory":dataPath,@"run_directory":runPath,@"instance_lock_held":@YES,
            @"host_arguments":@[ @"--data-dir",dataPath,@"--budget",@"100000000" ],
            @"test_queue_requested":@NO,@"input_origin":@"Cocoa NSEvent; physical versus OS-synthetic is not inferred",
            @"scope":@"wrapper preparation only; raw host stdout and external execution acceptance are required"};
        if(!save_record(files.run,"entry-started.json",started)){int saved=errno;na_close(&files);return failure(@"cannot record startup",saved);}
        fprintf(stderr,"PE_AOT_NOARG_RUN %s\n",[runPath fileSystemRepresentation]);
        [NSApplication sharedApplication];
        const NSInteger initialPolicy=[NSApp activationPolicy];
        NADelegate *delegate=[[NADelegate alloc] init];
        delegate->guest_window_class=guestWindowClass;
        [NSApp setDelegate:delegate];
        NSNotificationCenter *center=[NSNotificationCenter defaultCenter];
        [center addObserver:delegate selector:@selector(observe:) name:NSApplicationDidBecomeActiveNotification object:NSApp];
        [center addObserver:delegate selector:@selector(observe:) name:NSWindowDidBecomeKeyNotification object:nil];
        delegate->active_ever=[NSApp isActive];
        int result=aot_window_main(5,hostArgs);
        NSDictionary *finished=@{@"schema":@1,@"status":@"HOST_RETURNED_NOT_ACCEPTED",@"pid":@(getpid()),@"run_id":runID,
            @"host_returncode":@(result),@"initial_activation_policy":@(initialPolicy),@"final_activation_policy":@([NSApp activationPolicy]),
            @"active_ever":@(delegate->active_ever),@"guest_window_key_ever":@(delegate->key_ever),
            @"active_notifications":@(delegate->active_notifications),@"key_notifications":@(delegate->key_notifications),
            @"terminate_requests":@(delegate->terminate_requests),@"forwarded_close_requests":@(delegate->close_requests),
            @"instance_lock_held_until_host_return":@YES,@"test_queue_requested":@NO,
            @"scope":@"native lifecycle observation only; no physical-input, pixel or successful-save inference"};
        bool saved=save_record(files.run,"entry-finished.json",finished);
        [center removeObserver:delegate];[NSApp setDelegate:nil];[delegate release];
        na_close(&files);
        if(!saved){fprintf(stderr,"PE_AOT_NOARG_COMPLETION_RECORD_FAILED\n");return 64;}
        return result;
    }
}
