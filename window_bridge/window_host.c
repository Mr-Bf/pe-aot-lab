/* Native startup/API host only. All sample state, Draw decisions and saving
 * remain in the unmodified Windows PE. A test sequence is explicitly labeled
 * queue input, never an OS keyboard claim or a host write to guest state. */
#include "window_runtime/runtime.h"
#include "callback_v1.h"
#include "user32_v1.h"
#include "cocoa_host.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>
#include "native_image.h"
extern void *aot_entry(void*,uint64_t,void*);
static const uint64_t STACK_BASE=UINT64_C(0x70000000),EXIT_PC=UINT64_C(0x7fff00000000);
static const uint64_t PROXY_BASE=UINT64_C(0x60000000),MAP_BASE=UINT64_C(0x61000000),SCRATCH_BASE=UINT64_C(0x62000000);
enum {STACK_SIZE=65536,PROXY_SIZE=9*4096,MAP_SIZE=1024*1024,MAX_TEST_EVENTS=64};
static DXMTNativeWSIV1 original_wsi;
static atomic_uint_fast64_t observed_hwnd;
/* Preserve original callback userdata and return value. This observes an
 * already validated numeric token; it neither invents a handle nor touches
 * guest memory. The callback and original table have process lifetime. */
static int observe_query(void *user,uint64_t hwnd,DXMTNativeWindowInfoV1 *info) {
    int value=original_wsi.query(user,hwnd,info);
    if(value==1)atomic_store_explicit(&observed_hwnd,hwnd,memory_order_release);
    return value;
}
typedef struct {
    WBHost *host;const char *directory;uint64_t base,budget;
    atomic_bool done;
    uint32_t status,setup_status,exit_requested,exit_code,exit_depth,callback_end,user32_end;
    uint64_t exit_pc,exit_rsp;
    AotResult result;AotD3DStats before,after;AotWindowCallbackStats callbacks;AotUser32Stats user32;
    uint32_t cleanup,open_before,open_after,cleanup_closes,cleanup_errors,last_error;
    uint64_t file_calls[6],bytes_read,bytes_written;
    AotState *state;AotContext *ctx;uint8_t *image,*stack,*proxies,*map,*scratch,*thunks,*thunk_permissions;
    uint8_t stack_permissions[16],proxy_permissions[9],map_permissions[256],scratch_permissions[1];
} Run;
static void put64(uint8_t*p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(8*i));}
static int number(const char*t,uint64_t*out){if(!t||*t<'0'||*t>'9')return 0;char*end=NULL;errno=0;unsigned long long n=strtoull(t,&end,0);if(errno||!end||*end)return 0;*out=n;return 1;}
static uint64_t milliseconds(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))abort();return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;}
static int host_error(const char*message){printf("{\"outcome\":\"HOST_ERROR\",\"error\":\"%s\"}\n",message);return 64;}
static void *worker(void *opaque) {
    Run*r=opaque;int d3d=0,files=0,callbacks=0,user32=0;
    r->status=AOT_INVALID;r->setup_status=AOT_INVALID;
    if(!wb_host_bind_worker(r->host))goto done;
    if(!kThunkCount || kThunks[kThunkCount-1]<kThunks[0])goto done;
    size_t thunk_size=(size_t)(kThunks[kThunkCount-1]-kThunks[0])+4096;
    if((thunk_size&4095) || thunk_size>4*1024*1024)goto done;
    r->image=malloc(sizeof kImageBytes);r->stack=calloc(1,STACK_SIZE);r->proxies=calloc(1,PROXY_SIZE);
    r->map=calloc(1,MAP_SIZE);r->scratch=calloc(1,4096);r->thunks=calloc(1,thunk_size);r->thunk_permissions=calloc(thunk_size/4096,1);
    r->state=aot_state_create();
    if(!r->image||!r->stack||!r->proxies||!r->map||!r->scratch||!r->thunks||!r->thunk_permissions||!r->state)goto done;
    memcpy(r->image,kImageBytes,sizeof kImageBytes);
    for(size_t i=0;i<kRelocationCount;i++){if(kRelocations[i].rva>sizeof kImageBytes-8)abort();put64(r->image+kRelocations[i].rva,kRelocations[i].value+r->base-kPreferredBase);}
    for(size_t i=0;i<kImportCount;i++){if(kImports[i].iat_rva>sizeof kImageBytes-8)abort();put64(r->image+kImports[i].iat_rva,r->base+kImports[i].target_rva);}
    uint64_t rsp=STACK_BASE+STACK_SIZE-0x108;put64(r->stack+(size_t)(rsp-STACK_BASE),EXIT_PC);aot_set_register(r->state,AOT_RSP,rsp);
    memset(r->stack_permissions,GM_READ|GM_WRITE,sizeof r->stack_permissions);memset(r->proxy_permissions,GM_READ,sizeof r->proxy_permissions);r->scratch_permissions[0]=GM_READ|GM_WRITE;
    r->ctx=aot_context_create(r->base,kInstructions,kInstructionCount,r->budget,EXIT_PC,rsp);if(!r->ctx)goto done;
    GuestMemory regions[]={{r->base,sizeof kImageBytes,r->image,kImagePermissions,sizeof kImagePermissions},
        {STACK_BASE,STACK_SIZE,r->stack,r->stack_permissions,16},{PROXY_BASE,PROXY_SIZE,r->proxies,r->proxy_permissions,9},
        {MAP_BASE,MAP_SIZE,r->map,r->map_permissions,256},{SCRATCH_BASE,4096,r->scratch,r->scratch_permissions,1},
        {r->base+kThunks[0],thunk_size,r->thunks,r->thunk_permissions,thunk_size/4096}};
    AotD3DConfig config={0};config.proxy_base=PROXY_BASE;config.proxy_count=AOT_D3D_MAX_OBJECTS;config.map_base=MAP_BASE;config.map_capacity=MAP_SIZE;
    for(unsigned i=0;i<AOT_D3D_KIND_COUNT;i++)config.vtable_va[i]=PROXY_BASE+4096*(i+1);
    for(unsigned i=0;i<AOT_D3D_METHOD_COUNT;i++)config.method_targets[i]=r->base+kD3DMethodThunks[i];
    const unsigned methods[][3]={{0,2,AOT_D3D_RELEASE},{0,5,AOT_D3D_CREATE_TEXTURE},{0,9,AOT_D3D_CREATE_RTV},{0,39,AOT_D3D_GET_REMOVED},
        {1,2,AOT_D3D_RELEASE},{1,14,AOT_D3D_MAP},{1,15,AOT_D3D_UNMAP},{1,47,AOT_D3D_COPY},{1,50,AOT_D3D_CLEAR},
        {2,2,AOT_D3D_RELEASE},{3,2,AOT_D3D_RELEASE},{4,2,AOT_D3D_RELEASE},{5,2,AOT_D3D_RELEASE},{6,2,AOT_D3D_RELEASE},{7,2,AOT_D3D_RELEASE},
        {0,12,AOT_D3D_CREATE_VS},{0,15,AOT_D3D_CREATE_PS},{0,22,AOT_D3D_CREATE_RASTER},
        {1,33,AOT_D3D_OM_SET},{1,43,AOT_D3D_RS_SET},{1,44,AOT_D3D_VIEWPORT},{1,24,AOT_D3D_TOPOLOGY},{1,11,AOT_D3D_VS_SET},{1,9,AOT_D3D_PS_SET},{1,13,AOT_D3D_DRAW},
        {7,8,AOT_D3D_PRESENT},{7,9,AOT_D3D_GET_BUFFER},{1,110,AOT_D3D_CLEAR_STATE},{1,111,AOT_D3D_FLUSH}};
    for(size_t i=0;i<sizeof methods/sizeof *methods;i++)put64(r->proxies+4096*(methods[i][0]+1)+8*methods[i][1],config.method_targets[methods[i][2]]);
    for(size_t i=0;i<kThunkCount;i++){size_t off=(size_t)(kThunks[i]-kThunks[0]);if((off&4095)||off>=thunk_size)abort();r->thunks[off]=0xc3;r->thunk_permissions[off/4096]=GM_READ|AOT_EXEC;}
    for(size_t i=0;i<sizeof regions/sizeof *regions;i++){r->setup_status=aot_add_region(r->ctx,&regions[i]);if(r->setup_status)goto done;}
#ifdef AOT_WINDOW_SWITCH_V1
    r->setup_status=aot_bind_image_switch(r->ctx,r->base);if(r->setup_status)goto done;
#endif
    r->setup_status=aot_d3d_session_begin(r->ctx,&config);if(r->setup_status)goto done;d3d=1;
    r->setup_status=aot_file_session_begin(r->directory);if(r->setup_status)goto done;files=1;
    r->setup_status=aot_window_callbacks_begin(r->ctx,kCallbacks,kCallbackCount);if(r->setup_status)goto done;callbacks=1;
    AotUser32Config user_config={r->host,SCRATCH_BASE,4096};r->setup_status=aot_user32_session_begin(r->ctx,&user_config);if(r->setup_status)goto done;user32=1;
    r->status=aot_execute(aot_entry,r->state,r->ctx,r->base+kEntryRva);aot_result(r->ctx,&r->result);
    r->exit_requested=aot_process_exit_requested();r->exit_code=aot_process_exit_code();r->exit_pc=aot_process_exit_pc();r->exit_rsp=aot_process_exit_rsp();r->exit_depth=aot_process_exit_depth();
done:
    if(d3d){aot_d3d_stats(&r->before);r->cleanup=aot_d3d_session_end();aot_d3d_stats(&r->after);}
    /* No cleanup path executes WndProc, synthesizes QUIT, or writes a save.
     * Native window teardown waits until D3D has returned every view token. */
    if(user32){aot_user32_stats(&r->user32);r->user32_end=aot_user32_session_end(r->ctx);}
    if(callbacks){aot_window_callback_stats(&r->callbacks);r->callback_end=aot_window_callbacks_end(r->ctx);}
    if(files){r->open_before=aot_file_open_handles();aot_file_session_end();r->open_after=aot_file_open_handles();
        r->cleanup_closes=aot_file_cleanup_closes();r->cleanup_errors=aot_file_cleanup_errors();r->last_error=aot_file_last_error();
        r->bytes_read=aot_file_bytes_read();r->bytes_written=aot_file_bytes_written();for(unsigned i=0;i<6;i++)r->file_calls[i]=aot_file_api_calls(i+4);}
    wb_host_session_end(r->host);atomic_store_explicit(&r->done,true,memory_order_release);return NULL;
}
static void print_d3d(const AotD3DStats*s){printf("{");
#define U(field) printf("\"" #field "\":%" PRIu64 ",",s->field)
    U(create_device_calls);U(create_texture_calls);U(create_rtv_calls);U(clear_calls);U(copy_calls);U(map_calls);U(unmap_calls);U(get_removed_calls);U(release_calls);U(exit_calls);U(this_checks);U(created);U(guest_released);U(cleanup_releases);U(cleanup_unmaps);U(map_bytes_copied);U(map_postcall_failures);
    U(create_vs_calls);U(create_ps_calls);U(create_rasterizer_calls);U(om_set_calls);U(rs_set_calls);U(viewport_calls);U(topology_calls);U(vs_set_calls);U(ps_set_calls);U(draw_calls);U(create_swapchain_calls);U(present_calls);U(get_buffer_calls);U(clear_state_calls);U(flush_calls);U(cleanup_clear_state_calls);U(cleanup_flush_calls);
#undef U
    printf("\"live_objects\":%u,\"active_maps\":%u,\"last_native_release\":%u}",s->live_objects,s->active_maps,s->last_native_release);
}
static void print_host(const WBHostStats*s){printf("{");
#define U(field) printf("\"" #field "\":%" PRIu64 ",",s->field)
    U(windows_created);U(windows_destroyed);U(forced_cleanup_windows);U(views_created);U(views_released);U(active_views);U(cocoa_key_events);U(cocoa_window_events);U(test_queue_events);U(focus_recovery_events);U(guest_queue_events);U(ignored_keys);U(messages_taken);U(waits);U(quit_messages);U(queue_overflows);U(main_dispatches);U(event_pumps);U(close_requests);U(resize_events);U(api_focus_transitions);U(sent_notifications);
#undef U
    printf("\"pending_messages\":%u,\"error\":%u,\"stopped\":%u,\"worker_bound\":%u,\"paint_invalid\":%u,\"tombstones\":%u}",s->pending_messages,s->error,s->stopped,s->worker_bound,s->paint_invalid,s->tombstones);
}
static void print_user(const AotUser32Stats*s){printf("{\"api_calls\":[");for(unsigned i=0;i<14;i++)printf("%s%" PRIu64,i?",":"",s->api_calls[i]);printf("],");
#define U(field) printf("\"" #field "\":%" PRIu64 ",",s->field)
    U(callbacks);U(sent_notifications);U(posted_dispatches);U(discarded_stale);U(classes_registered);U(classes_unregistered);U(windows_created);U(windows_destroyed);
#undef U
    printf("\"registered\":%u,\"window_state\":%u,\"hwnd\":%" PRIu64 "}",s->registered,s->window_state,s->hwnd);
}
typedef struct {uint32_t message;uint64_t key;int64_t bits;const char*name;} TestEvent;
static int parse_events(const char*text,TestEvent*out,size_t*count){
    if(!text||!*text||text[0]==','||text[strlen(text)-1]==','||strstr(text,",,"))return 0;
    char *copy=strdup(text);if(!copy)return 0;char *save=NULL;*count=0;
    for(char*t=strtok_r(copy,",",&save);t;t=strtok_r(NULL,",",&save)){
        if(*count==MAX_TEST_EVENTS){free(copy);return 0;}TestEvent e={0x100,0,0,NULL};
        if(!strcmp(t,"right"))e=(TestEvent){0x100,0x27,0x014d0001,"right"};
        else if(!strcmp(t,"left"))e=(TestEvent){0x100,0x25,0x014b0001,"left"};
        else if(!strcmp(t,"right-repeat"))e=(TestEvent){0x100,0x27,0x414d0001,"right-repeat"};
        else if(!strcmp(t,"left-repeat"))e=(TestEvent){0x100,0x25,0x414b0001,"left-repeat"};
        else if(!strcmp(t,"right-up"))e=(TestEvent){0x101,0x27,0xc14d0001,"right-up"};
        else if(!strcmp(t,"left-up"))e=(TestEvent){0x101,0x25,0xc14b0001,"left-up"};
        else if(!strcmp(t,"escape"))e=(TestEvent){0x100,0x1b,0x00010001,"escape"};
        else if(!strcmp(t,"close"))e=(TestEvent){0x10,0,0,"close"};else {free(copy);return 0;}
        out[(*count)++]=e;
    }
    free(copy);return *count>0;
}
static void print_file(const char*directory){
    int dir=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),fd=-1;uint8_t data[4096];size_t length=0;int error=0,truncated=0;
    if(dir<0)error=errno;else {fd=openat(dir,kSaveName,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);if(fd<0)error=errno;}
    if(fd>=0){struct stat st;if(fstat(fd,&st)){error=errno;}else if(!S_ISREG(st.st_mode)){error=EINVAL;}
        else {for(;;){ssize_t n=read(fd,data+length,sizeof data-length);if(n<0){if(errno==EINTR)continue;error=errno;break;}if(!n)break;length+=(size_t)n;if(length==sizeof data){uint8_t extra;ssize_t more=read(fd,&extra,1);truncated=more!=0;break;}}}close(fd);}
    if(dir>=0)close(dir);printf("{\"name\":\"%s\",\"errno\":%d,\"truncated\":%s,\"data_hex\":",kSaveName,error,truncated?"true":"false");
    if(error)printf("null");else {printf("\"");for(size_t i=0;i<length;i++)printf("%02x",data[i]);printf("\"");}printf("}");
}
int main(int argc,char**argv){
    Run r={0};r.base=kPreferredBase;r.budget=UINT64_C(10000000);uint64_t timeout_ms=0;TestEvent events[MAX_TEST_EVENTS];size_t event_count=0;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--data-dir")&&i+1<argc)r.directory=argv[++i];
        else if(!strcmp(argv[i],"--base")&&i+1<argc){if(!number(argv[++i],&r.base))return host_error("invalid base");}
        else if(!strcmp(argv[i],"--budget")&&i+1<argc){if(!number(argv[++i],&r.budget)||!r.budget)return host_error("invalid budget");}
        else if(!strcmp(argv[i],"--timeout-ms")&&i+1<argc){if(!number(argv[++i],&timeout_ms)||timeout_ms>600000)return host_error("invalid timeout");}
        else if(!strcmp(argv[i],"--test-sequence")&&i+1<argc){if(!parse_events(argv[++i],events,&event_count))return host_error("invalid test sequence");}
        else return host_error("usage: --data-dir directory [--base value] [--budget value] [--timeout-ms value] [--test-sequence right,left,escape]");
    }
    if(!r.directory||r.directory[0]!='/')return host_error("absolute trusted data directory required");
    if((r.base&65535)||r.base>UINT64_MAX-sizeof kImageBytes||(r.base!=kPreferredBase&&!kCanRebase))return host_error("invalid image mapping");
    for(size_t i=0;i<kThunkCount;i++)if(r.base>UINT64_MAX-kThunks[i]-4096)return host_error("thunk address overflow");
    int translated=-1,translated_errno=0;size_t sys_size=sizeof translated;
    if(sysctlbyname("sysctl.proc_translated",&translated,&sys_size,NULL,0)){translated_errno=errno;if(errno==ENOENT)translated=0;}
    if(translated!=0)return host_error("native ARM64 process required");
    r.host=wb_host_create();if(!r.host)return host_error("Cocoa initialization failed");
    wb_host_callbacks(r.host,&original_wsi);DXMTNativeWSIV1 callbacks=original_wsi;callbacks.query=observe_query;
    if(!DXMTNativeInstallWSIV1(&callbacks))return host_error("native WSI installation failed");
    pthread_t thread;if(pthread_create(&thread,NULL,worker,&r))return host_error("guest worker creation failed");
    uint64_t start=milliseconds(),last_wait=0,posted_waits[MAX_TEST_EVENTS]={0};size_t posted=0;int timed_out=0,inject_error=0;
    while(!atomic_load_explicit(&r.done,memory_order_acquire)){
        wb_host_pump_once(r.host,0.001);WBHostStats stats={0};wb_host_stats(r.host,&stats);
        uint64_t hwnd=atomic_load_explicit(&observed_hwnd,memory_order_acquire);
        if(!timed_out&&!inject_error&&posted<event_count&&hwnd&&stats.waits>last_wait&&!stats.pending_messages&&!stats.paint_invalid){
            if(!wb_host_test_post(r.host,hwnd,events[posted].message,events[posted].key,events[posted].bits)){inject_error=1;wb_host_session_end(r.host);}
            else {posted_waits[posted]=stats.waits;last_wait=stats.waits;posted++;}
        }
        if(timeout_ms&&!timed_out&&milliseconds()-start>=timeout_ms){timed_out=1;wb_host_session_end(r.host);}
    }
    int join_status=pthread_join(thread,NULL);WBHostStats before_finish={0},after_finish={0};wb_host_stats(r.host,&before_finish);
    int finished=join_status?0:wb_host_finish(r.host);wb_host_stats(r.host,&after_finish);
    const char*outcome=r.setup_status?"SETUP_ERROR":r.status==AOT_PROCESS_EXITED?"PROCESS_EXITED":r.status==AOT_OK?"FUNCTION_RETURN":"FAULT";
    int host_status=r.setup_status||join_status||!finished||after_finish.active_views||r.after.live_objects||r.after.active_maps||r.cleanup_errors||r.open_after||r.callback_end||r.user32_end||timed_out||inject_error?64:r.status==AOT_PROCESS_EXITED?0:r.status==AOT_OK?2:3;
    printf("{\"outcome\":\"%s\",\"aot_status\":%u,\"setup_status\":%u,\"pe_sha256\":\"%s\",\"image_base\":%" PRIu64 ",\"entry_rva\":%u,\"entry_arguments\":0,\"host_exit_code\":%d,\"proc_translated\":%d,\"proc_translated_errno\":%d,\"timed_out\":%s,\"join_status\":%d,\"host_finished\":%s,",outcome,r.status,r.setup_status,kPeSha256,r.base,kEntryRva,host_status,translated,translated_errno,timed_out?"true":"false",join_status,finished?"true":"false");
    printf("\"exit_requested\":%u,\"exit_code\":%u,\"exit_pc\":%" PRIu64 ",\"exit_rsp\":%" PRIu64 ",\"exit_depth\":%u,\"returned\":%u,\"steps\":%" PRIu64 ",\"call_depth\":%u,",r.exit_requested,r.exit_code,r.exit_pc,r.exit_rsp,r.exit_depth,r.result.returned,r.result.steps,r.result.call_depth);
    printf("\"fault\":{\"status\":%u,\"pc\":%" PRIu64 ",\"address\":%" PRIu64 ",\"width\":%" PRIu64 ",\"access\":%u},",r.result.fault.status,r.result.fault.pc,r.result.fault.address,r.result.fault.width,r.result.fault.access);
    printf("\"rax\":%" PRIu64 ",\"rsp\":%" PRIu64 ",\"rip\":%" PRIu64 ",\"d3d_cleanup_result\":%u,\"d3d_before_cleanup\":",aot_get_register(r.state,AOT_RAX),aot_get_register(r.state,AOT_RSP),aot_get_register(r.state,AOT_RIP),r.cleanup);print_d3d(&r.before);printf(",\"d3d_after_cleanup\":");print_d3d(&r.after);
    printf(",\"callback_stats\":{\"calls\":%" PRIu64 ",\"returns\":%" PRIu64 ",\"rejections\":%" PRIu64 ",\"depth\":%u,\"max_depth\":%u,\"end_status\":%u},\"user32_stats\":",r.callbacks.calls,r.callbacks.returns,r.callbacks.rejections,r.callbacks.depth,r.callbacks.max_depth,r.callback_end);print_user(&r.user32);
    printf(",\"user32_end_status\":%u,\"host_before_finish\":",r.user32_end);print_host(&before_finish);printf(",\"host_after_finish\":");print_host(&after_finish);
    printf(",\"files\":{\"last_error\":%u,\"open_before_cleanup\":%u,\"open_after_cleanup\":%u,\"cleanup_closes\":%u,\"cleanup_errors\":%u,\"bytes_read\":%" PRIu64 ",\"bytes_written\":%" PRIu64 ",\"api_calls_4_to_9\":[",r.last_error,r.open_before,r.open_after,r.cleanup_closes,r.cleanup_errors,r.bytes_read,r.bytes_written);for(unsigned i=0;i<6;i++)printf("%s%" PRIu64,i?",":"",r.file_calls[i]);printf("]},\"test_queue\":{\"requested\":%zu,\"posted\":%zu,\"injection_error\":%d,\"observed_hwnd\":%" PRIuFAST64 ",\"events\":[",event_count,posted,inject_error,atomic_load(&observed_hwnd));
    for(size_t i=0;i<posted;i++)printf("%s{\"name\":\"%s\",\"origin\":%u,\"wait_count\":%" PRIu64 "}",i?",":"",events[i].name,WB_ORIGIN_TEST_QUEUE,posted_waits[i]);printf("]},\"observations\":{");
    for(size_t i=0;i<kObservationCount;i++){const NativeObservation*o=&kObservations[i];if(o->rva>sizeof kImageBytes||o->size>sizeof kImageBytes-o->rva)abort();printf("%s\"%s\":\"",i?",":"",o->name);if(r.image)for(uint32_t j=0;j<o->size;j++)printf("%02x",r.image[o->rva+j]);printf("\"");}printf("},\"saved_file\":");print_file(r.directory);
#ifdef AOT_WINDOW_SWITCH_V1
    printf(",\"switch_commits\":%" PRIu64,aot_window_switch_commits(r.ctx));
#endif
    printf("}\n");
    aot_context_destroy(r.ctx);aot_state_destroy(r.state);free(r.image);free(r.stack);free(r.proxies);free(r.map);free(r.scratch);free(r.thunks);free(r.thunk_permissions);return host_status;
}
