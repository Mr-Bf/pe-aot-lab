/* Diagnostic-only bounded replay. No clock, substitute API or retained
 * dereferenceable State/Context pointer. All live access descends from the
 * actual helper arguments. TLS owns only numeric counters and file handles. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef AOT_WINDOW_SWITCH_V1
#error The observation contract requires the fixed switch window profile
#endif
static _Thread_local int oa_directory=-1,oa_events=-1;
static _Thread_local uint64_t oa_sequence,oa_thread;
static _Thread_local unsigned oa_active,oa_event_index,oa_message,oa_seen;
static _Thread_local unsigned oa_nested,oa_rets,oa_callbacks;
static _Thread_local int oa_attempt;
static _Thread_local uint64_t oa_diagnostic_calls,oa_continuation_calls,oa_total_guest_steps,oa_total_switch_commits,oa_reset_count;

static void oa_fail(const char *reason) {
    fprintf(stderr,"OUTER_REPLAY_DIAGNOSTIC_FAILURE: %s\n",reason);_Exit(65);
}
static void oa_write(int fd,const void *data,size_t size) {
    const uint8_t *p=data;
    while(size){ssize_t n=write(fd,p,size);if(n<0&&errno==EINTR)continue;
        if(n<=0)oa_fail("write failed");p+=(size_t)n;size-=(size_t)n;}
}
static void oa_printf(int fd,const char *format,...) {
    char buffer[8192];va_list ap;va_start(ap,format);
    int n=vsnprintf(buffer,sizeof buffer,format,ap);va_end(ap);
    if(n<0||(size_t)n>=sizeof buffer)oa_fail("JSON buffer overflow");oa_write(fd,buffer,(size_t)n);
}
static int oa_open(const char *name) {
    int fd=openat(oa_directory,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)oa_fail("exclusive output creation failed");return fd;
}
static void oa_close(int fd){if(close(fd))oa_fail("output close failed");}
static void oa_layout(void) {
    int fd=oa_open("layout.json");
    oa_printf(fd,"{\"schema\":1,\"contract\":\"outer-abi-replay-v1\",\"diagnostics_per_event\":2,\"msg_fixed_hex\":\"7856341264000000c8000000\",\"byte_order\":\"little\",\"pointer_size\":%zu,\"sizes\":{",sizeof(void*));
#define SZ(name,type) oa_printf(fd,"\"" name "\":%zu,",sizeof(type))
    SZ("state",AotState);SZ("context",AotContext);SZ("instruction",AotInstruction);
    SZ("guest_memory",GuestMemory);SZ("return_frame",ReturnFrame);
    SZ("d3d_session",D3DSession);SZ("user32_session",User32Session);SZ("callback_session",WindowCallbackSession);
    SZ("callback_boundary",WindowCallbackBoundary);SZ("result",AotResult);SZ("fault",AotFault);
#undef SZ
    oa_printf(fd,"\"access_plan\":%zu},\"offsets\":{",sizeof(AccessPlan));
#define OFF(name,type,field) oa_printf(fd,"\"" name "\":%zu,",offsetof(type,field))
#define CTX(field) OFF("ctx." #field,AotContext,field)
    CTX(module_base);CTX(budget);CTX(exit_pc);CTX(initial_rsp);CTX(instructions);CTX(instruction_count);CTX(region_count);
    CTX(regions);CTX(result);CTX(result.fault);CTX(result.fault.status);CTX(result.fault.access);CTX(result.fault.pc);
    CTX(result.fault.address);CTX(result.fault.width);CTX(result.steps);CTX(result.call_depth);CTX(result.returned);
    CTX(current_pc);CTX(current);CTX(in_instruction);CTX(pending_size);CTX(pending);CTX(pending_value);CTX(frames);
    CTX(snapshot);CTX(d3d_binding_valid);CTX(d3d_object_index);CTX(d3d_signature);CTX(d3d_binding_pc);CTX(d3d_binding_target);
    CTX(import_binding_valid);CTX(import_signature);CTX(import_binding_pc);CTX(import_binding_target);CTX(d3d_map_permissions);
    CTX(switch_pc);CTX(switch_targets);CTX(switch_count);CTX(switch_bound);CTX(switch_binding_attempted);CTX(switch_commits);
#undef CTX
    OFF("region.base",GuestMemory,base);OFF("region.size",GuestMemory,size);OFF("region.bytes",GuestMemory,bytes);
    OFF("region.permissions",GuestMemory,permissions);OFF("region.page_count",GuestMemory,page_count);
    OFF("frame.pc",ReturnFrame,pc);OFF("frame.rsp",ReturnFrame,rsp);
    OFF("session.running",D3DSession,running);OFF("session.used",D3DSession,used);
    OFF("session.context_identity",D3DSession,context_identity);OFF("session.state_identity",D3DSession,state_identity);
    OFF("session.exit_requested",D3DSession,exit_requested);OFF("session.stats",D3DSession,stats);
    OFF("user32.owner",User32Session,owner);OFF("user32.stats",User32Session,stats);
    OFF("user32.stats.api_calls",User32Session,stats.api_calls);OFF("user32.stats.callbacks",User32Session,stats.callbacks);
    OFF("user32.stats.posted_dispatches",User32Session,stats.posted_dispatches);
    OFF("callback.owner",WindowCallbackSession,owner);OFF("callback.stats",WindowCallbackSession,stats);
    OFF("callback.stats.calls",WindowCallbackSession,stats.calls);OFF("callback.stats.returns",WindowCallbackSession,stats.returns);
    OFF("callback.stats.rejections",WindowCallbackSession,stats.rejections);OFF("callback.stats.depth",WindowCallbackSession,stats.depth);
    OFF("callback.stats.max_depth",WindowCallbackSession,stats.max_depth);
    OFF("boundary.state",WindowCallbackBoundary,state);OFF("boundary.snapshot",WindowCallbackBoundary,snapshot);
    OFF("boundary.frames",WindowCallbackBoundary,frames);
#undef OFF
    static const char *names[]={"RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI","R8","R9","R10","R11","R12","R13","R14","R15","RIP"};
    for(unsigned i=0;i<17;i++)oa_printf(fd,"\"state.%s\":%u,",names[i],(unsigned)reg_offsets[i]);
    oa_printf(fd,"\"state.DF\":2075},\"max_regions\":%u,\"max_calls\":%u,\"fixed_dispatch_call_rva\":5839,\"fixed_dispatch_target_rva\":4027408384,\"fixed_defproc_call_rva\":4248,\"fixed_defproc_target_rva\":4027400192,\"msg_rva\":12688,\"state_rva\":12288,\"result_rva\":12480}\n",AOT_MAX_REGIONS,AOT_MAX_CALLS);
    oa_close(fd);
}
static void oa_init(void) {
    if(oa_directory>=0)return;
    const char *directory=getenv("PE_AOT_OUTER_REPLAY_OUTPUT");
    if(!directory||directory[0]!='/')oa_fail("absolute PE_AOT_OUTER_REPLAY_OUTPUT required");
    oa_directory=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(oa_directory<0)oa_fail("output directory open failed");
    if(pthread_threadid_np(NULL,&oa_thread))oa_fail("thread identity unavailable");
    oa_events=oa_open("events.jsonl");oa_layout();
}
static void oa_owner(AotState *s,AotContext *ctx) {
    uint64_t tid=0;if(pthread_threadid_np(NULL,&tid))oa_fail("thread observation failed");
    if(!s||!ctx||!session.running||!session.used||session.context_identity!=(uintptr_t)ctx||
       session.state_identity!=(uintptr_t)s||window_callbacks.owner!=(uintptr_t)ctx||
       !window_callbacks.configured||!user32.configured||user32.owner!=(uintptr_t)ctx||tid!=oa_thread)
        oa_fail("live owner identity mismatch");
}
static bool oa_read(AotContext *ctx,uint64_t address,uint8_t *out,size_t count) {
    if(count>UINT64_MAX-address||ctx->region_count>AOT_MAX_REGIONS)return false;
    for(size_t i=0;i<count;i++){
        const GuestMemory *found=NULL;uint64_t a=address+i;
        for(size_t j=0;j<ctx->region_count;j++){const GuestMemory *r=&ctx->regions[j];
            if(a>=r->base&&a-r->base<r->size){found=r;break;}}
        if(!found||!gm_valid(found)||!(found->permissions[(size_t)(a-found->base)/GM_PAGE]&GM_READ))return false;
        out[i]=found->bytes[(size_t)(a-found->base)];
    }return true;
}
static uint32_t oa_signature(AotState *s,AotContext *ctx,uint64_t pc) {
    if(!s||!ctx||!session.running||session.context_identity!=(uintptr_t)ctx||session.state_identity!=(uintptr_t)s||
       !ctx->current||ctx->in_instruction||!ctx->result.call_depth||aot_get_register(s,AOT_RIP)!=pc)return 0;
    if(ctx->current->kind==AOT_REGISTER_CALL&&ctx->import_binding_valid&&
       ctx->import_binding_pc==ctx->module_base+ctx->current->rva&&ctx->import_binding_target==pc)
        return ctx->import_signature;
    if(ctx->current->kind==AOT_CALL)
        for(size_t i=0;i<AOT_IMPORT_CALL_COUNT;i++)
            if(aot_import_calls[i].call_rva==ctx->current->rva&&
               pc==ctx->module_base+aot_import_calls[i].target_rva)return aot_import_calls[i].signature;
    return 0;
}
static void oa_snapshot(const char *name,AotState *s,AotContext *ctx) {
    if(ctx->region_count>AOT_MAX_REGIONS||ctx->instruction_count>1048576)oa_fail("snapshot bounds");
    int fd=oa_open(name);const char magic[8]={'A','O','T','A','B','I','1',0};
    uint64_t header[8]={1,sizeof *s,sizeof *ctx,ctx->region_count,ctx->instruction_count,
                       sizeof session,sizeof user32,sizeof window_callbacks};
    oa_write(fd,magic,sizeof magic);oa_write(fd,header,sizeof header);
    oa_write(fd,s,sizeof *s);oa_write(fd,ctx,sizeof *ctx);
    oa_write(fd,ctx->instructions,ctx->instruction_count*sizeof *ctx->instructions);
    oa_write(fd,&session,sizeof session);oa_write(fd,&user32,sizeof user32);oa_write(fd,&window_callbacks,sizeof window_callbacks);
    for(size_t i=0;i<ctx->region_count;i++){
        const GuestMemory *r=&ctx->regions[i];if(!gm_valid(r)||r->size>32*1024*1024)oa_fail("snapshot region invalid");
        uint64_t info[3]={r->base,r->size,r->page_count};oa_write(fd,info,sizeof info);
        oa_write(fd,r->bytes,r->size);oa_write(fd,r->permissions,r->page_count);
    }oa_close(fd);
}
static void oa_record(const char *type,AotState *s,AotContext *ctx,uint64_t pc,uint32_t signature,bool snapshot) {
    oa_owner(s,ctx);char name[96];name[0]=0;
    if(snapshot){int n=snprintf(name,sizeof name,"event-%u-attempt-%d-%s.bin",oa_event_index,oa_attempt,type);
        if(n<0||(size_t)n>=sizeof name)oa_fail("snapshot name overflow");oa_snapshot(name,s,ctx);}
    oa_printf(oa_events,"{\"attempt\":%d,\"role\":\"%s\",\"diagnostic_calls\":%" PRIu64 ",\"continuation_calls\":%" PRIu64 ",\"total_guest_steps\":%" PRIu64 ",\"total_switch_commits\":%" PRIu64 ",\"reset_count\":%" PRIu64 ",",
        oa_attempt,oa_attempt<0?"original":oa_attempt<2?"diagnostic":"continuation",oa_diagnostic_calls,oa_continuation_calls,oa_total_guest_steps,oa_total_switch_commits,oa_reset_count);
    oa_printf(oa_events,"\"seq\":%" PRIu64 ",\"index\":%u,\"type\":\"%s\",\"signature\":%u,\"message\":%u,\"pc\":%" PRIu64 ",\"call_rva\":%u,\"rip\":%" PRIu64 ",\"rsp\":%" PRIu64 ",\"rax\":%" PRIu64 ",\"steps\":%" PRIu64 ",\"depth\":%u,\"fault\":%u,\"returned\":%u,\"switch_commits\":%" PRIu64 ",\"state_address\":%" PRIuPTR ",\"context_address\":%" PRIuPTR ",\"owner_state\":%" PRIuPTR ",\"owner_context\":%" PRIuPTR ",\"thread_id\":%" PRIu64 ",\"callback_calls\":%" PRIu64 ",\"callback_returns\":%" PRIu64 ",\"callback_rejections\":%" PRIu64 ",\"callback_depth\":%u,\"user32_callbacks\":%" PRIu64 ",\"posted_dispatches\":%" PRIu64 ",\"last_error\":%u,\"file_bytes_read\":%" PRIu64 ",\"file_bytes_written\":%" PRIu64 ",\"snapshot\":\"%s\",\"api_calls\":[",
        oa_sequence++,oa_event_index,type,signature,oa_message,pc,ctx->current?ctx->current->rva:UINT32_MAX,
        aot_get_register(s,AOT_RIP),aot_get_register(s,AOT_RSP),aot_get_register(s,AOT_RAX),ctx->result.steps,
        ctx->result.call_depth,ctx->result.fault.status,ctx->result.returned,ctx->switch_commits,
        (uintptr_t)s,(uintptr_t)ctx,session.state_identity,session.context_identity,oa_thread,
        window_callbacks.stats.calls,window_callbacks.stats.returns,window_callbacks.stats.rejections,window_callbacks.stats.depth,
        user32.stats.callbacks,user32.stats.posted_dispatches,wfile_get_last_error(),wfile_session.bytes_read,wfile_session.bytes_written,name);
    for(unsigned i=0;i<14;i++)oa_printf(oa_events,"%s%" PRIu64,i?",":"",user32.stats.api_calls[i]);
    oa_printf(oa_events,"],\"file_api_calls\":[");for(unsigned i=0;i<9;i++)oa_printf(oa_events,"%s%" PRIu64,i?",":"",wfile_session.api_calls[i]);
    oa_printf(oa_events,"]}\n");
}
/* This object owns copies only. Pointer values inside the Context/session
 * copies are compared as identity evidence; live memory is reached exclusively
 * through the actual helper arguments after the descriptor checks below. */
typedef struct {
    AotState state;
    AotContext context;
    D3DSession d3d;
    User32Session user;
    WindowCallbackSession callback;
    FileSession file;
    uint64_t next_file_handle;
    uint32_t files_ready;
    uint8_t *instructions,*bytes[AOT_MAX_REGIONS],*permissions[AOT_MAX_REGIONS];
} OuterReplayCapture;
static uint64_t oa_add(uint64_t value,uint64_t delta) {
    if(delta>UINT64_MAX-value)oa_fail("cumulative counter overflow");return value+delta;
}
static uint8_t *oa_copy(const void *source,size_t size) {
    if(!source||!size)oa_fail("empty replay allocation");
    uint8_t *copy=malloc(size);if(!copy)oa_fail("replay allocation failed");
    memcpy(copy,source,size);return copy;
}
static void oa_capture(OuterReplayCapture *saved,AotState *s,AotContext *ctx) {
    oa_owner(s,ctx);
    if(ctx->region_count!=6||!ctx->instruction_count||ctx->instruction_count>1048576||
       !ctx->instructions||window_callbacks.stats.depth||ctx->result.fault.status||
       ctx->result.returned||session.exit_requested)oa_fail("replay capture boundary invalid");
    memset(saved,0,sizeof *saved);
    memcpy(&saved->state,s,sizeof *s);memcpy(&saved->context,ctx,sizeof *ctx);
    memcpy(&saved->d3d,&session,sizeof session);memcpy(&saved->user,&user32,sizeof user32);
    memcpy(&saved->callback,&window_callbacks,sizeof window_callbacks);
    memcpy(&saved->file,&wfile_session,sizeof wfile_session);
    saved->next_file_handle=wfile_next_handle;saved->files_ready=window_files_ready;
    saved->instructions=oa_copy(ctx->instructions,ctx->instruction_count*sizeof *ctx->instructions);
    for(size_t i=0;i<ctx->region_count;i++) {
        const GuestMemory *r=&ctx->regions[i];
        if(!gm_valid(r)||r->size>32*1024*1024||!r->page_count)oa_fail("replay backing invalid");
        saved->bytes[i]=oa_copy(r->bytes,r->size);
        saved->permissions[i]=oa_copy(r->permissions,r->page_count);
    }
}
static void oa_host_unchanged_except_calls(const OuterReplayCapture *saved,unsigned completed,unsigned index) {
    /* No host object is restored: only these documented counters may advance.
     * Comparing complete copied TLS structs also covers padding and all owner,
     * handle, lifecycle, map, frame and LastError fields. */
    User32Session expected_user;WindowCallbackSession expected_callback;
    memcpy(&expected_user,&saved->user,sizeof expected_user);
    memcpy(&expected_callback,&saved->callback,sizeof expected_callback);
    expected_user.stats.api_calls[5]=oa_add(expected_user.stats.api_calls[5],completed);
    expected_user.stats.api_calls[3]=oa_add(expected_user.stats.api_calls[3],index*completed);
    expected_user.stats.callbacks=oa_add(expected_user.stats.callbacks,completed);
    expected_user.stats.posted_dispatches=oa_add(expected_user.stats.posted_dispatches,completed);
    expected_callback.stats.calls=oa_add(expected_callback.stats.calls,completed);
    expected_callback.stats.returns=oa_add(expected_callback.stats.returns,completed);
    if(completed&&expected_callback.stats.max_depth<1)expected_callback.stats.max_depth=1;
    if(memcmp(&session,&saved->d3d,sizeof session)||memcmp(&wfile_session,&saved->file,sizeof wfile_session)||
       wfile_next_handle!=saved->next_file_handle||window_files_ready!=saved->files_ready||
       memcmp(&user32,&expected_user,sizeof user32)||
       memcmp(&window_callbacks,&expected_callback,sizeof window_callbacks))
        oa_fail("host lifecycle, file state or unexpected TLS field changed; reset forbidden");
}
static void oa_storage_unchanged(const OuterReplayCapture *saved,AotState *s,AotContext *ctx) {
    oa_owner(s,ctx);
    if(ctx->result.fault.status||ctx->result.returned||session.exit_requested||ctx->in_instruction||ctx->pending_size)
        oa_fail("terminal guest or process state; reset forbidden");
    /* Validate identities BEFORE dereferencing live storage or restoring
     * Context: replacing Context first could conceal an illicit mapping change. */
    if(ctx->region_count!=saved->context.region_count||
       memcmp(ctx->regions,saved->context.regions,sizeof ctx->regions)||
       ctx->instructions!=saved->context.instructions||ctx->instruction_count!=saved->context.instruction_count||
       ctx->d3d_map_permissions!=saved->context.d3d_map_permissions||
       ctx->module_base!=saved->context.module_base||ctx->budget!=saved->context.budget||
       ctx->exit_pc!=saved->context.exit_pc||ctx->initial_rsp!=saved->context.initial_rsp)
        oa_fail("guest descriptor or instruction identity changed; reset forbidden");
    if(memcmp(ctx->instructions,saved->instructions,ctx->instruction_count*sizeof *ctx->instructions))
        oa_fail("instruction table content changed; reset forbidden");
    for(size_t i=0;i<ctx->region_count;i++) {
        const GuestMemory *r=&ctx->regions[i];
        if(memcmp(r->permissions,saved->permissions[i],r->page_count))
            oa_fail("permission content changed; reset forbidden");
    }
}
static void oa_restore(const OuterReplayCapture *saved,AotState *s,AotContext *ctx,unsigned completed,unsigned index) {
    oa_storage_unchanged(saved,s,ctx);oa_host_unchanged_except_calls(saved,completed,index);
    /* Permissions are a verified no-op, including const image permissions.
     * Bytes belong to the six fixed host-owned CPU allocations in this profile;
     * the D3D map is a separate shadow, never shared native mapped storage. */
    for(size_t i=0;i<ctx->region_count;i++)memcpy(ctx->regions[i].bytes,saved->bytes[i],ctx->regions[i].size);
    memcpy(s,&saved->state,sizeof *s);memcpy(ctx,&saved->context,sizeof *ctx);
    oa_storage_unchanged(saved,s,ctx);oa_host_unchanged_except_calls(saved,completed,index);
    for(size_t i=0;i<ctx->region_count;i++)
        if(memcmp(ctx->regions[i].bytes,saved->bytes[i],ctx->regions[i].size))oa_fail("guest backing restore differs");
    if(memcmp(s,&saved->state,sizeof *s)||memcmp(ctx,&saved->context,sizeof *ctx))oa_fail("guest state restore differs");
    oa_reset_count=oa_add(oa_reset_count,1);
}
static void oa_normalize_msg(AotContext *ctx) {
    static const uint8_t fixed[12]={0x78,0x56,0x34,0x12,0x64,0,0,0,0xc8,0,0,0};
    if(ctx->module_base>UINT64_MAX-0x3190-44)oa_fail("MSG normalization overflow");
    uint64_t address=ctx->module_base+0x3190+32;
    for(size_t i=0;i<ctx->region_count;i++) {
        GuestMemory *r=&ctx->regions[i];
        if(address<r->base||address-r->base>r->size||r->size-(size_t)(address-r->base)<sizeof fixed)continue;
        size_t offset=(size_t)(address-r->base);
        if(!gm_valid(r))oa_fail("MSG normalization region invalid");
        for(size_t n=0;n<sizeof fixed;n++)
            if((r->permissions[(offset+n)/GM_PAGE]&(GM_READ|GM_WRITE))!=(GM_READ|GM_WRITE))
                oa_fail("MSG normalization permissions invalid");
        memcpy(r->bytes+offset,fixed,sizeof fixed);return;
    }
    oa_fail("MSG normalization backing absent");
}
static void oa_release_capture(OuterReplayCapture *saved) {
    free(saved->instructions);
    for(size_t i=0;i<saved->context.region_count;i++){free(saved->bytes[i]);free(saved->permissions[i]);}
}
static void aot_outer_observe_ret(void *state,uint64_t pc,void *opaque,uint32_t signature) {
    AotState *s=state;AotContext *ctx=opaque;
    if(oa_active){if(signature!=214&&signature!=212)oa_fail("unexpected observed RET signature");
        oa_record("ret-before",s,ctx,pc,signature,false);}
    aot_import_ret(state,pc,opaque);
    if(oa_active){oa_rets++;oa_record("ret-after",s,ctx,pc,signature,false);}
}
uint32_t aot_wndproc_invoke(AotState *s,AotContext *ctx,uint64_t target,
        uint64_t hwnd,uint32_t message,uint64_t wparam,uint64_t lparam,uint64_t *out) {
    if(!oa_active)return aot_outer_original_wndproc_invoke(s,ctx,target,hwnd,message,wparam,lparam,out);
    if(oa_callbacks||message!=oa_message||wparam!=0x27||target!=ctx->module_base+0x1000||hwnd!=user32.stats.hwnd)
        oa_fail("unexpected observed callback");
    oa_callbacks++;oa_record("callback-before",s,ctx,target,214,true);
    uint32_t status=aot_outer_original_wndproc_invoke(s,ctx,target,hwnd,message,wparam,lparam,out);
    oa_record("callback-after",s,ctx,target,214,true);
    if(status!=AOT_OK)oa_fail("observed callback did not return normally");return status;
}
void *__remill_function_call(void *state,uint64_t pc,void *opaque) {
    AotState *s=state;AotContext *ctx=opaque;uint32_t signature=oa_signature(s,ctx,pc);
    if(oa_active){
        if(signature!=212||oa_message!=0x101||oa_nested||!ctx->current||ctx->current->rva!=0x1098||
           pc!=ctx->module_base+UINT64_C(0xf00d4000))oa_fail("unexpected nested import");
        if(!ctx->result.call_depth||ctx->result.call_depth>AOT_MAX_CALLS)oa_fail("nested call depth invalid");
        uint32_t before_depth=ctx->result.call_depth;
        ReturnFrame expected=ctx->frames[before_depth-1];
        oa_nested++;oa_record("nested-before",s,ctx,pc,signature,false);
        void *result=aot_outer_original_function_call(state,pc,opaque);
        oa_owner(s,ctx);
        if(result!=opaque||ctx->result.fault.status||ctx->result.returned||session.exit_requested||
           ctx->in_instruction||ctx->pending_size||ctx->result.call_depth!=before_depth-1||
           aot_get_register(s,AOT_RIP)!=expected.pc||aot_get_register(s,AOT_RSP)!=expected.rsp||oa_rets!=1)
            oa_fail("nested import did not complete its real RET; reset forbidden");
        oa_record("nested-after",s,ctx,pc,signature,false);return result;
    }
    if(signature!=214)return aot_outer_original_function_call(state,pc,opaque);
    uint8_t msg[48];uint64_t address=aot_get_register(s,AOT_RCX);
    if(!oa_read(ctx,address,msg,sizeof msg))oa_fail("unreadable actual DispatchMessage MSG");
    uint32_t message=wui_u32(msg+8);uint64_t wp=wui_u64(msg+16);
    if(wp!=0x27||(message!=0x100&&message!=0x101))return aot_outer_original_function_call(state,pc,opaque);
    if(wui_u64(msg)!=user32.stats.hwnd||!wui_u64(msg)||
       wui_u64(msg+24)!=(message==0x100?UINT64_C(0x014d0001):UINT64_C(0xc14d0001)))
        oa_fail("selected MSG handle or nonrepeat key bits differ");
    if(ctx->current->kind!=AOT_REGISTER_CALL||ctx->current->rva!=0x16cf||
       pc!=ctx->module_base+UINT64_C(0xf00d6000)||address!=ctx->module_base+0x3190||
       ctx->pending_size||ctx->in_instruction||ctx->result.fault.status||ctx->result.returned) {
        oa_printf(STDERR_FILENO,"{\"diagnostic_failure\":\"selected_dispatch_boundary\",\"kind\":%u,\"current_rva\":%u,\"pc\":%" PRIu64 ",\"module_base\":%" PRIu64 ",\"rcx\":%" PRIu64 ",\"pending_size\":%u,\"in_instruction\":%u,\"fault\":%u,\"returned\":%u,\"import_binding_valid\":%u,\"import_binding_pc\":%" PRIu64 ",\"import_binding_target\":%" PRIu64 ",\"import_signature\":%u}\n",
            (unsigned)ctx->current->kind,ctx->current->rva,pc,ctx->module_base,address,
            ctx->pending_size,ctx->in_instruction,ctx->result.fault.status,ctx->result.returned,
            ctx->import_binding_valid,ctx->import_binding_pc,ctx->import_binding_target,ctx->import_signature);
        oa_fail("selected dispatch boundary differs from fixed PE");
    }
    unsigned imports=0,registers=0;
    for(size_t i=0;i<AOT_IMPORT_TARGET_COUNT;i++)if(aot_import_targets[i].signature==214){
        if(aot_import_targets[i].target_rva!=0xf00d6000)oa_fail("unexpected dispatch target metadata");imports++;}
    for(size_t i=0;i<AOT_REGISTER_CALL_COUNT;i++)if(aot_register_calls[i].call_rva==0x16cf){
        if(aot_register_calls[i].operand_register!=AOT_R12)oa_fail("unexpected dispatch register metadata");registers++;}
    if(imports!=1||registers!=1||window_callbacks.count!=1||window_callbacks.entries[0].rva!=0x1000||
       window_callbacks.entries[0].signature!=AOT_WINDOW_WNDPROC)oa_fail("fixed profile metadata mismatch");
    unsigned index=message==0x100?0:1;
    if(oa_seen!=index)oa_fail("RIGHT then RIGHT-UP exactly once required");
    oa_init();oa_owner(s,ctx);oa_event_index=index;oa_message=message;oa_attempt=-1;
    OuterReplayCapture saved;oa_capture(&saved,s,ctx);
    oa_record("original-capture",s,ctx,pc,214,true);
    void *result=NULL;
    for(int attempt=0;attempt<3;attempt++) {
        if(attempt)oa_restore(&saved,s,ctx,(unsigned)attempt,index);
        if(attempt<2)oa_normalize_msg(ctx);
        oa_attempt=attempt;oa_active=1;oa_nested=oa_rets=oa_callbacks=0;
        oa_record("outer-before",s,ctx,pc,214,true);
        result=aot_outer_original_function_call(state,pc,opaque);
        /* A failed real call is terminal. In particular, never clear a latch
         * or overwrite a failing Context in order to reach the next pass. */
        if(result!=opaque||ctx->result.fault.status||ctx->result.returned||session.exit_requested||
           oa_callbacks!=1||oa_nested!=index||oa_rets!=index+1||ctx->result.steps<=saved.context.result.steps||
           ctx->switch_commits<saved.context.switch_commits)
            oa_fail("incomplete actual import/callback/RET chain; reset forbidden");
        oa_storage_unchanged(&saved,s,ctx);oa_host_unchanged_except_calls(&saved,(unsigned)attempt+1,index);
        oa_total_guest_steps=oa_add(oa_total_guest_steps,ctx->result.steps-saved.context.result.steps);
        oa_total_switch_commits=oa_add(oa_total_switch_commits,ctx->switch_commits-saved.context.switch_commits);
        if(attempt<2)oa_diagnostic_calls=oa_add(oa_diagnostic_calls,1);
        else oa_continuation_calls=oa_add(oa_continuation_calls,1);
        oa_record("outer-after",s,ctx,pc,214,true);oa_active=0;
    }
    oa_release_capture(&saved);oa_seen++;
    if(oa_seen==2){oa_close(oa_events);oa_close(oa_directory);oa_events=oa_directory=-1;}
    return result;
}
