/* Register-CALL integration host; no window or GPU acceptance.
 * Independent ARM64 process host. No Python, Rosetta or Windows DLL at runtime.
 * Generated image/metadata and host allocations are trusted. Guest accesses
 * still use checked addresses. CLI configuration is never a guest argument. */
#include "runtime.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native_image.h"
extern void *aot_entry(void *,uint64_t,void *);

static const uint64_t STACK_BASE=UINT64_C(0x70000000),EXIT_PC=UINT64_C(0x7fff00000000),PROXY_BASE=UINT64_C(0x60000000);
enum { STACK_SIZE=65536, PROXY_SIZE=8*4096, MAP_SIZE=1024*1024 };
static const uint64_t MAP_BASE=UINT64_C(0x61000000);
static int host_error(const char *message) {
    /* All messages are fixed program literals, not unescaped CLI values. */
    printf("{\"outcome\":\"HOST_ERROR\",\"error\":\"%s\"}\n",message);return 64;
}
static int number(const char *text,uint64_t *value) {
    if(!text || *text<'0' || *text>'9')return 0;
    char *end=NULL;errno=0;unsigned long long n=strtoull(text,&end,0);
    if(errno || !end || *end)return 0;
    *value=(uint64_t)n;return 1;
}
static void put64(uint8_t *data,uint64_t value) {
    for(unsigned i=0;i<8;i++)data[i]=(uint8_t)(value>>(i*8));
}
static void print_d3d_stats(const AotD3DStats *s) {
    printf("{");
    printf("\"create_device_calls\":%" PRIu64, s->create_device_calls);
    printf(",\"create_texture_calls\":%" PRIu64, s->create_texture_calls);
    printf(",\"create_rtv_calls\":%" PRIu64, s->create_rtv_calls);
    printf(",\"clear_calls\":%" PRIu64, s->clear_calls);
    printf(",\"copy_calls\":%" PRIu64, s->copy_calls);
    printf(",\"map_calls\":%" PRIu64, s->map_calls);
    printf(",\"unmap_calls\":%" PRIu64, s->unmap_calls);
    printf(",\"get_removed_calls\":%" PRIu64, s->get_removed_calls);
    printf(",\"release_calls\":%" PRIu64, s->release_calls);
    printf(",\"exit_calls\":%" PRIu64, s->exit_calls);
    printf(",\"this_checks\":%" PRIu64, s->this_checks);
    printf(",\"created\":%" PRIu64, s->created);
    printf(",\"guest_released\":%" PRIu64, s->guest_released);
    printf(",\"cleanup_releases\":%" PRIu64, s->cleanup_releases);
    printf(",\"cleanup_unmaps\":%" PRIu64, s->cleanup_unmaps);
    printf(",\"map_bytes_copied\":%" PRIu64, s->map_bytes_copied);
    printf(",\"map_postcall_failures\":%" PRIu64, s->map_postcall_failures);
    printf(",\"create_vs_calls\":%" PRIu64, s->create_vs_calls);
    printf(",\"create_ps_calls\":%" PRIu64, s->create_ps_calls);
    printf(",\"create_rasterizer_calls\":%" PRIu64, s->create_rasterizer_calls);
    printf(",\"om_set_calls\":%" PRIu64, s->om_set_calls);
    printf(",\"rs_set_calls\":%" PRIu64, s->rs_set_calls);
    printf(",\"viewport_calls\":%" PRIu64, s->viewport_calls);
    printf(",\"topology_calls\":%" PRIu64, s->topology_calls);
    printf(",\"vs_set_calls\":%" PRIu64, s->vs_set_calls);
    printf(",\"ps_set_calls\":%" PRIu64, s->ps_set_calls);
    printf(",\"draw_calls\":%" PRIu64, s->draw_calls);
    printf(",\"live_objects\":%u", s->live_objects);
    printf(",\"active_maps\":%u", s->active_maps);
    printf(",\"last_native_release\":%u", s->last_native_release);
    printf("}");
}
int main(int argc,char **argv) {
    uint64_t base=kPreferredBase,budget=UINT64_C(1000000);
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--base") && i+1<argc) {
            if(!number(argv[++i],&base))return host_error("invalid image base");
        } else if(!strcmp(argv[i],"--budget") && i+1<argc) {
            if(!number(argv[++i],&budget) || !budget)return host_error("invalid instruction budget");
        } else return host_error("usage: [--base address] [--budget instructions]");
    }
    if((base&65535) || base>UINT64_MAX-sizeof kImageBytes || (base!=kPreferredBase && !kCanRebase))
        return host_error("unsupported image base");
    for(size_t i=0;i<kThunkCount;i++)if(base>UINT64_MAX-kThunks[i]-4096)
        return host_error("import address overflow");
    if(!kThunkCount || kThunks[kThunkCount-1]<kThunks[0])abort();
    size_t thunk_size=(size_t)(kThunks[kThunkCount-1]-kThunks[0])+4096;
    if((thunk_size&4095) || thunk_size>4*1024*1024)abort();
    uint8_t *thunk_permissions=calloc(thunk_size/4096,1);
    uint8_t *image=malloc(sizeof kImageBytes),*stack=calloc(1,STACK_SIZE);
    uint8_t *proxies=calloc(1,PROXY_SIZE),*map_arena=calloc(1,MAP_SIZE);
    uint8_t *thunks=calloc(1,thunk_size);
    AotState *state=aot_state_create();AotContext *ctx=NULL;
    if(!image || !stack || !proxies || !map_arena || (!thunks || !thunk_permissions) || !state) {
        free(image);free(stack);free(thunks);free(thunk_permissions);free(proxies);free(map_arena);aot_state_destroy(state);return host_error("allocation failed");
    }
    memcpy(image,kImageBytes,sizeof kImageBytes);
    for(size_t i=0;i<kRelocationCount;i++) {
        const NativeRelocation *r=&kRelocations[i];
        if(r->rva>sizeof kImageBytes-8)abort(); /* generated trusted metadata invariant */
        put64(image+r->rva,r->value+base-kPreferredBase);
    }
    for(size_t i=0;i<kImportCount;i++) {
        if(kImports[i].iat_rva>sizeof kImageBytes-8)abort();
        put64(image+kImports[i].iat_rva,base+kImports[i].target_rva);
    }
    uint64_t rsp=STACK_BASE+STACK_SIZE-0x108;
    put64(stack+(size_t)(rsp-STACK_BASE),EXIT_PC);
    /* calloc-backed State has no guest business arguments. Only host startup
     * supplies stack/PC; static PE data carries the D3D11 contract observations. */
    aot_set_register(state,AOT_RSP,rsp);
    uint8_t stack_permissions[STACK_SIZE/4096];memset(stack_permissions,GM_READ|GM_WRITE,sizeof stack_permissions);
    ctx=aot_context_create(base,kInstructions,kInstructionCount,budget,EXIT_PC,rsp);
    uint32_t setup=ctx?AOT_OK:AOT_INVALID;
    GuestMemory mapped={base,sizeof kImageBytes,image,kImagePermissions,sizeof kImagePermissions};
    if(!setup)setup=aot_add_region(ctx,&mapped);
    GuestMemory guest_stack={STACK_BASE,STACK_SIZE,stack,stack_permissions,sizeof stack_permissions};
    if(!setup)setup=aot_add_region(ctx,&guest_stack);
    uint8_t proxy_permissions[8];memset(proxy_permissions,GM_READ,sizeof proxy_permissions);
    uint8_t map_permissions[MAP_SIZE/4096]={0};
    GuestMemory guest_proxies={PROXY_BASE,PROXY_SIZE,proxies,proxy_permissions,8};
    if(!setup)setup=aot_add_region(ctx,&guest_proxies);
    GuestMemory guest_map={MAP_BASE,MAP_SIZE,map_arena,map_permissions,MAP_SIZE/4096};
    if(!setup)setup=aot_add_region(ctx,&guest_map);
    AotD3DConfig config={0};
    config.proxy_base=PROXY_BASE;config.proxy_count=AOT_D3D_MAX_OBJECTS;
    config.map_base=MAP_BASE;config.map_capacity=MAP_SIZE;
    for(unsigned kind=0;kind<AOT_D3D_KIND_COUNT;kind++)config.vtable_va[kind]=PROXY_BASE+4096*(kind+1);
    for(unsigned method=0;method<AOT_D3D_METHOD_COUNT;method++)
        config.method_targets[method]=base+kD3DMethodThunks[method];
    /* Only registered methods have nonzero guest targets. No native address is
     * exposed. Interface+slot selects the runtime's typed method contract. */
    const unsigned methods[][3]={{0,2,AOT_D3D_RELEASE},{0,5,AOT_D3D_CREATE_TEXTURE},
        {0,9,AOT_D3D_CREATE_RTV},{0,39,AOT_D3D_GET_REMOVED},
        {1,2,AOT_D3D_RELEASE},{1,14,AOT_D3D_MAP},{1,15,AOT_D3D_UNMAP},
        {1,47,AOT_D3D_COPY},{1,50,AOT_D3D_CLEAR},
        {2,2,AOT_D3D_RELEASE},{3,2,AOT_D3D_RELEASE},
        {4,2,AOT_D3D_RELEASE},{5,2,AOT_D3D_RELEASE},{6,2,AOT_D3D_RELEASE},
        {0,12,AOT_D3D_CREATE_VS},{0,15,AOT_D3D_CREATE_PS},{0,22,AOT_D3D_CREATE_RASTER},
        {1,33,AOT_D3D_OM_SET},{1,43,AOT_D3D_RS_SET},{1,44,AOT_D3D_VIEWPORT},
        {1,24,AOT_D3D_TOPOLOGY},{1,11,AOT_D3D_VS_SET},{1,9,AOT_D3D_PS_SET},{1,13,AOT_D3D_DRAW}};
    for(size_t i=0;i<sizeof methods/sizeof methods[0];i++)
        put64(proxies+4096*(methods[i][0]+1)+8*methods[i][1],config.method_targets[methods[i][2]]);
    /* A single sparse region avoids one region per API. Only registered
     * thunk pages are R/X; unused pages remain inaccessible. The instruction
     * table and typed target checks still authorize only exact C3 addresses. */
    for(size_t i=0;i<kThunkCount;i++) {
        size_t offset=(size_t)(kThunks[i]-kThunks[0]);
        if((offset&4095) || offset>=thunk_size)abort();
        thunks[offset]=0xc3;thunk_permissions[offset/4096]=GM_READ|AOT_EXEC;
    }
    GuestMemory guest_thunks={base+kThunks[0],thunk_size,thunks,thunk_permissions,thunk_size/4096};
    if(!setup)setup=aot_add_region(ctx,&guest_thunks);
    uint32_t session_error=setup?AOT_INVALID:aot_d3d_session_begin(ctx,&config);
    if(session_error) {
        aot_context_destroy(ctx);aot_state_destroy(state);free(image);free(stack);free(thunks);free(thunk_permissions);free(proxies);free(map_arena);
        printf("{\"outcome\":\"HOST_ERROR\",\"session_error\":%u,\"setup_status\":%u}\n",session_error,setup);return 64;
    }
    if(aot_file_session_begin(kFileDirectory))return host_error("file session failed");
    uint32_t status=aot_execute(aot_entry,state,ctx,base+kEntryRva);
    AotResult result;memset(&result,0,sizeof result);aot_result(ctx,&result);
    AotD3DStats before_cleanup={0},after_cleanup={0};aot_d3d_stats(&before_cleanup);
    uint32_t cleanup=aot_d3d_session_end();aot_d3d_stats(&after_cleanup);
    uint32_t requested=aot_process_exit_requested(),exit_code=aot_process_exit_code();
    const char *outcome=status==AOT_PROCESS_EXITED?"PROCESS_EXITED":status==AOT_OK?"FUNCTION_RETURN":"FAULT";
    printf("{\"outcome\":\"%s\",\"aot_status\":%u,\"pe_sha256\":\"%s\","
           "\"image_base\":%" PRIu64 ",\"entry_rva\":%u,\"entry_arguments\":0,"
           "\"exit_requested\":%u,\"exit_code\":%u,\"exit_pc\":%" PRIu64 ","
           "\"exit_rsp\":%" PRIu64 ",\"exit_depth\":%u,\"returned\":%u,"
           "\"steps\":%" PRIu64 ",\"call_depth\":%u,"
           "\"fault\":{\"status\":%u,\"pc\":%" PRIu64 ",\"address\":%" PRIu64 ",\"width\":%" PRIu64 ",\"access\":%u},"
           "\"rax\":%" PRIu64 ",\"rsp\":%" PRIu64 ",\"rip\":%" PRIu64 ",\"d3d_cleanup_result\":%u,",
           outcome,status,kPeSha256,base,kEntryRva,requested,exit_code,aot_process_exit_pc(),aot_process_exit_rsp(),
           aot_process_exit_depth(),result.returned,result.steps,result.call_depth,result.fault.status,result.fault.pc,
           result.fault.address,result.fault.width,result.fault.access,aot_get_register(state,AOT_RAX),
           aot_get_register(state,AOT_RSP),aot_get_register(state,AOT_RIP),cleanup);
    printf("\"d3d_before_cleanup\":");print_d3d_stats(&before_cleanup);
    printf(",\"d3d_after_cleanup\":");print_d3d_stats(&after_cleanup);
    printf(",\"get_last_error_calls\":%" PRIu64 ",\"last_error\":%u,\"r14\":%" PRIu64,
           aot_file_api_calls(8),aot_file_last_error(),aot_get_register(state,AOT_R14));
    printf(",\"state_hex\":\"");for(size_t i=0;i<sizeof state->bytes;i++)printf("%02x",state->bytes[i]);printf("\"");
    printf(",\"stack_hex\":\"");for(size_t i=0;i<STACK_SIZE;i++)printf("%02x",stack[i]);printf("\"");
    uint64_t final_rsp=aot_get_register(state,AOT_RSP);
    printf(",\"below_rsp\":\"");
    if(final_rsp>=STACK_BASE+8 && final_rsp<=STACK_BASE+STACK_SIZE)
        for(size_t i=0;i<8;i++)printf("%02x",stack[(size_t)(final_rsp-STACK_BASE-8)+i]);
    printf("\"");aot_file_session_end();
    printf(",\"observations\":{");
    for(size_t i=0;i<kObservationCount;i++) {
        const NativeObservation *o=&kObservations[i];
        if(o->rva>sizeof kImageBytes || o->size>sizeof kImageBytes-o->rva)abort();
        printf("%s\"%s\":\"",i?",":"",o->name);
        for(size_t n=0;n<o->size;n++)printf("%02x",image[o->rva+n]);
        printf("\"");
    }
    printf("}}\n");
    aot_context_destroy(ctx);aot_state_destroy(state);free(image);free(stack);free(thunks);free(thunk_permissions);free(proxies);free(map_arena);
    if(after_cleanup.live_objects || after_cleanup.active_maps)return 3;
    return status==AOT_PROCESS_EXITED?0:status==AOT_OK?2:3;
}
