/* Independent ARM64 process host. No Python, Rosetta or Windows DLL at runtime.
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

static const uint64_t STACK_BASE=UINT64_C(0x70000000),EXIT_PC=UINT64_C(0x7fff00000000);
enum { STACK_SIZE=65536 };
static int host_error(const char *message) {
    /* All messages are fixed program literals, not unescaped CLI values. */
    printf("{\"outcome\":\"HOST_ERROR\",\"error\":\"%s\"}\n",message);return 64;
}
static int number(const char *text,uint64_t *value) {
    if(!text || !*text || *text=='-' || *text=='+' || *text==' ' || *text=='\t')return 0;
    char *end=NULL;errno=0;unsigned long long n=strtoull(text,&end,0);
    if(errno || !end || *end)return 0;
    *value=(uint64_t)n;return 1;
}
static void put64(uint8_t *data,uint64_t value) {
    for(unsigned i=0;i<8;i++)data[i]=(uint8_t)(value>>(i*8));
}
int main(int argc,char **argv) {
    const char *directory=NULL;uint64_t base=kPreferredBase,budget=UINT64_C(1000000);
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--data-dir") && i+1<argc && !directory)directory=argv[++i];
        else if(!strcmp(argv[i],"--base") && i+1<argc) {
            if(!number(argv[++i],&base))return host_error("invalid image base");
        } else if(!strcmp(argv[i],"--budget") && i+1<argc) {
            if(!number(argv[++i],&budget) || !budget)return host_error("invalid instruction budget");
        } else return host_error("usage: --data-dir directory [--base address] [--budget instructions]");
    }
    if(!directory)return host_error("data directory is required");
    if((base&65535) || base>UINT64_MAX-sizeof kImageBytes || (base!=kPreferredBase && !kCanRebase))
        return host_error("unsupported image base");
    for(size_t i=0;i<kThunkCount;i++)if(base>UINT64_MAX-kThunks[i]-4096)
        return host_error("import address overflow");
    uint8_t *image=malloc(sizeof kImageBytes),*stack=calloc(1,STACK_SIZE);
    uint8_t *thunks=kThunkCount?calloc(kThunkCount,4096):NULL;
    AotState *state=aot_state_create();AotContext *ctx=NULL;
    if(!image || !stack || (kThunkCount && !thunks) || !state) {
        free(image);free(stack);free(thunks);aot_state_destroy(state);return host_error("allocation failed");
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
     * supplies stack/PC; static PE data carries the program's filename/payload. */
    aot_set_register(state,AOT_RSP,rsp);
    uint8_t stack_permissions[STACK_SIZE/4096];memset(stack_permissions,GM_READ|GM_WRITE,sizeof stack_permissions);
    uint8_t thunk_permission=GM_READ|AOT_EXEC;
    ctx=aot_context_create(base,kInstructions,kInstructionCount,budget,EXIT_PC,rsp);
    uint32_t setup=ctx?AOT_OK:AOT_INVALID;
    GuestMemory mapped={base,sizeof kImageBytes,image,kImagePermissions,sizeof kImagePermissions};
    if(!setup)setup=aot_add_region(ctx,&mapped);
    GuestMemory guest_stack={STACK_BASE,STACK_SIZE,stack,stack_permissions,sizeof stack_permissions};
    if(!setup)setup=aot_add_region(ctx,&guest_stack);
    for(size_t i=0;i<kThunkCount && !setup;i++) {
        thunks[4096*i]=0xc3;
        GuestMemory thunk={base+kThunks[i],4096,thunks+4096*i,&thunk_permission,1};
        setup=aot_add_region(ctx,&thunk);
    }
    uint32_t session_error=setup?87:aot_file_session_begin(directory);
    if(session_error) {
        aot_context_destroy(ctx);aot_state_destroy(state);free(image);free(stack);free(thunks);
        printf("{\"outcome\":\"HOST_ERROR\",\"session_error\":%u,\"setup_status\":%u}\n",session_error,setup);return 64;
    }
    uint32_t status=aot_execute(aot_entry,state,ctx,base+kEntryRva);
    AotResult result;memset(&result,0,sizeof result);aot_result(ctx,&result);
    uint32_t open_before=aot_file_open_handles();uint32_t cleanup=aot_file_session_end();
    uint32_t open_after=aot_file_open_handles(),cleanup_errors=aot_file_cleanup_errors();
    uint32_t requested=aot_process_exit_requested(),exit_code=aot_process_exit_code();
    const char *outcome=status==AOT_PROCESS_EXITED?"PROCESS_EXITED":status==AOT_OK?"FUNCTION_RETURN":"FAULT";
    printf("{\"outcome\":\"%s\",\"aot_status\":%u,\"pe_sha256\":\"%s\","
           "\"image_base\":%" PRIu64 ",\"entry_rva\":%u,\"entry_arguments\":0,"
           "\"exit_requested\":%u,\"exit_code\":%u,\"exit_pc\":%" PRIu64 ","
           "\"exit_rsp\":%" PRIu64 ",\"exit_depth\":%u,\"returned\":%u,"
           "\"steps\":%" PRIu64 ",\"call_depth\":%u,"
           "\"fault\":{\"status\":%u,\"pc\":%" PRIu64 ",\"address\":%" PRIu64 ",\"width\":%" PRIu64 ",\"access\":%u},"
           "\"rax\":%" PRIu64 ",\"rsp\":%" PRIu64 ",\"rip\":%" PRIu64 ","
           "\"api_calls\":%" PRIu64 ",\"last_error\":%u,\"bytes_read\":%" PRIu64 ",\"bytes_written\":%" PRIu64 ","
           "\"open_before_cleanup\":%u,\"open_after_cleanup\":%u,\"cleanup_closes\":%u,\"cleanup_errors\":%u,\"call_counts\":{",
           outcome,status,kPeSha256,base,kEntryRva,requested,exit_code,aot_process_exit_pc(),aot_process_exit_rsp(),
           aot_process_exit_depth(),result.returned,result.steps,result.call_depth,result.fault.status,result.fault.pc,
           result.fault.address,result.fault.width,result.fault.access,aot_get_register(state,AOT_RAX),
           aot_get_register(state,AOT_RSP),aot_get_register(state,AOT_RIP),aot_bridge_api_calls(),aot_file_last_error(),
           aot_file_bytes_read(),aot_file_bytes_written(),open_before,open_after,cleanup,cleanup_errors);
    for(unsigned signature=4;signature<=9;signature++)printf("%s\"%u\":%" PRIu64,signature==4?"":",",signature,aot_file_api_calls(signature));
    printf("},\"observations\":{");
    for(size_t i=0;i<kObservationCount;i++) {
        const NativeObservation *o=&kObservations[i];
        if(o->rva>sizeof kImageBytes || o->size>sizeof kImageBytes-o->rva)abort();
        printf("%s\"%s\":\"",i?",":"",o->name);
        for(size_t n=0;n<o->size;n++)printf("%02x",image[o->rva+n]);
        printf("\"");
    }
    printf("}}\n");
    aot_context_destroy(ctx);aot_state_destroy(state);free(image);free(stack);free(thunks);
    if(open_after || cleanup_errors)return 3;
    return status==AOT_PROCESS_EXITED?0:status==AOT_OK?2:3;
}
