/* Execute the actual lifted WndProc object on the real transaction engine.
 * No Cocoa/App/COM/API backend is linked. All API paths reject explicitly.
 * Host initialization selects an input position in a copy of the real mapped
 * image; no PE, instruction, table, lifted IR or object bytes are modified. */
#include "runtime.h"
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__aarch64__)
#error This probe requires native ARM64
#endif

static unsigned rejected_api_calls;
static bool d3d_validate_call(AotState *s,AotContext *ctx,uint64_t pc) {
    (void)s;(void)ctx;(void)pc;rejected_api_calls++;return false;
}
static bool import_validate_call(AotState *s,AotContext *ctx,uint64_t pc) {
    (void)s;(void)ctx;(void)pc;rejected_api_calls++;return false;
}
#define aot_commit aot_probe_engine_commit
#define __remill_function_call aot_probe_rejected_function_call
#include "../window_bridge/window_runtime/transaction_v1.c"
#undef __remill_function_call
#undef aot_commit

typedef struct {
    uint64_t pc,next_pc;
    uint32_t kind,before_depth,after_depth,status;
} ProbeCommit;
static ProbeCommit commits[4096];
static unsigned commit_count,call_count,ret_count,max_depth,trace_overflow;

uint32_t aot_commit(void *state,uint64_t next_pc,void *opaque) {
    AotContext *ctx=opaque;
    uint64_t pc=ctx?ctx->current_pc:0;
    unsigned kind=ctx&&ctx->current?ctx->current->kind:UINT32_MAX;
    unsigned before=ctx?ctx->result.call_depth:0;
    uint32_t status=aot_probe_engine_commit(state,next_pc,opaque);
    unsigned after=ctx?ctx->result.call_depth:0;
    if(commit_count<sizeof commits/sizeof *commits)
        commits[commit_count++]=(ProbeCommit){pc,next_pc,kind,before,after,status};
    else trace_overflow=1;
    if(!status){call_count+=kind==AOT_CALL;ret_count+=kind==AOT_RET;}
    if(after>max_depth)max_depth=after;
    return status;
}

void *__remill_function_call(void *state,uint64_t pc,void *ctx) {
    rejected_api_calls++;
    return aot_probe_rejected_function_call(state,pc,ctx);
}

#include "callback_probe_input.h"
extern void *aot_window_proc_1000(void *,uint64_t,void *);

#define PROBE_STACK_BASE UINT64_C(0x70000000)
#define PROBE_STACK_SIZE 65536u
#define PROBE_EXIT UINT64_C(0x7fff00000000)
#define PROBE_RSP (PROBE_STACK_BASE+PROBE_STACK_SIZE-0x108)

static void stop(const char *what) {fprintf(stderr,"callback_probe: %s (errno=%d)\n",what,errno);exit(2);}
static void read_exact(const char *filename,void *destination,size_t size) {
    FILE *file=fopen(filename,"rb");if(!file)stop("cannot open input");
    if(fread(destination,1,size,file)!=size || fgetc(file)!=EOF || ferror(file))stop("input extent differs");
    if(fclose(file))stop("input close failed");
}
static void put32(uint8_t *bytes,uint32_t value) {memcpy(bytes,&value,4);}
static uint32_t get32(const uint8_t *bytes) {uint32_t value;memcpy(&value,bytes,4);return value;}
static void put64(uint8_t *bytes,uint64_t value) {memcpy(bytes,&value,8);}
static void binary(const char *directory,unsigned index,const AotState *state,const uint8_t *image,const uint8_t *stack) {
    char pathname[4096];int n=snprintf(pathname,sizeof pathname,"%s/case-%u.bin",directory,index);
    if(n<0 || (size_t)n>=sizeof pathname)stop("output path too long");
    FILE *file=fopen(pathname,"wbx");if(!file)stop("cannot create case response");
    if(fwrite(state,1,sizeof *state,file)!=sizeof *state ||
       fwrite(image,1,kProbeImageSize,file)!=kProbeImageSize ||
       fwrite(stack,1,PROBE_STACK_SIZE,file)!=PROBE_STACK_SIZE)stop("response write failed");
    if(fclose(file))stop("response close failed");
}

int main(int argc,char **argv) {
    if(argc!=5)stop("expected image, permissions, base and fresh output directory");
    errno=0;char *end=NULL;uint64_t base=strtoull(argv[3],&end,0);
    if(errno || !end || *end || !base || (base&0xffff) || base>UINT64_MAX-kProbeImageSize)stop("invalid base");
    uint8_t *original=malloc(kProbeImageSize),*permissions=malloc(kProbePageCount);
    if(!original || !permissions)stop("input allocation failed");
    read_exact(argv[1],original,kProbeImageSize);read_exact(argv[2],permissions,kProbePageCount);
    printf("{\"transport\":\"CALLBACK_PROBE_RECORDED\",\"base\":%" PRIu64 ",\"state_size\":%u,\"image_size\":%zu,\"stack_size\":%u,\"cases\":[",base,AOT_STATE_SIZE,kProbeImageSize,PROBE_STACK_SIZE);
    for(unsigned index=0;index<8;index++) {
        uint8_t *image=malloc(kProbeImageSize),*stack=calloc(1,PROBE_STACK_SIZE);
        if(!image || !stack)stop("case allocation failed");
        memcpy(image,original,kProbeImageSize);
        put32(image+kProbeStateRva+8,index);
        AotState *state=aot_state_create();
        AotContext *ctx=aot_context_create(base,kProbeInstructions,sizeof kProbeInstructions/sizeof *kProbeInstructions,
                                         4096,PROBE_EXIT,PROBE_RSP);
        if(!state || !ctx)stop("context allocation failed");
        for(unsigned reg=0;reg<17;reg++)
            aot_set_register(state,reg,UINT64_C(0xabc0000000000000)+UINT64_C(0x10101010101)*reg);
        aot_set_register(state,AOT_RSP,PROBE_RSP);
        aot_set_register(state,AOT_RCX,0);aot_set_register(state,AOT_RDX,0x100);
        aot_set_register(state,AOT_R8,39);aot_set_register(state,AOT_R9,0);
        put64(stack+(PROBE_RSP-PROBE_STACK_BASE),PROBE_EXIT);
        uint8_t stack_rights[PROBE_STACK_SIZE/GM_PAGE];memset(stack_rights,GM_READ|GM_WRITE,sizeof stack_rights);
        GuestMemory image_map={base,kProbeImageSize,image,permissions,kProbePageCount};
        GuestMemory stack_map={PROBE_STACK_BASE,PROBE_STACK_SIZE,stack,stack_rights,sizeof stack_rights};
        uint32_t setup=aot_add_region(ctx,&image_map);
        if(!setup)setup=aot_add_region(ctx,&stack_map);
        uint64_t targets[32];
        for(size_t i=0;i<kProbeTargetCount;i++)targets[i]=base+kProbeTargetRvas[i];
        if(!setup)setup=aot_configure_switch(ctx,base+kProbeJumpRva,targets,kProbeTargetCount);
        if(!setup)setup=aot_bind_switch(ctx,base+kProbeTableRva,kProbeTableBytes,sizeof kProbeTableBytes);
        rejected_api_calls=commit_count=call_count=ret_count=max_depth=trace_overflow=0;
        uint32_t status=setup?AOT_INVALID:aot_execute(aot_window_proc_1000,state,ctx,base+kProbeRootRva);
        AotResult result;aot_result(ctx,&result);
        binary(argv[4],index,state,image,stack);
        if(index)printf(",");
        printf("{\"initial_position\":%u,\"position\":%u,\"moves\":%u,\"draws\":%u,\"keydowns\":%u,\"dirty\":%u,\"setup_status\":%u,\"status\":%u,\"returned\":%u,\"call_depth\":%u,\"steps\":%" PRIu64 ",\"switch_commits\":%" PRIu64 ",\"call_commits\":%u,\"ret_commits\":%u,\"max_call_depth\":%u,\"rejected_api_calls\":%u,\"trace_overflow\":%u,\"response\":\"case-%u.bin\",",
               index,get32(image+kProbeStateRva+8),get32(image+kProbeStateRva+12),get32(image+kProbeStateRva+16),
               get32(image+kProbeResultRva+12),get32(image+kProbeResultRva+56),setup,status,result.returned,result.call_depth,
               result.steps,aot_window_switch_commits(ctx),call_count,ret_count,max_depth,rejected_api_calls,trace_overflow,index);
        printf("\"fault\":{\"status\":%u,\"access\":%u,\"pc\":%" PRIu64 ",\"address\":%" PRIu64 ",\"width\":%" PRIu64 "},\"registers\":[",
               result.fault.status,result.fault.access,result.fault.pc,result.fault.address,result.fault.width);
        for(unsigned reg=0;reg<17;reg++)printf("%s%" PRIu64,reg?",":"",aot_get_register(state,reg));
        printf("],\"flags\":%u,\"trace\":[",aot_get_flags(state));
        for(unsigned i=0;i<commit_count;i++) {
            ProbeCommit *c=commits+i;
            printf("%s{\"pc\":%" PRIu64 ",\"next_pc\":%" PRIu64 ",\"kind\":%u,\"before_depth\":%u,\"after_depth\":%u,\"status\":%u}",
                   i?",":"",c->pc,c->next_pc,c->kind,c->before_depth,c->after_depth,c->status);
        }
        printf("]}");
        aot_context_destroy(ctx);aot_state_destroy(state);free(image);free(stack);
    }
    printf("]}\n");free(original);free(permissions);return 0;
}
