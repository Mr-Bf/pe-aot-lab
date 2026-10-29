/* Independent actual-PE / actual-DXMT review harness. All fault injection below
 * is trusted host test code; it is not attributed to unmodified guest inputs. */
#include "runtime.h"
#include "native_backend.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint64_t backend_calls[19];
static unsigned inject_map_pitch;
static uint32_t review_create(void **d,void **c,uint32_t *l){backend_calls[0]++;return aot_d3d_native_create_device(d,c,l);}
static uint32_t review_texture(void *d,const uint32_t x[11],void **t){backend_calls[1]++;return aot_d3d_native_create_texture(d,x,t);}
static uint32_t review_rtv(void *d,void *t,void **v){backend_calls[2]++;return aot_d3d_native_create_rtv(d,t,v);}
static uint32_t review_removed(void *d){backend_calls[3]++;return aot_d3d_native_get_removed(d);}
static void review_clear(void *c,void *v,const float x[4]){backend_calls[4]++;aot_d3d_native_clear(c,v,x);}
static void review_copy(void *c,void *d,void *s){backend_calls[5]++;aot_d3d_native_copy(c,d,s);}
static uint32_t review_map(void *c,void *t,AotD3DNativeMap *r){backend_calls[6]++;uint32_t hr=aot_d3d_native_map(c,t,r);if(!(hr&0x80000000) && inject_map_pitch)r->row_pitch=inject_map_pitch;return hr;}
static void review_unmap(void *c,void *t){backend_calls[7]++;aot_d3d_native_unmap(c,t);}
static uint32_t review_release(uint32_t k,void *p){backend_calls[8]++;return aot_d3d_native_release(k,p);}
static uint32_t review_shader(uint32_t k,void*d,const uint8_t*b,uint64_t n,void**s){backend_calls[k==5?9:10]++;return aot_d3d_native_create_shader(k,d,b,n,s);}
static uint32_t review_raster(void*d,const uint32_t x[10],void**r){backend_calls[11]++;return aot_d3d_native_create_raster(d,x,r);}
static void review_om(void*c,void*r){backend_calls[12]++;aot_d3d_native_om_set(c,r);}
static void review_rs(void*c,void*r){backend_calls[13]++;aot_d3d_native_rs_set(c,r);}
static void review_viewport(void*c,const uint32_t*x){backend_calls[14]++;aot_d3d_native_viewport(c,x);}
static void review_topology(void*c){backend_calls[15]++;aot_d3d_native_topology(c);}
static void review_set_shader(uint32_t k,void*c,void*s){backend_calls[k==5?16:17]++;aot_d3d_native_shader_set(k,c,s);}
static void review_draw(void*c){backend_calls[18]++;aot_d3d_native_draw(c);}
#define aot_d3d_native_create_shader review_shader
#define aot_d3d_native_create_raster review_raster
#define aot_d3d_native_om_set review_om
#define aot_d3d_native_rs_set review_rs
#define aot_d3d_native_viewport review_viewport
#define aot_d3d_native_topology review_topology
#define aot_d3d_native_shader_set review_set_shader
#define aot_d3d_native_draw review_draw
#define aot_d3d_native_create_device review_create
#define aot_d3d_native_create_texture review_texture
#define aot_d3d_native_create_rtv review_rtv
#define aot_d3d_native_get_removed review_removed
#define aot_d3d_native_clear review_clear
#define aot_d3d_native_copy review_copy
#define aot_d3d_native_map review_map
#define aot_d3d_native_unmap review_unmap
#define aot_d3d_native_release review_release
#include "runtime.c"
#include "native_image.h"
#include "review_points.h"
extern void *aot_entry(void *,uint64_t,void *);
static unsigned checks,actual_pe_cases,trusted_cases,case_id;
static FILE *case_log;
static void case_start(const char *name){case_id++;fprintf(case_log,"{\"event\":\"start\",\"id\":%u,\"name\":\"%s\"}\n",case_id,name);fflush(case_log);}
#define CHECK(c) do {checks++;if(!(c)){fprintf(stderr,"CHECK line %d: %s\n",__LINE__,#c);exit(90);}}while(0)
enum {SS=65536,PS=8*4096,MS=1024*1024};
static const uint64_t SB=0x70000000,PB=0x60000000,MB=0x61000000,EXIT_PC=UINT64_C(0x7fff00000000);
typedef struct {
    uint8_t *image,*stack,*proxy,*arena,*thunks;
    uint8_t stack_perms[SS/4096],proxy_perms[8],arena_perms[MS/4096],thunk_perms[1024];size_t thunk_size;
    AotState *s;AotContext *c;AotD3DConfig config;uint64_t base,rsp;
} Env;
static void put64(uint8_t *p,uint64_t v){memcpy(p,&v,8);}
static uint64_t get64(const uint8_t *p){uint64_t v;memcpy(&v,p,8);return v;}
static unsigned obs(const char *name){for(size_t i=0;i<kObservationCount;i++)if(!strcmp(name,kObservations[i].name))return kObservations[i].rva;CHECK(0);return 0;}
static void prepare(Env *e,uint64_t base,uint64_t budget){
    memset(e,0,sizeof *e);memset(backend_calls,0,sizeof backend_calls);inject_map_pitch=0;
    e->base=base;e->rsp=SB+SS-0x108;e->image=malloc(sizeof kImageBytes);e->stack=calloc(1,SS);e->proxy=calloc(1,PS);e->arena=calloc(1,MS);e->thunk_size=(size_t)(kThunks[kThunkCount-1]-kThunks[0])+4096;CHECK(e->thunk_size<=4*1024*1024);e->thunks=calloc(1,e->thunk_size);e->s=aot_state_create();
    CHECK(e->image&&e->stack&&e->proxy&&e->arena&&e->thunks&&e->s);memcpy(e->image,kImageBytes,sizeof kImageBytes);
    for(size_t i=0;i<kRelocationCount;i++)put64(e->image+kRelocations[i].rva,kRelocations[i].value+base-kPreferredBase);
    for(size_t i=0;i<kImportCount;i++)put64(e->image+kImports[i].iat_rva,base+kImports[i].target_rva);
    put64(e->stack+e->rsp-SB,EXIT_PC);aot_set_register(e->s,AOT_RSP,e->rsp);
    memset(e->stack_perms,3,sizeof e->stack_perms);memset(e->proxy_perms,1,sizeof e->proxy_perms);
    e->c=aot_context_create(base,kInstructions,kInstructionCount,budget,EXIT_PC,e->rsp);CHECK(e->c);
    GuestMemory regions[]={{base,sizeof kImageBytes,e->image,kImagePermissions,sizeof kImagePermissions},{SB,SS,e->stack,e->stack_perms,sizeof e->stack_perms},
        {PB,PS,e->proxy,e->proxy_perms,8},{MB,MS,e->arena,e->arena_perms,sizeof e->arena_perms}};
    for(size_t i=0;i<4;i++)CHECK(!aot_add_region(e->c,&regions[i]));
    e->config.proxy_base=PB;e->config.proxy_count=32;e->config.map_base=MB;e->config.map_capacity=MS;
    for(unsigned i=0;i<AOT_D3D_KIND_COUNT;i++)e->config.vtable_va[i]=PB+4096*(i+1);
    for(unsigned i=0;i<AOT_D3D_METHOD_COUNT;i++)e->config.method_targets[i]=base+kD3DMethodThunks[i];
    const unsigned methods[][3]={{0,2,0},{0,5,1},{0,9,2},{0,39,3},{1,2,0},{1,14,6},{1,15,7},{1,47,5},{1,50,4},{2,2,0},{3,2,0},{4,2,0},{5,2,0},{6,2,0},{0,12,8},{0,15,9},{0,22,10},{1,33,11},{1,43,12},{1,44,13},{1,24,14},{1,11,15},{1,9,16},{1,13,17}};
    for(size_t i=0;i<sizeof methods/sizeof methods[0];i++)put64(e->proxy+4096*(methods[i][0]+1)+8*methods[i][1],e->config.method_targets[methods[i][2]]);
    for(size_t i=0;i<kThunkCount;i++){size_t off=kThunks[i]-kThunks[0];e->thunks[off]=0xc3;e->thunk_perms[off/4096]=5;}
    GuestMemory thunks={base+kThunks[0],e->thunk_size,e->thunks,e->thunk_perms,e->thunk_size/4096};CHECK(!aot_add_region(e->c,&thunks));
    CHECK(!aot_d3d_session_begin(e->c,&e->config));
    CHECK(e->c->d3d_map_permissions!=e->arena_perms && (uintptr_t)e->image!=base && (uintptr_t)e->arena!=MB);
}
static void canonical(FILE *f,const Env *e,const AotD3DStats *before,const AotD3DStats *after,uint32_t status){
    CHECK(fwrite(&status,sizeof status,1,f)==1);CHECK(fwrite(e->s,1,sizeof *e->s,f)==sizeof *e->s);
    CHECK(fwrite(&e->c->result,1,sizeof e->c->result,f)==sizeof e->c->result);
    CHECK(fwrite(e->image,1,sizeof kImageBytes,f)==sizeof kImageBytes);CHECK(fwrite(e->stack,1,SS,f)==SS);
    CHECK(fwrite(e->proxy,1,PS,f)==PS);CHECK(fwrite(e->arena,1,MS,f)==MS);
    CHECK(fwrite(e->c->d3d_map_permissions,1,MS/4096,f)==MS/4096);
    CHECK(fwrite(before,1,sizeof *before,f)==sizeof *before);CHECK(fwrite(after,1,sizeof *after,f)==sizeof *after);
    CHECK(fwrite(backend_calls,1,sizeof backend_calls,f)==sizeof backend_calls);
}
static void finish(Env *e,FILE *f,uint32_t status){
    AotD3DStats before={0},after={0};aot_d3d_stats(&before);AotState saved=*e->s;AotResult result=e->c->result;
    uint64_t actual_releases=backend_calls[8],actual_unmaps=backend_calls[7];
    uint32_t cleanup=aot_d3d_session_end();aot_d3d_stats(&after);
    CHECK(cleanup==before.live_objects);CHECK(backend_calls[8]-actual_releases==before.live_objects);CHECK(backend_calls[7]-actual_unmaps==before.active_maps);CHECK(after.cleanup_releases-before.cleanup_releases==before.live_objects);
    CHECK(after.cleanup_unmaps-before.cleanup_unmaps==before.active_maps);CHECK(!after.live_objects&&!after.active_maps);
    CHECK(after.release_calls==before.release_calls&&after.unmap_calls==before.unmap_calls);
    CHECK(!memcmp(&saved,e->s,sizeof saved)&&!memcmp(&result,&e->c->result,sizeof result));
    for(unsigned i=0;i<MS/4096;i++)CHECK(!e->c->d3d_map_permissions[i]&&!e->arena_perms[i]);
    CHECK(!aot_d3d_session_end());AotD3DStats twice={0};aot_d3d_stats(&twice);CHECK(!memcmp(&twice,&after,sizeof after));
    canonical(f,e,&before,&after,status);CHECK(!fflush(f));fprintf(case_log,"{\"event\":\"end\",\"id\":%u,\"status\":%u}\n",case_id,status);CHECK(!fflush(case_log));aot_context_destroy(e->c);aot_state_destroy(e->s);free(e->image);free(e->stack);free(e->proxy);free(e->arena);free(e->thunks);
}
static void original_pe(FILE *f,uint64_t base,uint64_t budget){
    Env e;prepare(&e,base,budget);uint32_t status=aot_execute(aot_entry,e.s,e.c,base+kEntryRva);AotD3DStats stats={0};aot_d3d_stats(&stats);
    uint32_t r[28];memcpy(r,e.image+obs("graphics_result"),sizeof r);
    if(budget>kMapCallStep+1){CHECK(status==AOT_PROCESS_EXITED&&!e.c->result.fault.status&&aot_process_exit_code()==0);CHECK(e.c->result.steps==39415);for(unsigned i=2;i<8;i++)CHECK(r[i]==0);CHECK(r[0]==11&&r[1]==0xb000&&r[10]==1024&&r[11]==4096&&r[12]==0&&r[13]==0&&r[14]==0);CHECK(stats.created==8&&stats.guest_released==8&&stats.release_calls==8&&stats.this_checks==26);CHECK(stats.map_calls==1&&stats.unmap_calls==1&&stats.map_bytes_copied==4096&&!stats.active_maps&&!stats.live_objects);CHECK(!get64(e.image+obs("graphics_device")));CHECK(!r[24]&&!r[25]&&!r[26]&&r[27]==1);for(unsigned i=9;i<19;i++)CHECK(backend_calls[i]==1);}
    else {CHECK(status==AOT_BUDGET&&e.c->result.steps==budget&&e.c->result.fault.status==AOT_BUDGET);CHECK(stats.created==8&&stats.release_calls==0&&stats.live_objects==8&&stats.unmap_calls==0);CHECK(stats.map_calls==(budget==kMapCallStep+1)&&stats.active_maps==(budget==kMapCallStep+1));CHECK(stats.map_bytes_copied==(budget==kMapCallStep+1?4096:0));if(budget==kMapCallStep+1){CHECK(get64(e.image+obs("graphics_mapped"))==MB);CHECK(e.c->d3d_map_permissions[0]==GM_READ);}}
    uint32_t marker;memcpy(&marker,e.image+obs("graphics_after_exit"),4);CHECK(!marker);actual_pe_cases++;finish(&e,f,status);
}
/* A trusted test entry pauses at the real Map CALL boundary by using the real
 * PE with the exact manifest-derived Map CALL budget. Then only the harness resets fault/budget and
 * invokes the already committed opaque helper. This is explicitly a host hook,
 * not a supported public resume facility or a mutated guest program. */
static void at_map(Env *e){
    prepare(e,kPreferredBase,kMapCallStep);CHECK(aot_execute(aot_entry,e->s,e->c,e->base+kEntryRva)==AOT_BUDGET);
    CHECK(e->c->current->rva==kMapCallRva && e->c->result.call_depth==1 && session.stats.map_calls==0);
    memset(&e->c->result.fault,0,sizeof e->c->result.fault);e->c->budget=1000000;
    session.running=1;session.state_identity=(uintptr_t)e->s;
}
static void map_hook(FILE *f,unsigned scenario){
    Env e;at_map(&e);uint64_t rsp=aot_get_register(e.s,AOT_RSP),out=get64(e.stack+rsp+48-SB);AotState before=*e.s;
    CHECK(out>=e.base && out-e.base<=sizeof kImageBytes-16);uint8_t saved[16];memcpy(saved,e.image+(out-e.base),16);uint64_t count=backend_calls[6],unmap=backend_calls[7];uint32_t expected;
    if(scenario==0){put64(e.stack+rsp+48-SB,UINT64_C(0x77770000));expected=AOT_BOUNDS;}
    else if(scenario==1){put64(e.stack+rsp+48-SB,rsp+8);expected=AOT_UNSUPPORTED;}
    else if(scenario==2){inject_map_pitch=MS;expected=AOT_CAPACITY;}
    else {e.s->bytes[2075]=1;before=*e.s;expected=AOT_INVALID;}
    __remill_function_call(e.s,e.config.method_targets[AOT_D3D_MAP],e.c);session.running=0;
    CHECK(e.c->result.fault.status==expected);CHECK(!memcmp(&before,e.s,sizeof before));CHECK(!memcmp(saved,e.image+(out-e.base),16));
    CHECK(backend_calls[6]-count==(scenario==2));CHECK(backend_calls[7]-unmap==(scenario==2));
    CHECK(session.stats.map_postcall_failures==(scenario==2)&&session.stats.cleanup_unmaps==(scenario==2));
    CHECK(!session.stats.active_maps&&session.stats.live_objects==8&&session.stats.map_bytes_copied==0);
    trusted_cases++;finish(&e,f,expected);
}
static void active_release(FILE *f){
    Env e;prepare(&e,kPreferredBase,kMapCallStep+1);CHECK(aot_execute(aot_entry,e.s,e.c,e.base+kEntryRva)==AOT_BUDGET);CHECK(session.stats.active_maps==1);
    memset(&e.c->result.fault,0,sizeof e.c->result.fault);e.c->d3d_object_index=1;aot_set_register(e.s,AOT_RCX,session.objects[1].proxy);
    AotState before=*e.s;uint64_t releases=backend_calls[8];bool has_result=true;
    invoke_method(e.s,e.c,AOT_D3D_SIG_RELEASE,aot_get_register(e.s,AOT_RSP),&has_result);
    CHECK(e.c->result.fault.status==AOT_MAP_STATE&&backend_calls[8]==releases);CHECK(!memcmp(&before,e.s,sizeof before));
    CHECK(session.stats.active_maps==1&&!session.stats.release_calls);trusted_cases++;finish(&e,f,AOT_MAP_STATE);
}
static void bad_target(FILE *f){
    Env e;prepare(&e,kPreferredBase,kMapCallStep-1);CHECK(aot_execute(aot_entry,e.s,e.c,e.base+kEntryRva)==AOT_BUDGET);
    CHECK(e.c->result.fault.pc==e.base+kMapCallRva);memset(&e.c->result.fault,0,sizeof e.c->result.fault);e.c->budget=1000000;
    session.running=1;session.state_identity=(uintptr_t)e.s;uint64_t pc=e.base+kMapCallRva,rsp=aot_get_register(e.s,AOT_RSP);
    CHECK(!aot_begin(e.s,pc,e.c));AotState before=*e.s;uint8_t stack[8];memcpy(stack,e.stack+rsp-8-SB,8);uint64_t target=e.config.method_targets[AOT_D3D_MAP]+1;
    __remill_write_memory_64(e.c,rsp-8,pc+e.c->current->length);aot_set_register(e.s,AOT_RSP,rsp-8);aot_set_register(e.s,AOT_RIP,target);
    CHECK(aot_commit(e.s,target,e.c));session.running=0;CHECK(e.c->result.fault.status==AOT_BAD_METHOD);
    CHECK(!memcmp(&before,e.s,sizeof before)&&!memcmp(stack,e.stack+rsp-8-SB,8));CHECK(!backend_calls[6]&&!session.stats.active_maps);
    trusted_cases++;finish(&e,f,AOT_BAD_METHOD);
}

/* These hooks execute the actual lifted prefix first. Only trusted test code
 * clears the terminal budget fault; production has no public resume API. */
static void at_call(Env *e,uint64_t step,uint32_t rva){
    prepare(e,kPreferredBase,step);CHECK(aot_execute(aot_entry,e->s,e->c,e->base+kEntryRva)==AOT_BUDGET);
    CHECK(e->c->current->rva==rva && e->c->result.call_depth==1 && e->c->d3d_binding_valid);
    memset(&e->c->result.fault,0,sizeof e->c->result.fault);e->c->budget=1000000;
    session.running=1;session.state_identity=(uintptr_t)e->s;
}
static void shader_hook(FILE *f,unsigned scenario){
    Env e;at_call(&e,kVSCallStep,kVSCallRva);CHECK(session.stats.live_objects==5&&!backend_calls[9]);
    uint64_t rsp=aot_get_register(e.s,AOT_RSP),source=aot_get_register(e.s,AOT_RDX),out=get64(e.stack+rsp+40-SB);
    CHECK(source>=e.base&&source-e.base<=sizeof kImageBytes-sizeof kTriangleVsDxbc);
    CHECK(out>=e.base&&out-e.base<=sizeof kImageBytes-8);uint64_t saved_out=get64(e.image+out-e.base);
    uint32_t expected=AOT_UNSUPPORTED;
    if(scenario==0)aot_set_register(e.s,AOT_R8,sizeof kTriangleVsDxbc+1);
    else if(scenario==1)e.image[source-e.base]^=1;
    else if(scenario==2){put64(e.stack+rsp+40-SB,UINT64_C(0x77770000));expected=AOT_BOUNDS;}
    else if(scenario==3)aot_set_register(e.s,AOT_R9,1);
    else {memcpy(e.stack+0x1000,e.image+source-e.base,sizeof kTriangleVsDxbc);aot_set_register(e.s,AOT_RDX,SB+0x1000);put64(e.stack+rsp+40-SB,SB+0x1008);}
    AotState before=*e.s;AotD3DStats stats=session.stats;uint64_t calls[19];memcpy(calls,backend_calls,sizeof calls);
    uint8_t source_copy[sizeof kTriangleVsDxbc];if(scenario==4)memcpy(source_copy,e.stack+0x1000,sizeof source_copy);
    __remill_function_call(e.s,e.config.method_targets[AOT_D3D_CREATE_VS],e.c);session.running=0;
    CHECK(e.c->result.fault.status==expected&&!memcmp(&before,e.s,sizeof before));
    CHECK(!memcmp(calls,backend_calls,sizeof calls)&&!memcmp(&stats,&session.stats,sizeof stats));
    CHECK(saved_out==get64(e.image+out-e.base));if(scenario==4)CHECK(!memcmp(source_copy,e.stack+0x1000,sizeof source_copy));
    trusted_cases++;finish(&e,f,expected);
}
static void pipeline_hook(FILE *f,unsigned scenario){
    Env e;at_call(&e,kDrawCallStep,kDrawCallRva);CHECK(session.stats.live_objects==8&&session.pipelines[1].flags==63&&!backend_calls[18]);
    uint32_t signature=AOT_D3D_SIG_DRAW,expected=AOT_UNSUPPORTED;
    uint64_t rsp=aot_get_register(e.s,AOT_RSP);e.c->d3d_object_index=1;
    if(scenario==0){
        uint32_t desc[10]={3,1,0,0,0,0,1,0,0,1};memcpy(e.stack+0x1000,desc,sizeof desc);
        e.c->d3d_object_index=0;aot_set_register(e.s,AOT_RCX,session.objects[0].proxy);
        aot_set_register(e.s,AOT_RDX,SB+0x1000);aot_set_register(e.s,AOT_R8,SB+0x2000);signature=AOT_D3D_SIG_CREATE_RASTER;
    }else if(scenario==1){
        uint32_t viewport[6]={0,0,0x7fc00000,0x42000000,0,0x3f800000};memcpy(e.stack+0x1000,viewport,sizeof viewport);
        aot_set_register(e.s,AOT_RDX,1);aot_set_register(e.s,AOT_R8,SB+0x1000);signature=AOT_D3D_SIG_VIEWPORT;
    }else if(scenario==2){aot_set_register(e.s,AOT_RDX,2);signature=AOT_D3D_SIG_TOPOLOGY;
    }else if(scenario==3){aot_set_register(e.s,AOT_RDX,session.objects[6].proxy);aot_set_register(e.s,AOT_R8,0);aot_set_register(e.s,AOT_R9,0);signature=AOT_D3D_SIG_VS_SET;expected=AOT_BAD_OBJECT;
    }else if(scenario==4)aot_set_register(e.s,AOT_RDX,4);
    else session.pipelines[1].flags&=~4u;
    AotState before=*e.s;AotD3DStats stats=session.stats;PipelineState pipeline=session.pipelines[1];uint64_t calls[19];memcpy(calls,backend_calls,sizeof calls);
    uint8_t saved[0x1010];memcpy(saved,e.stack+0x1000,sizeof saved);bool has_result=true;
    invoke_method(e.s,e.c,signature,rsp,&has_result);session.running=0;
    CHECK(e.c->result.fault.status==expected&&!memcmp(&before,e.s,sizeof before));
    CHECK(!memcmp(calls,backend_calls,sizeof calls)&&!memcmp(&stats,&session.stats,sizeof stats));
    CHECK(!memcmp(&pipeline,&session.pipelines[1],sizeof pipeline)&&!memcmp(saved,e.stack+0x1000,sizeof saved));
    trusted_cases++;finish(&e,f,expected);
}

/* Actual lifted Draw prefix, followed by trusted method-layer early release.
 * There is intentionally no Map, EVENT wait, added native reference or altered
 * production cleanup. The final device Release exercises the fixed backend's
 * terminal ordering while all commands are still allowed to be asynchronous. */
static void early_release_all(FILE *f){
    Env e;at_map(&e);CHECK(session.stats.live_objects==8&&session.stats.draw_calls==1&&!session.stats.map_calls);
    AotState saved=*e.s;uint64_t rsp=aot_get_register(e.s,AOT_RSP);
    for(unsigned n=8;n;n--){unsigned i=n-1;e.c->d3d_object_index=i;aot_set_register(e.s,AOT_RCX,session.objects[i].proxy);bool result=true;
        invoke_method(e.s,e.c,AOT_D3D_SIG_RELEASE,rsp,&result);CHECK(!e.c->result.fault.status&&!session.objects[i].native);}
    *e.s=saved;session.running=0;
    CHECK(session.stats.guest_released==8&&session.stats.release_calls==8&&!session.stats.live_objects&&!session.stats.map_calls&&!session.stats.cleanup_releases);
    CHECK(backend_calls[8]==8&&!backend_calls[6]&&!backend_calls[7]);trusted_cases++;finish(&e,f,AOT_OK);
}

/* Real native context ownership is tested after releasing application refs.
 * The real PE prefix bound all four objects; the test hook changes only their
 * release timing. Readback below is explicitly trusted native API verification,
 * not execution of the remainder of the original guest loop. */
static void bound_release_draw(FILE *f){
    Env e;at_call(&e,kDrawCallStep,kDrawCallRva);CHECK(session.stats.live_objects==8&&!backend_calls[18]);
    AotState call_state=*e.s;uint64_t rsp=aot_get_register(e.s,AOT_RSP),return_pc=get64(e.stack+rsp-SB);
    const unsigned release_slots[]={5,6,7,3};PipelineState pipeline=session.pipelines[1];
    for(unsigned i=0;i<4;i++){
        unsigned slot=release_slots[i];e.c->d3d_object_index=slot;aot_set_register(e.s,AOT_RCX,session.objects[slot].proxy);bool result=true;
        invoke_method(e.s,e.c,AOT_D3D_SIG_RELEASE,rsp,&result);CHECK(!e.c->result.fault.status&&!session.objects[slot].native);
    }
    CHECK(session.stats.live_objects==4&&session.stats.release_calls==4&&!memcmp(&pipeline,&session.pipelines[1],sizeof pipeline));
    *e.s=call_state;e.c->d3d_object_index=1;
    __remill_function_call(e.s,e.config.method_targets[AOT_D3D_DRAW],e.c);session.running=0;
    CHECK(!e.c->result.fault.status&&backend_calls[18]==1&&session.stats.draw_calls==1);
    CHECK(aot_get_register(e.s,AOT_RSP)==rsp+8&&aot_get_register(e.s,AOT_RIP)==return_pc&&e.c->result.call_depth==0);
    for(unsigned i=0;i<16;i++)if(i!=AOT_RSP)CHECK(aot_get_register(e.s,i)==aot_get_register(&call_state,i));
    CHECK(aot_get_flags(e.s)==aot_get_flags(&call_state));
    review_copy(session.objects[1].native,session.objects[4].native,session.objects[2].native);
    AotD3DNativeMap map={0};CHECK(!review_map(session.objects[1].native,session.objects[4].native,&map));
    CHECK(map.data&&map.row_pitch>=128);const uint8_t expected[4]={0,255,0,255};
    for(unsigned y=0;y<32;y++)for(unsigned x=0;x<32;x++)for(unsigned c=0;c<4;c++)CHECK(((uint8_t*)map.data)[y*(size_t)map.row_pitch+x*4+c]==expected[c]);
    review_unmap(session.objects[1].native,session.objects[4].native);
    CHECK(!session.stats.map_calls&&!session.stats.copy_calls&&!session.stats.active_maps);
    trusted_cases++;finish(&e,f,AOT_OK);
}

int main(int argc,char **argv){
#if !defined(__aarch64__)
#error ARM64 runtime required
#endif
    CHECK(argc==2);FILE *f=fopen(argv[1],"wb");CHECK(f);char *case_path=malloc(strlen(argv[1])+7);CHECK(case_path);CHECK(snprintf(case_path,strlen(argv[1])+7,"%s.cases",argv[1])==(int)(strlen(argv[1])+6));case_log=fopen(case_path,"w");free(case_path);CHECK(case_log);
    case_start("normal-preferred");original_pe(f,kPreferredBase,1000000);case_start("normal-rebased");original_pe(f,kPreferredBase+0x20000000,1000000);
    case_start("map-call-budget");original_pe(f,kPreferredBase,kMapCallStep);case_start("map-active-budget");original_pe(f,kPreferredBase,kMapCallStep+1);
    for(unsigned i=0;i<4;i++){char label[32];CHECK(snprintf(label,sizeof label,"map-hook-%u",i)>0);case_start(label);map_hook(f,i);}case_start("bad-call-target");bad_target(f);case_start("active-map-release");active_release(f);
    for(unsigned i=0;i<5;i++){char label[32];CHECK(snprintf(label,sizeof label,"shader-hook-%u",i)>0);case_start(label);shader_hook(f,i);}for(unsigned i=0;i<6;i++){char label[32];CHECK(snprintf(label,sizeof label,"pipeline-hook-%u",i)>0);case_start(label);pipeline_hook(f,i);}case_start("bound-apprefs-release-draw");bound_release_draw(f);case_start("early-release-all-no-map");early_release_all(f);
    CHECK(case_id==23);CHECK(!fclose(case_log));CHECK(!fclose(f));printf("{\"status\":\"PASS\",\"architecture\":\"arm64\",\"actual_pe_cases\":%u,\"trusted_hook_cases\":%u,\"actual_guest_entry_executions\":23,\"checks\":%u,\"actual_dxmt\":true}\n",actual_pe_cases,trusted_cases,checks);return 0;
}
