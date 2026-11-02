/* Paired experimental instruction lookup in the actual lifted callback.
 * Both modes include shared volatile strategy dispatch and full reset/checks.
 * No deployment, outer ABI, App, GPU or game performance claim. */
#include <window_switch_v1/runtime.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(__aarch64__)
#error Native ARM64 is required
#endif

static unsigned rejected_api_calls;
static bool d3d_validate_call(AotState *s,AotContext *c,uint64_t pc) {
    (void)s;(void)c;(void)pc;rejected_api_calls++;return false;
}
static bool import_validate_call(AotState *s,AotContext *c,uint64_t pc) {
    (void)s;(void)c;(void)pc;rejected_api_calls++;return false;
}
static volatile unsigned aot_pair_lookup_mode;
#define __remill_function_call aot_bench_rejected_function_call
#include <window_bridge/window_runtime/transaction_v1.c>
#undef __remill_function_call
void *__remill_function_call(void *s,uint64_t pc,void *c) {
    rejected_api_calls++;return aot_bench_rejected_function_call(s,pc,c);
}
#include "callback_probe_input.h"
extern void *aot_window_proc_1000(void *,uint64_t,void *);

#define STACK_BASE UINT64_C(0x70000000)
#define STACK_SIZE 65536u
#define EXIT_PC UINT64_C(0x7fff00000000)
#define INITIAL_RSP (STACK_BASE+STACK_SIZE-0x108)
enum { CASES=8, WARMUP=256, MAX_ITERATIONS=65536, MAX_ROUNDS=20 };
typedef struct {
    AotState state;
    AotContext context;
    uint8_t *image,*stack;
    uint64_t checksum;
} Snapshot;
typedef struct {
    unsigned round,scenario,order_slot,mode,path;
    uint64_t wall_ns,cpu_ns,checksum;
} Measurement;
static AotState *live_state;
static AotContext *live_context;
static AotState initial_state;
static AotContext initial_context;
static uint8_t *original,*live_image,*initial_image,*live_stack,*initial_stack;
static uint8_t *permissions,*original_permissions;
static uint8_t stack_rights[STACK_SIZE/GM_PAGE];
static uint64_t module_base;

_Noreturn static void stop(const char *message) {
    fprintf(stderr,"callback_pair: %s (errno=%d)\n",message,errno);exit(2);
}
static void need(bool value,const char *message) {if(!value)stop(message);}
#include "lookup_bounds.inc"
static uint64_t number(const char *s,uint64_t lower,uint64_t upper) {
    need(s && *s && *s!='-' && *s!='+' && !isspace((unsigned char)*s),"invalid unsigned argument");
    errno=0;char *end=NULL;uint64_t value=strtoull(s,&end,0);
    need(!errno && end && !*end && value>=lower && value<=upper,"numeric argument out of range");
    return value;
}
static void read_exact(const char *path,void *buffer,size_t size) {
    FILE *f=fopen(path,"rb");need(f!=NULL,"input open");
    need(fread(buffer,1,size,f)==size && fgetc(f)==EOF && !ferror(f),"input extent");
    need(fclose(f)==0,"input close");
}
static uint32_t get32(const uint8_t *p) {uint32_t v;memcpy(&v,p,4);return v;}
static void put32(uint8_t *p,uint32_t v) {memcpy(p,&v,4);}
static void put64(uint8_t *p,uint64_t v) {memcpy(p,&v,8);}
static uint64_t word(void) {
    return aot_get_register(live_state,AOT_RAX)^aot_get_register(live_state,AOT_RSP)^
        aot_get_register(live_state,AOT_RIP)^aot_get_flags(live_state)^
        live_context->result.steps^(live_context->switch_commits<<8)^
        ((uint64_t)get32(live_image+kProbeStateRva+8)<<32)^
        get32(live_image+kProbeStateRva+12)^get32(live_image+kProbeResultRva+12);
}
static void configure(unsigned scenario) {
    memcpy(initial_image,original,kProbeImageSize);
    put32(initial_image+kProbeStateRva+8,scenario);
}
static void reset_inputs(void) {
    memcpy(live_state,&initial_state,sizeof initial_state);
    memcpy(live_context,&initial_context,sizeof initial_context);
    memcpy(live_image,initial_image,kProbeImageSize);
    memcpy(live_stack,initial_stack,STACK_SIZE);
    rejected_api_calls=0;
    /* Compiler visibility only, not a hardware fence; identical in both paths. */
    __asm__ volatile("" : : "r"(live_state),"r"(live_context),"r"(live_image),"r"(live_stack) : "memory");
}
static void copy_snapshot(Snapshot *s) {
    memcpy(&s->state,live_state,sizeof s->state);
    memcpy(&s->context,live_context,sizeof s->context);
    memcpy(s->image,live_image,kProbeImageSize);memcpy(s->stack,live_stack,STACK_SIZE);
    s->checksum=word();
}
static void snapshot(Snapshot *s) {
    s->image=malloc(kProbeImageSize);s->stack=malloc(STACK_SIZE);
    need(s->image && s->stack,"snapshot allocation");copy_snapshot(s);
}
static void full_equal(const Snapshot *s) {
    need(!memcmp(live_state,&s->state,sizeof s->state),"full State differs");
    need(!memcmp(live_context,&s->context,sizeof s->context),"full Context differs");
    need(!memcmp(live_image,s->image,kProbeImageSize),"full image differs");
    need(!memcmp(live_stack,s->stack,STACK_SIZE),"full stack differs");
    need(!memcmp(permissions,original_permissions,kProbePageCount),"image permissions changed");
    for(size_t i=0;i<sizeof stack_rights;i++)need(stack_rights[i]==(GM_READ|GM_WRITE),"stack permissions changed");
    need(!memcmp(live_context->instructions,kProbeInstructions,sizeof kProbeInstructions),"instructions changed");
    need(rejected_api_calls==0,"unexpected rejected API path");
}
static void key_equal(const Snapshot *s,uint32_t status) {
    need(status==AOT_OK && live_context->result.fault.status==AOT_OK,"iteration execution fault");
    need(live_context->result.steps==s->context.result.steps &&
         live_context->switch_commits==s->context.switch_commits &&
         live_context->result.returned==s->context.result.returned &&
         live_context->result.call_depth==s->context.result.call_depth &&
         rejected_api_calls==0 && word()==s->checksum,"iteration key invariants");
}
/* The same loop, reset, checks and checksum serve execute and reset controls.
 * The external lifted object is linked without LTO. There are no clock calls
 * or per-instruction hooks in this loop or the transaction engine. */
__attribute__((noinline)) static uint64_t batch(unsigned path,unsigned count,const Snapshot *expected) {
    uint64_t checksum=0;
    for(unsigned i=0;i<count;i++) {
        reset_inputs();
        uint32_t status=path?AOT_OK:aot_execute(aot_window_proc_1000,live_state,live_context,module_base+kProbeRootRva);
        key_equal(expected,status);checksum+=word();
    }
    return checksum;
}
static uint64_t ns(const struct timespec *t) {
    need(t->tv_sec>=0 && t->tv_nsec>=0 && t->tv_nsec<1000000000,"invalid clock timestamp");
    need((uint64_t)t->tv_sec <= (UINT64_MAX-(uint64_t)t->tv_nsec)/UINT64_C(1000000000),"clock overflow");
    return (uint64_t)t->tv_sec*UINT64_C(1000000000)+(uint64_t)t->tv_nsec;
}
static uint64_t clock_ns(clockid_t clock) {
    struct timespec t;need(clock_gettime(clock,&t)==0,"clock_gettime failed");return ns(&t);
}
static uint64_t resolution(clockid_t clock) {
    struct timespec t;need(clock_getres(clock,&t)==0,"clock_getres failed");return ns(&t);
}
static const char *mode_name(unsigned mode) {return mode?"candidate":"reference";}
static void binary(const char *directory,unsigned scenario,unsigned mode,bool final,const AotState *state,
                   const uint8_t *image,const uint8_t *stack) {
    char pathname[4096];int n=snprintf(pathname,sizeof pathname,"%s/%scase-%s-%u.bin",directory,final?"final-":"",mode_name(mode),scenario);
    need(n>=0 && (size_t)n<sizeof pathname,"output path length");
    FILE *f=fopen(pathname,"wbx");need(f!=NULL,"fresh response output required");
    need(fwrite(state,1,sizeof *state,f)==sizeof *state &&
         fwrite(image,1,kProbeImageSize,f)==kProbeImageSize &&
         fwrite(stack,1,STACK_SIZE,f)==STACK_SIZE,"response write");
    need(fclose(f)==0,"response close");
}

typedef struct {
    unsigned scenario,budget,status;
    AotResult result;
    uint64_t checksum;
} BudgetCheck;

static unsigned budgets(Snapshot *normal,BudgetCheck *checks) {
    unsigned used=0;Snapshot reference={0};
    reference.image=malloc(kProbeImageSize);reference.stack=malloc(STACK_SIZE);
    need(reference.image && reference.stack,"budget snapshot allocation");
    uint64_t saved_budget=initial_context.budget;
    for(unsigned scenario=0;scenario<CASES;scenario++) {
        configure(scenario);
        for(unsigned budget=0;budget<=normal[scenario].context.result.steps;budget++) {
            /* Internal boundary test: constructor intentionally rejects zero,
             * so zero is injected only into the saved test Context here. */
            initial_context.budget=budget;
            aot_pair_lookup_mode=0;reset_inputs();
            uint32_t status=aot_execute(aot_window_proc_1000,live_state,live_context,module_base+kProbeRootRva);
            need(status==(budget<normal[scenario].context.result.steps?AOT_BUDGET:AOT_OK),"budget result");
            need(live_context->result.steps==budget && rejected_api_calls==0,"budget step count");
            copy_snapshot(&reference);
            aot_pair_lookup_mode=1;reset_inputs();
            need(aot_execute(aot_window_proc_1000,live_state,live_context,module_base+kProbeRootRva)==status,"candidate budget status");
            full_equal(&reference);
            checks[used++]=(BudgetCheck){scenario,budget,status,reference.context.result,reference.checksum};
        }
    }
    initial_context.budget=saved_budget;aot_pair_lookup_mode=0;
    free(reference.image);free(reference.stack);return used;
}

int main(int argc,char **argv) {
    need(argc==8 && (!strcmp(argv[1],"--check") || !strcmp(argv[1],"--measure")),
         "expected --check|--measure image permissions base output_dir iterations rounds");
    const bool measure=!strcmp(argv[1],"--measure");
    module_base=number(argv[4],1,UINT64_MAX-kProbeImageSize);
    need((module_base&0xffff)==0,"base alignment");
    unsigned iterations=(unsigned)number(argv[6],1,MAX_ITERATIONS);
    unsigned rounds=(unsigned)number(argv[7],1,MAX_ROUNDS);
    original=malloc(kProbeImageSize);live_image=malloc(kProbeImageSize);initial_image=malloc(kProbeImageSize);
    live_stack=malloc(STACK_SIZE);initial_stack=calloc(1,STACK_SIZE);
    permissions=malloc(kProbePageCount);original_permissions=malloc(kProbePageCount);
    live_state=aot_state_create();
    live_context=aot_context_create(module_base,kProbeInstructions,sizeof kProbeInstructions/sizeof *kProbeInstructions,
                                    4096,EXIT_PC,INITIAL_RSP);
    need(original && live_image && initial_image && live_stack && initial_stack && permissions &&
         original_permissions && live_state && live_context,"input allocation");
    read_exact(argv[2],original,kProbeImageSize);read_exact(argv[3],permissions,kProbePageCount);
    memcpy(original_permissions,permissions,kProbePageCount);
    memcpy(live_image,original,kProbeImageSize);memset(live_stack,0,STACK_SIZE);
    put64(initial_stack+INITIAL_RSP-STACK_BASE,EXIT_PC);
    for(unsigned reg=0;reg<17;reg++)
        aot_set_register(live_state,reg,UINT64_C(0xabc0000000000000)+UINT64_C(0x10101010101)*reg);
    aot_set_register(live_state,AOT_RSP,INITIAL_RSP);
    aot_set_register(live_state,AOT_RCX,0);aot_set_register(live_state,AOT_RDX,0x100);
    aot_set_register(live_state,AOT_R8,39);aot_set_register(live_state,AOT_R9,0);
    memcpy(&initial_state,live_state,sizeof initial_state);
    memset(stack_rights,GM_READ|GM_WRITE,sizeof stack_rights);
    GuestMemory im={module_base,kProbeImageSize,live_image,permissions,kProbePageCount};
    GuestMemory st={STACK_BASE,STACK_SIZE,live_stack,stack_rights,sizeof stack_rights};
    need(aot_add_region(live_context,&im)==AOT_OK && aot_add_region(live_context,&st)==AOT_OK,"region setup");
    need(kProbeTargetCount==8 && kProbeTargetCount<=32,"eight-way input contract");
    uint64_t targets[32];
    for(size_t i=0;i<kProbeTargetCount;i++)targets[i]=module_base+kProbeTargetRvas[i];
    need(aot_configure_switch(live_context,module_base+kProbeJumpRva,targets,kProbeTargetCount)==AOT_OK &&
         aot_bind_switch(live_context,module_base+kProbeTableRva,kProbeTableBytes,sizeof kProbeTableBytes)==AOT_OK,"switch binding");
    memcpy(&initial_context,live_context,sizeof initial_context);
    LookupChecks lookup={0};if(!measure)lookup=lookup_boundaries(live_context);
    Snapshot expected[CASES],reset_expected[CASES],final[2][CASES];
    for(unsigned scenario=0;scenario<CASES;scenario++) {
        configure(scenario);reset_inputs();snapshot(reset_expected+scenario);
        for(unsigned mode=0;mode<2;mode++) {
            aot_pair_lookup_mode=mode;reset_inputs();
            uint32_t status=aot_execute(aot_window_proc_1000,live_state,live_context,module_base+kProbeRootRva);
            need(status==AOT_OK && live_context->result.returned==1 && live_context->result.call_depth==0 &&
                 live_context->result.steps==(scenario<7?45:41) && live_context->switch_commits==1 && rejected_api_calls==0,"callback result");
            unsigned moved=scenario<7;
            need(get32(live_image+kProbeStateRva+8)==scenario+moved &&
                 get32(live_image+kProbeStateRva+12)==moved && get32(live_image+kProbeStateRva+16)==0 &&
                 get32(live_image+kProbeResultRva+12)==1 && get32(live_image+kProbeResultRva+56)==moved,"callback observations");
            if(!mode)snapshot(expected+scenario);else full_equal(expected+scenario);
            binary(argv[5],scenario,mode,false,live_state,live_image,live_stack);
            if(measure) {
                snapshot(&final[mode][scenario]);
                need(batch(0,WARMUP,expected+scenario)==expected[scenario].checksum*WARMUP,"execute warmup checksum");
                full_equal(expected+scenario);
            }
        }
        if(measure) {
            need(batch(1,WARMUP,reset_expected+scenario)==reset_expected[scenario].checksum*WARMUP,"reset warmup checksum");
            full_equal(reset_expected+scenario);
        }
    }
    BudgetCheck budget_checks[CASES*46];unsigned budget_used=0;
    if(!measure)budget_used=budgets(expected,budget_checks);
    Measurement measurements[MAX_ROUNDS*CASES*5];unsigned used=0;
    uint64_t wall_resolution=0,cpu_resolution=0;
    if(measure) {
        wall_resolution=resolution(CLOCK_MONOTONIC_RAW);cpu_resolution=resolution(CLOCK_THREAD_CPUTIME_ID);
        for(unsigned round=0;round<rounds;round++) {
            for(unsigned offset=0;offset<CASES;offset++) {
                unsigned scenario=(round+offset)%CASES;configure(scenario);
                unsigned reset_slot=((round+scenario)&1)?4:0;
                for(unsigned slot=0;slot<5;slot++) {
                    unsigned path=slot==reset_slot;
                    unsigned execute_slot=slot-(reset_slot==0?1:0);
                    unsigned mode=path?0:((execute_slot==0 || execute_slot==3)?(round&1):1-(round&1));
                    aot_pair_lookup_mode=mode;
                    const Snapshot *wanted=path?reset_expected+scenario:expected+scenario;
                    need(batch(path,1,wanted)==wanted->checksum,"pre-batch checksum");full_equal(wanted);
                    uint64_t wall_start=clock_ns(CLOCK_MONOTONIC_RAW),cpu_start=clock_ns(CLOCK_THREAD_CPUTIME_ID);
                    uint64_t sum=batch(path,iterations,wanted);
                    uint64_t cpu_end=clock_ns(CLOCK_THREAD_CPUTIME_ID),wall_end=clock_ns(CLOCK_MONOTONIC_RAW);
                    need(wall_end>wall_start && cpu_end>cpu_start,"nonpositive interval");
                    need(sum==wanted->checksum*iterations,"batch checksum");full_equal(wanted);
                    measurements[used++]=(Measurement){round,scenario,slot,mode,path,wall_end-wall_start,cpu_end-cpu_start,sum};
                    if(round+1==rounds && !path)copy_snapshot(&final[mode][scenario]);
                }
            }
        }
        for(unsigned scenario=0;scenario<CASES;scenario++)for(unsigned mode=0;mode<2;mode++)
            binary(argv[5],scenario,mode,true,&final[mode][scenario].state,final[mode][scenario].image,final[mode][scenario].stack);
    }
    uint64_t timed=measure?(uint64_t)rounds*CASES*4*iterations:0;
    uint64_t untimed=2*CASES+(measure?(uint64_t)2*CASES*WARMUP+(uint64_t)rounds*CASES*4:2*budget_used);
    uint64_t reset_controls=measure?(uint64_t)CASES*WARMUP+(uint64_t)rounds*CASES*(iterations+1):0;
    /* One additional reset per scenario creates each reset_expected snapshot. */
    uint64_t resets=timed+untimed+reset_controls+CASES;
    printf("{\"status\":\"%s\",\"mode\":\"%s\",\"base\":%" PRIu64 ","
           "\"state_size\":%zu,\"context_size\":%zu,\"image_size\":%zu,\"stack_size\":%u,"
           "\"iterations\":%u,\"rounds\":%u,\"warmup_iterations_per_scenario_path\":%u,"
           "\"actual_callback_executions\":%" PRIu64 ",\"timed_callback_executions\":%" PRIu64 ","
           "\"untimed_callback_executions\":%" PRIu64 ",\"reset_control_iterations\":%" PRIu64 ","
           "\"all_reset_calls\":%" PRIu64 ",\"timer_calls\":%u,\"clock_resolution_queries\":%u,"
           "\"wall_clock\":\"CLOCK_MONOTONIC_RAW\",\"cpu_clock\":\"CLOCK_THREAD_CPUTIME_ID\","
           "\"clock_order\":\"wall_start,cpu_start,batch,cpu_end,wall_end\","
           "\"wall_resolution_ns\":%" PRIu64 ",\"thread_cpu_resolution_ns\":%" PRIu64 ","
           "\"reset_bytes_per_iteration\":%zu,\"reset_included\":true,\"checksum_included\":true,"
           "\"key_invariants_per_iteration\":true,\"full_comparison_per_batch\":true,"
           "\"reset_control_not_subtracted\":true,\"lto\":false,\"transaction_trace_hooks\":false,"
           "\"strategy_dispatch\":\"shared volatile mode load and branch per valid instruction lookup\","
           "\"pair_order\":\"ABBA even rounds, BAAB odd rounds; reset before/after by round+scenario parity\","
           "\"final_snapshot_capture\":\"live final execute batch for each mode copied outside clocks; IO after all timed batches\","
           "\"legacy_block_fastpath\":\"NOT_INTEGRATED\",\"outer_callback_abi_invoked\":false,"
           "\"app_executions\":0,\"gpu_executions\":0,"
           "\"lookup_checks\":{\"contexts\":%" PRIu64 ",\"queries\":%" PRIu64 ",\"hits\":%" PRIu64 ",\"misses\":%" PRIu64 "},\"budget_checks\":[",
           measure?"PASS_CALLBACK_PAIR_MEASURE":"PASS_CALLBACK_PAIR_CHECK",measure?"measure":"check",module_base,
           sizeof(AotState),sizeof(AotContext),kProbeImageSize,STACK_SIZE,iterations,rounds,measure?WARMUP:0,
           timed+untimed,timed,untimed,reset_controls,resets,used*4,measure?2:0,
           wall_resolution,cpu_resolution,sizeof(AotState)+sizeof(AotContext)+kProbeImageSize+STACK_SIZE,
           lookup.contexts,lookup.queries,lookup.hits,lookup.misses);
    for(unsigned i=0;i<budget_used;i++) {
        BudgetCheck *b=budget_checks+i;AotFault *f=&b->result.fault;
        printf("%s{\"scenario\":%u,\"budget\":%u,\"status\":%u,\"steps\":%" PRIu64 ","
               "\"returned\":%u,\"call_depth\":%u,\"checksum\":%" PRIu64 ","
               "\"fault\":{\"status\":%u,\"access\":%u,\"pc\":%" PRIu64 ",\"address\":%" PRIu64 ",\"width\":%" PRIu64 "},"
               "\"full_state_context_image_stack_equal\":true}",
               i?",":"",b->scenario,b->budget,b->status,b->result.steps,b->result.returned,b->result.call_depth,b->checksum,
               f->status,f->access,f->pc,f->address,f->width);
    }
    printf("],\"cases\":[");
    for(unsigned i=0;i<CASES;i++)for(unsigned mode=0;mode<2;mode++) {
        Snapshot *s=expected+i;
        printf("%s{\"lookup_mode\":\"%s\",\"initial_position\":%u,\"position\":%u,\"moves\":%u,\"draws\":%u,"
               "\"keydowns\":%u,\"dirty\":%u,\"status\":0,\"returned\":%u,\"call_depth\":%u,"
               "\"steps\":%" PRIu64 ",\"switch_commits\":%" PRIu64 ",\"rejected_api_calls\":0,"
               "\"response\":\"case-%s-%u.bin\",\"checksum\":%" PRIu64 ",\"reset_checksum\":%" PRIu64,
               (i || mode)?",":"",mode_name(mode),i,get32(s->image+kProbeStateRva+8),get32(s->image+kProbeStateRva+12),
               get32(s->image+kProbeStateRva+16),get32(s->image+kProbeResultRva+12),get32(s->image+kProbeResultRva+56),
               s->context.result.returned,s->context.result.call_depth,s->context.result.steps,s->context.switch_commits,
               mode_name(mode),i,s->checksum,reset_expected[i].checksum);
        if(measure)printf(",\"timed_final_response\":\"final-case-%s-%u.bin\"}",mode_name(mode),i);
        else printf(",\"timed_final_response\":null}");
    }
    printf("],\"records\":[");
    for(unsigned i=0;i<used;i++) {
        Measurement *m=measurements+i;const Snapshot *s=m->path?reset_expected+m->scenario:expected+m->scenario;
        printf("%s{\"round\":%u,\"scenario\":%u,\"order_slot\":%u,\"lookup_mode\":\"%s\",\"path\":\"%s\",\"iterations\":%u,"
               "\"wall_ns\":%" PRIu64 ",\"thread_cpu_ns\":%" PRIu64 ",\"checksum\":%" PRIu64 ","
               "\"steps_per_iteration\":%" PRIu64 ",\"switch_commits_per_iteration\":%" PRIu64 ","
               "\"rejected_api_calls\":0,\"complete_post_batch_match\":true}",
               i?",":"",m->round,m->scenario,m->order_slot,m->path?"none":mode_name(m->mode),m->path?"reset":"execute",iterations,
               m->wall_ns,m->cpu_ns,m->checksum,s->context.result.steps,s->context.switch_commits);
    }
    puts("]}");
    for(unsigned i=0;i<CASES;i++) {
        free(expected[i].image);free(expected[i].stack);free(reset_expected[i].image);free(reset_expected[i].stack);
        if(measure)for(unsigned mode=0;mode<2;mode++){free(final[mode][i].image);free(final[mode][i].stack);}
    }
    aot_context_destroy(live_context);aot_state_destroy(live_state);
    free(original);free(live_image);free(initial_image);free(live_stack);free(initial_stack);free(permissions);free(original_permissions);
    return 0;
}

