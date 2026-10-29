/* Actual no-argument guest PE. Host termination is a recorded outcome, never
 * exit(guest_code), synthetic RET, or a reason to erase guest call frames. */
#include "runtime.c"
#include <inttypes.h>
#include <stdio.h>
#include "sanitizer_fixture.h"
extern void *aot_entry(void *,uint64_t,void *);
static const uint64_t STACK_BASE=0x70000000,EXIT_PC=UINT64_C(0x7fff00000000);
enum {STACK_SIZE=65536};
static const char *directory;
static unsigned current_case,terminal_checks,reentry_checks,budget_cases;
static void failed(const char *text,unsigned line){fprintf(stderr,"process sanitizer variant=%u case=%u line=%u: %s\n",kVariant,current_case,line,text);exit(2);}
#define CHECK(x) do {if(!(x))failed(#x,__LINE__);}while(0)
static uint64_t random64(uint64_t *s){uint64_t v=*s;v^=v<<13;v^=v>>7;v^=v<<17;return *s=v;}
static void put64(uint8_t *p,uint64_t v){memcpy(p,&v,8);}
static uint32_t get32(const uint8_t *p){uint32_t v;memcpy(&v,p,4);return v;}
typedef struct {AotState *state;AotContext *ctx;AotResult result;uint8_t *image,*stack,*thunks;
    uint8_t permissions[sizeof kImagePermissions],stack_permissions[16],thunk_permission;
    uint64_t base,rsp,initial_rax;} Case;
static void path(char out[4096]){CHECK(snprintf(out,4096,"%s/process-save.bin",directory)>0);}
static void remove_file(void){char name[4096];path(name);CHECK(unlink(name)==0 || errno==ENOENT);}
static Case *make_case(uint64_t budget,uint64_t seed,unsigned variant) {
    Case *c=calloc(1,sizeof *c);CHECK(c);c->state=aot_state_create();c->image=malloc(sizeof kImage);c->stack=malloc(STACK_SIZE);
    c->thunks=calloc(kThunkCount?kThunkCount:1,4096);CHECK(c->state && c->image && c->stack && c->thunks);
    c->base=kPreferredBase+(seed%4)*UINT64_C(0x100000);c->rsp=STACK_BASE+(variant?0x1028:0xf008);
    for(unsigned i=0;i<AOT_STATE_SIZE;i++)c->state->bytes[i]=(uint8_t)random64(&seed);
    for(unsigned i=0;i<17;i++)aot_set_register(c->state,i,random64(&seed));
    c->initial_rax=aot_get_register(c->state,AOT_RAX);c->state->bytes[2075]=0;aot_set_register(c->state,AOT_RSP,c->rsp);
    memcpy(c->image,kImage,sizeof kImage);memcpy(c->permissions,kImagePermissions,sizeof kImagePermissions);
    for(unsigned i=0;i<kRelocCount;i++)put64(c->image+kRelocRvas[i],kRelocOld[i]+c->base-kPreferredBase);
    for(unsigned i=0;i<kImportCount;i++)put64(c->image+kIatRvas[i],c->base+kImportTargets[i]);
    memset(c->stack,0xa5,STACK_SIZE);put64(c->stack+c->rsp-STACK_BASE,EXIT_PC);
    memset(c->stack_permissions,GM_READ|GM_WRITE,sizeof c->stack_permissions);
    if(variant==1 || variant==2)c->stack_permissions[0]=GM_WRITE;
    if(variant==2)c->stack_permissions[1]=GM_READ;
    c->thunk_permission=GM_READ|AOT_EXEC;
    c->ctx=aot_context_create(c->base,kInstructions,sizeof kInstructions/sizeof kInstructions[0],budget,EXIT_PC,c->rsp);CHECK(c->ctx);
    GuestMemory image={c->base,sizeof kImage,c->image,c->permissions,sizeof c->permissions};CHECK(aot_add_region(c->ctx,&image)==AOT_OK);
    GuestMemory stack={STACK_BASE,STACK_SIZE,c->stack,c->stack_permissions,16};CHECK(aot_add_region(c->ctx,&stack)==AOT_OK);
    for(unsigned i=0;i<kThunkCount;i++){c->thunks[i*4096]=0xc3;GuestMemory thunk={c->base+kThunks[i],4096,c->thunks+i*4096,&c->thunk_permission,1};CHECK(aot_add_region(c->ctx,&thunk)==AOT_OK);}
    return c;
}
static void destroy(Case *c){aot_state_destroy(c->state);aot_context_destroy(c->ctx);free(c->image);free(c->stack);free(c->thunks);free(c);}
static void check_terminal(Case *c) {
    AotState state=*c->state;AotContext context=*c->ctx;FileSession prior=session;
    CHECK(aot_should_exit(c->ctx));CHECK(aot_begin(c->state,UINT64_C(0xbad0000),c->ctx)==1);
    CHECK(aot_commit(c->state,UINT64_C(0xbad0008),c->ctx)==1);
    CHECK(__remill_function_call(c->state,UINT64_C(0xbad0010),c->ctx)==c->ctx);
    CHECK(!memcmp(c->state,&state,sizeof state) && !memcmp(c->ctx,&context,sizeof context) && !memcmp(&session,&prior,sizeof session));terminal_checks++;
}
static void *audited_entry(void *state,uint64_t pc,void *opaque) {
    void *result=aot_entry(state,pc,opaque);AotState saved=*(AotState*)state;AotContext prior=*(AotContext*)opaque;FileSession stats=session;
    CHECK(aot_execute(aot_entry,state,opaque,pc)==AOT_INVALID);CHECK(aot_file_session_begin(directory)==W_INVALID_PARAMETER);
    CHECK(aot_file_session_end()==0 && !memcmp(&session,&stats,sizeof stats));
    CHECK(!memcmp(state,&saved,sizeof saved) && !memcmp(opaque,&prior,sizeof prior));reentry_checks++;return result;
}
static uint32_t execute(Case *c) {
    remove_file();CHECK(aot_file_session_begin(directory)==0);
    CHECK(!aot_process_exit_requested() && !aot_process_exit_code() && !aot_process_exit_pc() && !aot_process_exit_depth());
    uint32_t status=aot_execute(audited_entry,c->state,c->ctx,c->base+kEntryRva);aot_result(c->ctx,&c->result);
    CHECK(!session.running);return status;
}
static void disk(Case *c) {
    char name[4096];path(name);
    if(kVariant<=3){int fd=open(name,O_RDONLY);CHECK(fd>=0);struct stat st;CHECK(fstat(fd,&st)==0 && st.st_size==kSourceLength);
        uint8_t *bytes=malloc(kSourceLength);CHECK(bytes);CHECK(read(fd,bytes,kSourceLength)==(ssize_t)kSourceLength);
        CHECK(!memcmp(bytes,c->image+kSourceRva,kSourceLength));free(bytes);CHECK(close(fd)==0);
    } else CHECK(access(name,F_OK)!=0 && errno==ENOENT);
}
static void committed_io(Case *c) {
    char name[4096];path(name);
    if(!aot_file_api_calls(4)) {CHECK(access(name,F_OK)!=0 && errno==ENOENT);return;}
    if(aot_file_api_calls(5)) {disk(c);return;}
    struct stat st;CHECK(stat(name,&st)==0 && st.st_size==0);
}
static void cleanup(Case *c) {
    uint32_t opened=aot_file_open_handles(),error=aot_file_last_error();uint64_t closes=aot_file_api_calls(7);FileSession stats=session;
    CHECK(aot_file_session_end()==opened && aot_file_open_handles()==0 && aot_file_cleanup_errors()==0);
    CHECK(aot_file_api_calls(7)==closes && aot_file_last_error()==error);
    CHECK(aot_process_exit_requested()==stats.exit_requested && aot_process_exit_pc()==stats.exit_pc && aot_process_exit_depth()==stats.exit_depth);
    CHECK(aot_execute(aot_entry,c->state,c->ctx,c->base+kEntryRva)==AOT_INVALID);
}
static uint64_t successful(uint64_t seed,unsigned variant) {
    Case *c=make_case(1000000,seed,variant);uint32_t status=execute(c);
    if(kVariant==4) {
        CHECK(status==AOT_OK && c->result.returned && !c->result.call_depth && !aot_process_exit_requested());
        CHECK(aot_get_register(c->state,AOT_RSP)==c->rsp+8 && aot_get_register(c->state,AOT_RIP)==EXIT_PC);
        CHECK(aot_bridge_api_calls()==0);
    } else {
        CHECK(status==AOT_PROCESS_EXITED && aot_process_exit_requested() && !c->result.returned && !c->result.fault.status);
        CHECK(aot_process_exit_code()==kExitCode && aot_file_api_calls(9)==1);
        CHECK(aot_process_exit_pc()==c->base+kExitThunk && aot_get_register(c->state,AOT_RIP)==aot_process_exit_pc());
        CHECK(aot_process_exit_rsp()==aot_get_register(c->state,AOT_RSP));
        CHECK(c->result.call_depth==(kVariant==3?2u:1u) && aot_process_exit_depth()==c->result.call_depth);
        CHECK(c->ctx->current && c->ctx->current->kind==AOT_CALL);
        ReturnFrame frame=c->ctx->frames[c->result.call_depth-1];
        CHECK(frame.rsp==aot_process_exit_rsp()+8 && frame.pc==c->base+c->ctx->current->rva+c->ctx->current->length);
        if(kVariant==5){CHECK(aot_get_register(c->state,AOT_RAX)==c->initial_rax);CHECK(aot_bridge_api_calls()==1);}
        if(kVariant<=3) {
            CHECK(get32(c->image+kResultRva)==(kVariant==1?8u:3u));CHECK(get32(c->image+kResultRva+4)==0);
            CHECK(get32(c->image+kResultRva+8)==kSourceLength && get32(c->image+kResultRva+12)==(kVariant==1?kSourceLength:0));
            CHECK(get32(c->image+kMarkerRva)==0 && get32(c->image+kCallerMarkerRva)==0);
            CHECK(aot_file_api_calls(5)==1 && aot_file_api_calls(7)==(kVariant==1?2u:0u));
            CHECK(aot_file_api_calls(4)==(kVariant==1?2u:1u) && aot_file_api_calls(6)==(kVariant==1?1u:0u));
            CHECK(aot_file_api_calls(8)==0 && aot_bridge_api_calls()==(kVariant==1?7u:3u));
            CHECK(aot_file_bytes_written()==kSourceLength && aot_file_bytes_read()==(kVariant==1?kSourceLength:0));
            CHECK(aot_file_open_handles()==(kVariant==1?0u:1u));
            if(kVariant==1)CHECK(!memcmp(c->image+kDestinationRva,c->image+kSourceRva,kSourceLength));
        }
        check_terminal(c);
    }
    disk(c);uint64_t steps=c->result.steps;cleanup(c);disk(c);destroy(c);return steps;
}
static void cut_budgets(uint64_t steps) {
    for(uint64_t budget=1;budget<=steps;budget++) {
        Case *c=make_case(budget,UINT64_C(0xbad123),0);uint32_t status=execute(c);
        CHECK(c->result.steps==budget);
        if(budget==steps) {
            CHECK(status==(kVariant==4?AOT_OK:AOT_PROCESS_EXITED));
            CHECK(aot_process_exit_requested()==(kVariant!=4));
            if(kVariant!=4)CHECK(aot_process_exit_code()==kExitCode && !c->result.returned && !c->result.fault.status);
        } else {
            CHECK(status==AOT_BUDGET && c->result.fault.status==AOT_BUDGET && !aot_process_exit_requested());
            CHECK(!c->result.returned && aot_file_api_calls(9)==0);budget_cases++;
        }
        if(kVariant<=3)CHECK(get32(c->image+kMarkerRva)==0 && get32(c->image+kCallerMarkerRva)==0);
        if(kVariant!=4 || budget<steps)check_terminal(c);
        committed_io(c);cleanup(c);committed_io(c);destroy(c);
    }
}
static void bad_exit_iat(void) {
    Case *c=make_case(1000000,UINT64_C(0xbad1a7),0);put64(c->image+kExitIat,c->base+kExitThunk+8);
    CHECK(execute(c)==AOT_BAD_INSTRUCTION && !aot_process_exit_requested() && !c->result.returned);
    CHECK(c->result.fault.status==AOT_BAD_INSTRUCTION && c->result.fault.address==c->base+kExitThunk+8 && aot_file_api_calls(9)==0);
    check_terminal(c);cleanup(c);destroy(c);
}
static void private_boundaries(void) {
    CHECK(kVariant==5);
    successful(UINT64_C(0x201),1); /* actual CALL writes its return slot on W-only page */
    Case *c=make_case(3,UINT64_C(0x202),2);
    CHECK(execute(c)==AOT_PROTECTION && !aot_process_exit_requested() && c->result.call_depth==1);
    CHECK(c->result.fault.address==STACK_BASE+4096 && c->result.fault.width==8 && c->result.fault.access==(GM_READ|GM_WRITE));
    check_terminal(c);cleanup(c);destroy(c);
    /* Same initial State: before the final CALL vs committed Exit. No files or
     * opaque handle tokens are involved; only real CALL RSP/RIP may differ. */
    Case *before=make_case(2,UINT64_C(0x203),0);CHECK(execute(before)==AOT_BUDGET);AotState expected=*before->state;cleanup(before);
    Case *after=make_case(3,UINT64_C(0x203),0);CHECK(execute(after)==AOT_PROCESS_EXITED);
    aot_set_register(&expected,AOT_RSP,aot_get_register(&expected,AOT_RSP)-8);
    aot_set_register(&expected,AOT_RIP,after->base+kExitThunk);CHECK(!memcmp(&expected,after->state,sizeof expected));
    check_terminal(after);cleanup(after);destroy(before);destroy(after);
}
int main(int argc,char **argv) {
    CHECK(argc==2);directory=argv[1];uint64_t steps=0;
    for(current_case=0;current_case<16;current_case++)steps=successful(UINT64_C(0x20261027)+current_case,0);
    cut_budgets(steps);if(kVariant!=4)bad_exit_iat();if(kVariant==5)private_boundaries();
    printf("{\"status\":\"PASS\",\"variant\":%u,\"normal_cases\":16,\"budget_cuts\":%u,"
           "\"exact_budget_success\":1,\"bad_exit_IAT\":%u,\"private_boundaries\":%u,"
           "\"terminal_no_mutation_checks\":%u,\"public_reentry_checks\":%u,\"success_steps\":%" PRIu64 "}\n",
           kVariant,budget_cases,kVariant!=4,kVariant==5?3:0,terminal_checks,reentry_checks,steps);
    return 0;
}
