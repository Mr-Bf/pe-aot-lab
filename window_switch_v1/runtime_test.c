/* Tests the real window transaction engine plus versioned include hooks.
 * C bodies below model instruction effects; these are NOT translated PE or
 * D3D/COM integration tests. API dispatch validators remain rejecting stubs. */
#include "../window_bridge/window_runtime/runtime.h"
#ifdef AOT_WINDOW_SWITCH_V1
#include "runtime.h"
#endif
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static bool d3d_validate_call(AotState *s,AotContext *ctx,uint64_t pc) {
    (void)s;(void)ctx;(void)pc;return false;
}
static bool import_validate_call(AotState *s,AotContext *ctx,uint64_t pc) {
    (void)s;(void)ctx;(void)pc;return false;
}
#include "../window_bridge/window_runtime/transaction_v1.c"

#define BASE UINT64_C(0x140000000)
#define STACK UINT64_C(0x70000000)
#define EXIT UINT64_C(0x7fff00000000)
#define PC(rva) (BASE+(rva))
#define RSP (STACK+GM_PAGE-16)
static unsigned checks;
#define CHECK(value) do { checks++;if(!(value)) { \
    fprintf(stderr,"FAIL line %u: %s\n",__LINE__,#value);exit(1); } } while(0)

typedef struct {
    uint8_t image[GM_PAGE*3],stack[GM_PAGE],permissions[3],stack_permissions[1];
    uint8_t expected[8];
    uint64_t targets[2];
    AotContext *ctx;AotState *state;
} Fixture;

static const AotInstruction code[]={
    {0x1000,5,AOT_CALL,0,0x1100},{0x1005,1,AOT_RET,0,0},
    {0x1100,2,5,0,0},{0x1110,1,AOT_RET,0,0},{0x1120,1,AOT_RET,0,0},
};

static void *one_return(void *opaque,uint64_t pc,void *context) {
    AotState *s=opaque;AotContext *ctx=context;
    if(aot_begin(s,pc,ctx))return ctx;
    uint64_t rsp=aot_get_register(s,AOT_RSP);
    uint64_t next=__remill_read_memory_64(ctx,rsp);
    aot_set_register(s,AOT_RSP,rsp+8);
    aot_commit(s,next,ctx);return ctx;
}

static void put64(uint8_t *p,uint64_t value){memcpy(p,&value,8);}

static Fixture *fixture(uint64_t budget,const AotInstruction *instructions,size_t count) {
    Fixture *f=calloc(1,sizeof *f);CHECK(f!=NULL);
    f->state=aot_state_create();CHECK(f->state!=NULL);
    f->ctx=aot_context_create(BASE,instructions,count,budget,EXIT,RSP);CHECK(f->ctx!=NULL);
    f->permissions[0]=GM_READ;f->permissions[1]=GM_READ|AOT_EXEC;f->permissions[2]=GM_READ;
    f->stack_permissions[0]=GM_READ|GM_WRITE;
    f->targets[0]=PC(0x1110);f->targets[1]=PC(0x1120);
    for(unsigned i=0;i<2;i++) {
        int32_t rel=(int32_t)(f->targets[i]-PC(0x2000));
        memcpy(f->expected+4*i,&rel,4);
    }
    memcpy(f->image+0x2000,f->expected,sizeof f->expected);
    put64(f->stack+GM_PAGE-16,EXIT);aot_set_register(f->state,AOT_RSP,RSP);
    GuestMemory image={BASE,sizeof f->image,f->image,f->permissions,3};
    GuestMemory stack={STACK,sizeof f->stack,f->stack,f->stack_permissions,1};
    CHECK(aot_add_region(f->ctx,&image)==AOT_OK);
    CHECK(aot_add_region(f->ctx,&stack)==AOT_OK);
    return f;
}

static void dispose(Fixture *f) {
    aot_context_destroy(f->ctx);aot_state_destroy(f->state);free(f);
}

#ifdef AOT_WINDOW_SWITCH_V1
static Fixture *ready(uint64_t budget) {
    Fixture *f=fixture(budget,code,sizeof code/sizeof *code);
    CHECK(aot_configure_switch(f->ctx,PC(0x1100),f->targets,2)==AOT_OK);
    CHECK(aot_bind_switch(f->ctx,PC(0x2000),f->expected,sizeof f->expected)==AOT_OK);
    CHECK(aot_window_switch_commits(f->ctx)==0);
    return f;
}

static unsigned entered;
static void *entry_count(void *state,uint64_t pc,void *ctx) {
    (void)state;(void)pc;entered++;return ctx;
}

static void *call_switch_return(void *opaque,uint64_t pc,void *context) {
    AotState *s=opaque;AotContext *ctx=context;
    if(aot_begin(s,pc,ctx))return ctx;
    uint64_t rsp=aot_get_register(s,AOT_RSP);
    __remill_write_memory_64(ctx,rsp-8,pc+5);aot_set_register(s,AOT_RSP,rsp-8);
    if(aot_commit(s,PC(0x1100),ctx))return ctx;
    CHECK(ctx->result.call_depth==1);
    if(aot_begin(s,PC(0x1100),ctx))return ctx;
    if(aot_commit(s,PC(0x1110),ctx))return ctx;
    CHECK(ctx->result.call_depth==1);
    CHECK(aot_window_switch_commits(ctx)==1);
    one_return(s,PC(0x1110),ctx);
    if(aot_should_exit(ctx))return ctx;
    CHECK(ctx->result.call_depth==0);
    return one_return(s,PC(0x1005),ctx);
}

static void test_normal_nested_call(void) {
    Fixture *f=ready(4);
    CHECK(aot_execute(call_switch_return,f->state,f->ctx,PC(0x1000))==AOT_OK);
    CHECK(f->ctx->result.returned==1 && f->ctx->result.call_depth==0);
    CHECK(f->ctx->result.steps==4 && aot_window_switch_commits(f->ctx)==1);
    CHECK(aot_get_register(f->state,AOT_RIP)==EXIT);
    CHECK(aot_get_register(f->state,AOT_RSP)==RSP+8);
    CHECK(aot_execute(entry_count,f->state,f->ctx,PC(0x1000))==AOT_INVALID);
    dispose(f);
}

static void test_missing_and_bad_binding(void) {
    for(unsigned test=0;test<14;test++) {
        Fixture *f=fixture(4,code,sizeof code/sizeof *code);
        uint64_t table=PC(0x2000);size_t size=8;const uint8_t *expected=f->expected;
        if(test==6) {uint64_t swap=f->targets[0];f->targets[0]=f->targets[1];f->targets[1]=swap;}
        if(test!=0)CHECK(aot_configure_switch(f->ctx,PC(0x1100),f->targets,2)==AOT_OK);
        uint32_t want=AOT_BAD_INSTRUCTION;
        switch(test) {
        case 0:want=AOT_INVALID;break;
        case 1:f->image[0x2000]^=1;break;
        case 2:f->expected[0]^=1;break;
        case 3:f->permissions[2]=GM_READ|GM_WRITE;want=AOT_PROTECTION;break;
        case 4:f->permissions[2]=GM_READ|AOT_EXEC;want=AOT_PROTECTION;break;
        case 5:f->permissions[2]=0;want=AOT_PROTECTION;break;
        case 6:break; /* configured valid targets in the wrong table order */
        case 7:table++;want=AOT_INVALID;break;
        case 8:size--;want=AOT_INVALID;break;
        case 9:expected=NULL;want=AOT_INVALID;break;
        case 10:table=PC(0x3000);want=AOT_BOUNDS;break;
        case 11:table=UINT64_MAX-3;want=AOT_INVALID;break;
        case 12:CHECK(aot_bind_switch(f->ctx,table,expected,size)==AOT_OK);want=AOT_INVALID;break;
        case 13:table=PC(0x2ffc);f->permissions[2]=0;want=AOT_BOUNDS;break;
        }
        CHECK(aot_bind_switch(f->ctx,table,expected,size)==want);
        CHECK(f->ctx->result.fault.status==want);
        CHECK(aot_bind_switch(f->ctx,PC(0x2000),f->expected,8)==AOT_INVALID);
        CHECK(f->ctx->result.fault.status==want); /* preserve the first fault */
        uint8_t bytes[GM_PAGE]={0},rights[1]={GM_READ};
        GuestMemory extra={UINT64_C(0x90000000),GM_PAGE,bytes,rights,1};
        CHECK(aot_add_region(f->ctx,&extra)==AOT_INVALID);
        entered=0;
        CHECK(aot_execute(entry_count,f->state,f->ctx,PC(0x1000))==AOT_INVALID);
        CHECK(entered==0 && f->ctx->result.steps==0 && aot_window_switch_commits(f->ctx)==0);
        dispose(f);
    }
    Fixture *f=fixture(4,code,sizeof code/sizeof *code);
    CHECK(aot_configure_switch(f->ctx,PC(0x1100),f->targets,2)==AOT_OK);
    entered=0;CHECK(aot_execute(entry_count,f->state,f->ctx,PC(0x1000))==AOT_INVALID);
    CHECK(entered==0 && f->ctx->result.steps==0);
    CHECK(aot_begin(f->state,PC(0x1100),f->ctx)==1 && f->ctx->result.steps==0);
    dispose(f);
}

static void test_table_extent_and_mapping_edges(void) {
    const unsigned counts[]={2,8,31,32};
    for(unsigned c=0;c<sizeof counts/sizeof *counts;c++) {
        Fixture *f=fixture(4,code,sizeof code/sizeof *code);
        uint64_t targets[32];uint8_t expected[128];
        for(unsigned i=0;i<counts[c];i++) {
            targets[i]=f->targets[i%2];int32_t rel=(int32_t)(targets[i]-PC(0x2000));
            memcpy(expected+4*i,&rel,4);
        }
        memcpy(f->image+0x2000,expected,counts[c]*4);
        CHECK(aot_configure_switch(f->ctx,PC(0x1100),targets,counts[c])==AOT_OK);
        CHECK(aot_bind_switch(f->ctx,PC(0x2000),expected,counts[c]*4)==AOT_OK);
        CHECK(aot_window_switch_commits(f->ctx)==0);dispose(f);
    }
    /* Positive rel32 values take a separate arithmetic branch: place the
     * table in an earlier read-only page instead of before/inside code. */
    Fixture *positive=fixture(4,code,sizeof code/sizeof *code);
    for(unsigned i=0;i<2;i++) {
        int32_t rel=(int32_t)(positive->targets[i]-PC(0x80));
        memcpy(positive->expected+4*i,&rel,4);
    }
    memcpy(positive->image+0x80,positive->expected,8);
    CHECK(aot_configure_switch(positive->ctx,PC(0x1100),positive->targets,2)==AOT_OK);
    CHECK(aot_bind_switch(positive->ctx,PC(0x80),positive->expected,8)==AOT_OK);
    dispose(positive);
    /* An eight-byte table can span two adjacent guest mappings with unrelated
     * host allocations. The table base, not each element address, anchors rel32. */
    Fixture *f=fixture(4,code,sizeof code/sizeof *code);
    uint8_t tail[4],rights[1]={GM_READ},expected[8];
    for(unsigned i=0;i<2;i++) {
        int32_t rel=(int32_t)(f->targets[i]-PC(0x2ffc));memcpy(expected+4*i,&rel,4);
    }
    memcpy(f->image+0x2ffc,expected,4);memcpy(tail,expected+4,4);
    GuestMemory next={PC(0x3000),4,tail,rights,1};
    CHECK(aot_add_region(f->ctx,&next)==AOT_OK);
    CHECK(aot_configure_switch(f->ctx,PC(0x1100),f->targets,2)==AOT_OK);
    CHECK(aot_bind_switch(f->ctx,PC(0x2ffc),expected,8)==AOT_OK);
    dispose(f);
}

static void test_configure(void) {
    Fixture *f=fixture(4,code,sizeof code/sizeof *code);
    CHECK(aot_configure_switch(f->ctx,PC(0x1100),f->targets,1)==AOT_INVALID);
    CHECK(aot_configure_switch(f->ctx,PC(0x1100),f->targets,33)==AOT_INVALID);
    CHECK(aot_configure_switch(f->ctx,PC(0x1100),NULL,2)==AOT_INVALID);
    CHECK(aot_configure_switch(f->ctx,PC(0x1000),f->targets,2)==AOT_INVALID);
    f->targets[0]++;
    CHECK(aot_configure_switch(f->ctx,PC(0x1100),f->targets,2)==AOT_INVALID);
    f->targets[0]--;
    CHECK(aot_configure_switch(f->ctx,PC(0x1100),f->targets,2)==AOT_OK);
    CHECK(aot_configure_switch(f->ctx,PC(0x1100),f->targets,2)==AOT_INVALID);
    dispose(f);
    AotInstruction two[sizeof code/sizeof *code];memcpy(two,code,sizeof two);two[4].kind=5;
    f=fixture(4,two,sizeof two/sizeof *two);
    CHECK(aot_configure_switch(f->ctx,PC(0x1100),f->targets,2)==AOT_INVALID);dispose(f);
    f=fixture(4,code,sizeof code/sizeof *code);
    f->targets[1]=f->targets[0];memcpy(f->expected+4,f->expected,4);memcpy(f->image+0x2000,f->expected,8);
    CHECK(aot_configure_switch(f->ctx,PC(0x1100),f->targets,2)==AOT_OK);
    CHECK(aot_bind_switch(f->ctx,PC(0x2000),f->expected,8)==AOT_OK);dispose(f);
}

static void test_commit_rollback(void) {
    for(unsigned test=0;test<5;test++) {
        Fixture *f=ready(2);AotState before;
        CHECK(aot_begin(f->state,PC(0x1100),f->ctx)==0);
        memcpy(&before,f->state,sizeof before);
        aot_set_register(f->state,AOT_RAX,123);
        uint64_t next=f->targets[0];
        switch(test) {
        case 0:next=PC(0x1121);break;
        case 1:aot_set_register(f->state,AOT_RSP,RSP-8);break;
        case 2:__remill_write_memory_64(f->ctx,STACK,9);break;
        case 3:f->ctx->switch_pc++;break; /* host metadata fault injection */
        case 4:aot_switch_miss(f->state,next,f->ctx);break;
        }
        CHECK(aot_commit(f->state,next,f->ctx)==1);
        CHECK(f->ctx->result.fault.status==AOT_BAD_INSTRUCTION);
        CHECK(memcmp(&before,f->state,sizeof before)==0 && f->stack[0]==0);
        CHECK(f->ctx->result.call_depth==0 && f->ctx->in_instruction==0 && f->ctx->pending_size==0);
        CHECK(aot_window_switch_commits(f->ctx)==0);
        dispose(f);
    }
    Fixture *f=ready(1);
    CHECK(aot_begin(f->state,PC(0x1100),f->ctx)==0);
    CHECK(aot_commit(f->state,f->targets[0],f->ctx)==0);
    CHECK(aot_window_switch_commits(f->ctx)==1);
    CHECK(aot_begin(f->state,PC(0x1100),f->ctx)==1);
    CHECK(f->ctx->result.fault.status==AOT_BUDGET && aot_window_switch_commits(f->ctx)==1);
    dispose(f);
    for(unsigned budget=1;budget<4;budget++) {
        f=ready(budget);
        CHECK(aot_execute(call_switch_return,f->state,f->ctx,PC(0x1000))==AOT_BUDGET);
        CHECK(f->ctx->result.steps==budget && aot_window_switch_commits(f->ctx)==(budget>=2));
        CHECK(f->ctx->result.call_depth==(budget<3));dispose(f);
    }
}

int main(void) {
    test_normal_nested_call();test_missing_and_bad_binding();test_configure();
    test_table_extent_and_mapping_edges();test_commit_rollback();
    CHECK(aot_window_switch_commits(NULL)==0);
    printf("{\"status\":\"PASS\",\"contract\":\"window-switch-v1-transaction-only\",\"checks\":%u,\"bad_bindings\":14,\"translated_PE_executions\":0,\"gpu_executions\":0}\n",checks);
    return 0;
}
#else
int main(void) {
    CHECK(aot_context_create(BASE,code,sizeof code/sizeof *code,4,EXIT,RSP)==NULL);
    const AotInstruction ret={0x1000,1,AOT_RET,0,0};
    Fixture *f=fixture(1,&ret,1);
    CHECK(aot_execute(one_return,f->state,f->ctx,PC(0x1000))==AOT_OK);
    CHECK(f->ctx->result.returned==1 && f->ctx->result.steps==1);
    CHECK(aot_get_register(f->state,AOT_RIP)==EXIT);
    dispose(f);
    printf("{\"status\":\"PASS\",\"contract\":\"legacy-kind5-rejected\",\"checks\":%u,\"translated_PE_executions\":0,\"gpu_executions\":0}\n",checks);
    return 0;
}
#endif
