#include "runtime.h"
#include "sanitizer-fixture.h"
#include <stdio.h>
#include <string.h>

extern void *aot_entry(void *,uint64_t,void *);
static uint32_t random32(uint32_t *s) { *s=*s*1664525u+1013904223u;return *s; }
static uint32_t access_status(uint64_t base,uint64_t address,const uint8_t *perms,unsigned access) {
    if(address<base || address-base>8192-4)return AOT_BOUNDS;
    size_t off=(size_t)(address-base);
    for(size_t i=off/4096;i<=(off+3)/4096;i++)if((perms[i]&access)!=access)return AOT_PROTECTION;
    return AOT_OK;
}
int main(void) {
    uint32_t seed=20261028;unsigned statuses[11]={0};
    for(unsigned test=0;test<2000;test++) {
        uint8_t data[8192],expected[8192],stack[4096]={0};
        uint8_t perms[2]={(uint8_t)((random32(&seed)>>16)%4),(uint8_t)((random32(&seed)>>16)%4)};
        uint8_t stack_perm[1]={(test%11==0)?0:3};
        for(unsigned i=0;i<sizeof(data);i++)data[i]=(uint8_t)(random32(&seed)>>24);
        memcpy(expected,data,sizeof data);
        uint64_t base=UINT64_C(0x500000000)+(uint64_t)test*0x10000;
        uint64_t address=base+random32(&seed)%8200;
        if(test%17==0)address=UINT64_MAX-2;
        uint32_t count=random32(&seed)%129,remaining=count,accumulator=0,error=0;
        uint64_t pointer=address,fault_pc=0,fault_address=0,width=0;unsigned access=0;
        uint64_t stack_base=UINT64_C(0x70000000),rsp=stack_base+4040;
        uint64_t return_pc=test%13==0?UINT64_C(0xdeadbeef):EXIT_PC;
        memcpy(stack+4040,&return_pc,8);
        while(remaining) {
            error=access_status(base,pointer,perms,GM_READ);
            if(error){fault_pc=LOAD_PC;fault_address=pointer;width=4;access=GM_READ;break;}
            uint32_t word;memcpy(&word,expected+(size_t)(pointer-base),4);
            accumulator^=word;accumulator=(accumulator<<5)|(accumulator>>27);
            error=access_status(base,pointer,perms,GM_WRITE);
            if(error){fault_pc=STORE_PC;fault_address=pointer;width=4;access=GM_WRITE;break;}
            memcpy(expected+(size_t)(pointer-base),&accumulator,4);
            pointer+=4;remaining--;
        }
        if(!error && !stack_perm[0]) {
            error=AOT_PROTECTION;fault_pc=RET_PC;fault_address=rsp;width=8;access=GM_READ;
        }
        if(!error && return_pc!=EXIT_PC) {
            error=AOT_BAD_RETURN;fault_pc=RET_PC;fault_address=return_pc;width=0;access=AOT_EXEC;
        }
        AotState *state=aot_state_create();
        AotContext *ctx=aot_context_create(IMAGE_BASE,instructions,
            sizeof(instructions)/sizeof(instructions[0]),10000,EXIT_PC,rsp);
        GuestMemory image={IMAGE_BASE,sizeof(image_bytes),image_bytes,image_permissions,sizeof(image_permissions)};
        GuestMemory memory={base,sizeof(data),data,perms,2};
        GuestMemory stack_map={stack_base,sizeof(stack),stack,stack_perm,1};
        if(!state || !ctx || aot_add_region(ctx,&image) || aot_add_region(ctx,&memory) || aot_add_region(ctx,&stack_map))return 2;
        aot_set_register(state,AOT_RSP,rsp);aot_set_register(state,AOT_RCX,address);aot_set_register(state,AOT_RDX,count);
        uint32_t actual=aot_execute(aot_entry,state,ctx,IMAGE_BASE+ENTRY_RVA);
        AotResult result;aot_result(ctx,&result);
        if(actual!=error || result.returned!=(error==0) ||
           aot_get_register(state,AOT_RAX)!=accumulator ||
           aot_get_register(state,AOT_RCX)!=pointer || aot_get_register(state,AOT_RDX)!=remaining ||
           aot_get_register(state,AOT_RSP)!=(error?rsp:rsp+8) ||
           aot_get_register(state,AOT_RIP)!=(error?fault_pc:EXIT_PC) ||
           result.fault.pc!=fault_pc || result.fault.address!=fault_address ||
           result.fault.width!=width || result.fault.access!=access || memcmp(data,expected,sizeof data)) {
            fprintf(stderr,"mismatch test=%u status=%u expected=%u pc=%llx expected_pc=%llx\n",
                test,actual,error,(unsigned long long)result.fault.pc,(unsigned long long)fault_pc);return 3;
        }
        aot_context_destroy(ctx);aot_state_destroy(state);
        statuses[actual]++;
    }
    if(!statuses[0] || !statuses[1] || !statuses[2] || !statuses[5])return 4;
    printf("{\"status\":\"PASS\",\"cases\":2000,\"outcomes\":{\"returned\":%u,\"bounds\":%u,\"protection\":%u,\"bad_return\":%u}}\n",
           statuses[0],statuses[1],statuses[2],statuses[5]);return 0;
}
