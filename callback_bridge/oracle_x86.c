/* Original PE bytes execute on x86/Rosetta with actual typed ms_abi CALL/RET.
 * These host pointers exist only in this oracle, never in the ARM guest IAT. */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "oracle_image.h"

typedef uint64_t (__attribute__((ms_abi)) *GuestFunction)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
static unsigned char *mapped;
static uint64_t calls,callback_calls,depth,max_depth,callback_result,callback_rva;
static uint64_t observed[6],nested_observed[6];
static void fail(const char *message){fprintf(stderr,"oracle: %s\n",message);exit(2);}

__attribute__((ms_abi,noinline)) static uint64_t oracle_six(
    uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f) {
    calls++;nested_observed[0]=a;nested_observed[1]=b;nested_observed[2]=c;
    nested_observed[3]=d;nested_observed[4]=e;nested_observed[5]=f;
    return a+3*b+5*c+7*d+11*e+13*f;
}

__attribute__((ms_abi,noinline)) static uint64_t oracle_invoke(GuestFunction callback,
    uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f) {
    if((uintptr_t)callback!=(uintptr_t)(mapped+kOracleCallbackRva))fail("unregistered callback pointer");
    calls++;callback_calls++;depth++;if(depth>max_depth)max_depth=depth;
    if(depth==1){observed[0]=a;observed[1]=b;observed[2]=c;observed[3]=d;observed[4]=e;observed[5]=f;}
    callback_rva=(uintptr_t)callback-(uintptr_t)mapped;
    callback_result=callback(a,b,c,d,e,f);depth--;
    return callback_result+23;
}

int main(void) {
    mapped=mmap(NULL,sizeof kOracleImage,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(mapped==MAP_FAILED)fail("mmap failed");
    memcpy(mapped,kOracleImage,sizeof kOracleImage);
    uintptr_t invoke=(uintptr_t)&oracle_invoke,six=(uintptr_t)&oracle_six;
    memcpy(mapped+kOracleInvokeIat,&invoke,8);
    if(kOracleSixIat)memcpy(mapped+kOracleSixIat,&six,8);
    if(mprotect(mapped,sizeof kOracleImage,PROT_READ|PROT_EXEC))fail("W-to-X protection failed");
    GuestFunction entry=(GuestFunction)(mapped+kOracleEntryRva);uint64_t args[6];
    while(scanf("%" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64,
        &args[0],&args[1],&args[2],&args[3],&args[4],&args[5])==6) {
        calls=callback_calls=depth=max_depth=callback_result=callback_rva=0;
        memset(observed,0,sizeof observed);memset(nested_observed,0,sizeof nested_observed);
        uint64_t result=entry(args[0],args[1],args[2],args[3],args[4],args[5]);
        if(depth)fail("callback depth did not unwind");
        if(memcmp(mapped+kOracleEntryRva,kOracleImage+kOracleEntryRva,kOracleTextSize))fail("original PE text changed");
        printf("%016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64,
               result,calls,callback_calls,max_depth,callback_result,callback_rva);
        for(unsigned i=0;i<6;i++)printf(" %016" PRIx64,observed[i]);
        for(unsigned i=0;i<6;i++)printf(" %016" PRIx64,nested_observed[i]);putchar('\n');
    }
    if(ferror(stdin)||fflush(stdout))fail("stream failure");
    if(munmap(mapped,sizeof kOracleImage))fail("munmap failed");return 0;
}
