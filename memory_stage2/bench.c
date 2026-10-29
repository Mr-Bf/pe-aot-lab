#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "guest_memory.h"
#if BENCH_MODE==3
__attribute__((ms_abi)) uint32_t guest_entry(const uint8_t *,uint32_t);
#elif BENCH_MODE==2
uint32_t native_kernel(uint8_t *,uint32_t);
#else
GuestResult guest_checked(GuestMemory *,uint64_t,uint32_t);
GuestResult guest_fast(GuestMemory *,uint64_t,uint32_t);
#endif
static uint64_t now(void) {struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
int main(int argc,char **argv) {
 uint32_t count=argc>1?(uint32_t)strtoul(argv[1],0,0):4096;
 uint32_t rounds=argc>2?(uint32_t)strtoul(argv[2],0,0):3000;
 if(!count || count>65536 || !rounds || rounds>100000)return 2;
 size_t size=(size_t)count*4+1,pages=(size+4095)/4096;
 uint8_t *data=malloc(size),*perms=malloc(pages);if(!data||!perms)return 3;
 memset(perms,3,pages);uint32_t seed=20261027;
 for(size_t i=0;i<size;i++){seed=seed*1664525u+1013904223u;data[i]=(uint8_t)(seed>>24);}
 GuestMemory memory={0x170000000,size,data,perms,pages};
 uint64_t checksum=0,start=now();
 for(uint32_t i=0;i<rounds;i++) {
#if BENCH_MODE==3
  checksum+=guest_entry(data+1,count);
#elif BENCH_MODE==2
  checksum+=native_kernel(data+1,count);
#else
  GuestResult r;
#if BENCH_MODE==0
  r=guest_checked(&memory,memory.base+1,count);
#else
  r=guest_fast(&memory,memory.base+1,count);
#endif
  if(r.status)return 4;checksum+=r.result;
#endif
 }
 uint64_t elapsed=now()-start,hash=1469598103934665603ull;
 for(size_t i=0;i<size;i++){hash^=data[i];hash*=1099511628211ull;}
 printf("{\"elapsed_ns\":%llu,\"elements\":%llu,\"checksum\":%llu,\"buffer_hash\":\"%016llx\"}\n",(unsigned long long)elapsed,(unsigned long long)count*rounds,(unsigned long long)checksum,(unsigned long long)hash);
 free(data);free(perms);return 0;
}
