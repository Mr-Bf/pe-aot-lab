#include <stdio.h>
#include <stdlib.h>
#include "guest_memory.h"
GuestResult guest_checked(GuestMemory *,uint64_t,uint32_t);
GuestResult guest_fast(GuestMemory *,uint64_t,uint32_t);
static uint32_t seed=20261027;
static uint32_t random32(void) {seed=seed*1664525u+1013904223u;return seed;}
int main(void) {
 enum { CAPACITY=12288, CASES=5000 };
 uint8_t *a=malloc(CAPACITY),*b=malloc(CAPACITY);if(!a||!b)return 2;
 for(int i=0;i<CASES;i++) {
  size_t size=1+random32()%CAPACITY;
  for(size_t j=0;j<size;j++)a[j]=(uint8_t)(random32()>>24);
  memcpy(b,a,size);
  uint8_t perms[3];for(int j=0;j<3;j++)perms[j]=(uint8_t)(random32()%4);
  uint64_t base=0x170000000ull+(uint64_t)(random32()%1024)*4096;
  GuestMemory left={base,size,a,perms,(size+4095)/4096},right=left;right.bytes=b;
  uint64_t address=base+(random32()%(CAPACITY+4));
  uint32_t count=random32()%4097;
  GuestResult x=guest_checked(&left,address,count),y=guest_fast(&right,address,count);
  if(x.result!=y.result || x.status!=y.status || x.access_address!=y.access_address || x.guest_pc!=y.guest_pc || memcmp(a,b,size)) {
   fprintf(stderr,"mismatch case=%d count=%u status=%u/%u\n",i,count,x.status,y.status);return 3;
  }
 }
 free(a);free(b);printf("{\"cases\":%u,\"status\":\"PASS\"}\n",CASES);return 0;
}
