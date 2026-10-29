#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
__attribute__((ms_abi)) uint32_t guest_entry(const uint8_t *,uint32_t);
int main(void) {
    unsigned count,offset;
    while(scanf("%u %u",&count,&offset)==2) {
        if(count>8192 || offset>64)return 2;
        size_t bytes=(size_t)count*4+offset+16;
        uint8_t *buffer=malloc(bytes); if(!buffer)return 3;
        memset(buffer,0xa5,bytes);
        for(unsigned i=0;i<count;i++) {
            uint32_t value;
            if(scanf("%x",&value)!=1)return 4;
            memcpy(buffer+offset+i*4,&value,4);
        }
        uint32_t result=guest_entry(buffer+offset,count);
        printf("%08x",result);
        for(unsigned i=0;i<count;i++) {
            uint32_t value;memcpy(&value,buffer+offset+i*4,4);printf(" %08x",value);
        }
        putchar('\n');free(buffer);
    }
}
