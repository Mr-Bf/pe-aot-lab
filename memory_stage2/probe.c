#include "guest_memory.h"
int memory_load(GuestMemory *m,uint64_t address,uint32_t *out,uint32_t *error) {
    return gm_load32(m,address,out,error);
}
int memory_store(GuestMemory *m,uint64_t address,uint32_t value,uint32_t *error) {
    return gm_store32(m,address,value,error);
}
