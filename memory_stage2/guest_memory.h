#ifndef PE_AOT_GUEST_MEMORY_H
#define PE_AOT_GUEST_MEMORY_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#if UINTPTR_MAX != UINT64_MAX || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error This experiment requires a 64-bit little-endian host
#endif

enum { GM_PAGE=4096, GM_READ=1, GM_WRITE=2 };
enum { GM_OK=0, GM_BOUNDS=1, GM_PROTECTION=2, GM_INVALID=3 };
typedef struct {
    uint64_t base;
    size_t size;
    uint8_t *bytes;
    const uint8_t *permissions;
    size_t page_count;
} GuestMemory;
typedef struct {
    uint32_t result;
    uint32_t status;
    uint64_t access_address; /* Operand effective address, not OS fault byte/CR2. */
    uint64_t guest_pc;
} GuestResult;

/* Trusted host supplies backing allocation. No guest integer is cast to a host
 * pointer. Permissions are guest 4KiB granularity, independent of host pages.
 * Mapping and backing memory must remain stable for the entire single-threaded
 * call; this is not a concurrent-memory or VirtualProtect implementation. */
static inline int gm_valid(const GuestMemory *m) {
    return m && m->bytes && m->permissions && !(m->base & (GM_PAGE-1))
        && m->size && m->size <= UINT64_MAX-m->base
        && m->page_count == m->size/GM_PAGE+(m->size%GM_PAGE!=0);
}
static inline uint8_t *gm_range(const GuestMemory *m,uint64_t address,
                                size_t width,uint8_t access,uint32_t *error) {
    *error=GM_OK;
    if(!gm_valid(m)) {*error=GM_INVALID;return NULL;}
    if(address<m->base) {*error=GM_BOUNDS;return NULL;}
    uint64_t offset=address-m->base;
    if(offset>m->size || width>m->size-(size_t)offset) {*error=GM_BOUNDS;return NULL;}
    if(width) {
        size_t first=(size_t)offset/GM_PAGE;
        size_t last=((size_t)offset+width-1)/GM_PAGE;
        for(size_t i=first;i<=last;i++)
            if((m->permissions[i]&access)!=access) {*error=GM_PROTECTION;return NULL;}
    }
    return m->bytes+(size_t)offset;
}
static inline int gm_load32(const GuestMemory *m,uint64_t address,uint32_t *out,uint32_t *error) {
    uint8_t *p=gm_range(m,address,4,GM_READ,error);
    if(!p)return 0;
    /* memcpy is alignment-safe; currently supported hosts are little-endian. */
    memcpy(out,p,4);return 1;
}
static inline int gm_store32(GuestMemory *m,uint64_t address,uint32_t value,uint32_t *error) {
    uint8_t *p=gm_range(m,address,4,GM_WRITE,error);
    if(!p)return 0;
    memcpy(p,&value,4);return 1;
}
#endif
