/* Restricted real file API extracted from process_bridge/runtime.c.
 * Source SHA256: 0d4baa6c0ff85a92d490faba903f3bd5a97dfc23f03399e50e76bdcb4d118e33
 * Include after AotContext, AccessPlan, plan_access, fault and GuestMemory.
 * Host owns configured-session lifetime and invokes begin/end outside guest
 * execution, on the single owning thread. CALL/RET, argument-stack validation,
 * context ownership and instruction rollback remain in the outer dispatcher.
 * Completed POSIX effects cannot be rolled back by a subsequent guest fault.
 * This module shares one Win32 LastError cell with User32 via get/set accessors.
 * No process-exit state, graph session, virtual files or guest algorithms live here.
 */
#ifndef PE_AOT_WINDOW_FILE_API_INC
#define PE_AOT_WINDOW_FILE_API_INC
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

enum { WFILE_HANDLES=32, WFILE_NAME_MAX=120, WFILE_IO_MAX=1024*1024 };
enum { WFILE_FILE_NOT_FOUND=2,WFILE_TOO_MANY_OPEN_FILES=4,WFILE_ACCESS_DENIED=5,
       WFILE_INVALID_HANDLE=6,WFILE_NOT_ENOUGH_MEMORY=8,WFILE_CRC=23,WFILE_SHARING_VIOLATION=32,
       WFILE_NOT_SUPPORTED=50,WFILE_INVALID_PARAMETER=87,WFILE_DISK_FULL=112,
       WFILE_INVALID_NAME=123,WFILE_ALREADY_EXISTS=183 };
typedef struct { uint64_t token; int fd; uint32_t rights; dev_t device; ino_t inode; } WFileHandle;
typedef struct {
    int rootfd;
    uint32_t configured,last_error,cleanup_closes,cleanup_errors;
    uint64_t api_calls[9],bytes_read,bytes_written;
    WFileHandle handles[WFILE_HANDLES];
} FileSession;
static _Thread_local FileSession wfile_session;
static _Thread_local uint64_t wfile_next_handle=1; /* never reset by a new wfile_session */
static uint32_t wfile_win_error(int value) {
    switch(value) {
        case ENOENT:return WFILE_FILE_NOT_FOUND;
        case EACCES:case EPERM:case ELOOP:case EISDIR:case ENOTDIR:return WFILE_ACCESS_DENIED;
        case EBADF:return WFILE_INVALID_HANDLE;
        case ENOMEM:return WFILE_NOT_ENOUGH_MEMORY;
        case EMFILE:case ENFILE:return WFILE_TOO_MANY_OPEN_FILES;
        case ENOSPC:case EDQUOT:return WFILE_DISK_FULL;
        case EINVAL:return WFILE_INVALID_PARAMETER;
        default:return WFILE_CRC; /* restricted regular-file I/O error mapping */
    }
}
static inline uint32_t wfile_begin(const char *directory) {
    if(wfile_session.configured || !directory)return WFILE_INVALID_PARAMETER;
    int fd=open(directory,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return wfile_win_error(errno);
    memset(&wfile_session,0,sizeof wfile_session);
    wfile_session.rootfd=fd;wfile_session.configured=1;
    return 0;
}
static inline uint32_t wfile_end(void) {
    if(!wfile_session.configured)return 0;
    for(unsigned i=0;i<WFILE_HANDLES;i++)if(wfile_session.handles[i].token) {
        /* Do not retry close(EINTR): the descriptor's ownership may already
         * have ended. All tests use regular local files; failures are recorded. */
        if(close(wfile_session.handles[i].fd)==0)wfile_session.cleanup_closes++;
        else wfile_session.cleanup_errors++;
        wfile_session.handles[i].token=0;
    }
    if(close(wfile_session.rootfd)!=0)wfile_session.cleanup_errors++;
    wfile_session.rootfd=-1;wfile_session.configured=0;
    return wfile_session.cleanup_closes;
}
static inline uint32_t wfile_get_last_error(void){return wfile_session.last_error;}
static inline uint32_t wfile_open_handles(void) {
    uint32_t count=0;
    for(unsigned i=0;i<WFILE_HANDLES;i++)count+=wfile_session.handles[i].token!=0;
    return count;
}
static inline uint32_t wfile_cleanup_closes(void){return wfile_session.cleanup_closes;}
static inline uint32_t wfile_cleanup_errors(void){return wfile_session.cleanup_errors;}
static inline uint64_t wfile_api_calls(uint32_t signature){return signature<9?wfile_session.api_calls[signature]:0;}
static inline uint64_t wfile_bytes_read(void){return wfile_session.bytes_read;}
static inline uint64_t wfile_bytes_written(void){return wfile_session.bytes_written;}
static inline uint64_t wfile_total_calls(void) {
    uint64_t count=0;for(unsigned i=4;i<9;i++)count+=wfile_session.api_calls[i];return count;
}
static void wfile_write_count(const AccessPlan *plan,uint32_t value) {
    for(unsigned i=0;i<4;i++)*plan->byte[i]=(uint8_t)(value>>(8*i));
}
typedef struct { const GuestMemory *region; size_t offset,size; } WFileSpan;
typedef struct { unsigned count; WFileSpan spans[AOT_MAX_REGIONS]; } WFileBuffer;
static bool wfile_buffer(AotContext *ctx,uint64_t address,uint32_t size,uint32_t access,WFileBuffer *out) {
    out->count=0;
    if(!size)return true; /* zero-byte I/O does not dereference the buffer */
    if(address>UINT64_MAX-(size-1)) {fault(ctx,AOT_BOUNDS,address,size,access);return false;}
    uint64_t cursor=address;size_t remaining=size;
    /* Resolve the whole VA interval before checking permissions, preserving
     * the transaction engine's BOUNDS-before-PROTECTION precedence. */
    while(remaining) {
        const GuestMemory *found=NULL;
        for(size_t i=0;i<ctx->region_count;i++) {
            const GuestMemory *r=&ctx->regions[i];
            if(cursor>=r->base && cursor-r->base<r->size){found=r;break;}
        }
        if(!found || out->count==AOT_MAX_REGIONS) {fault(ctx,AOT_BOUNDS,address,size,access);return false;}
        size_t offset=(size_t)(cursor-found->base),chunk=found->size-offset;
        if(chunk>remaining)chunk=remaining;
        out->spans[out->count++]=(WFileSpan){found,offset,chunk};
        remaining-=chunk;if(remaining)cursor+=chunk;
    }
    for(unsigned i=0;i<out->count;i++) {
        WFileSpan *p=&out->spans[i];
        for(size_t page=p->offset/GM_PAGE;page<=(p->offset+p->size-1)/GM_PAGE;page++)
            if((p->region->permissions[page]&access)!=access) {
                fault(ctx,AOT_PROTECTION,address,size,access);return false;
            }
    }
    return true;
}
static void wfile_buffer_copy(const WFileBuffer *buffer,uint8_t *temporary,size_t size,bool to_guest) {
    for(unsigned i=0;i<buffer->count && size;i++) {
        const WFileSpan *p=&buffer->spans[i];size_t n=p->size<size?p->size:size;
        if(to_guest)memcpy(p->region->bytes+p->offset,temporary,n);
        else memcpy(temporary,p->region->bytes+p->offset,n);
        temporary+=n;size-=n;
    }
}
static bool wfile_ascii_alnum(unsigned char c) {
    return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9');
}
static bool wfile_valid_name(const char *name,size_t n) {
    if(!n || !wfile_ascii_alnum((unsigned char)name[0]) || name[n-1]=='.' || strstr(name,".."))return false;
    for(size_t i=0;i<n;i++)if(!wfile_ascii_alnum((unsigned char)name[i]) && name[i]!='.' && name[i]!='_' && name[i]!='-')return false;
    char stem[5]={0};size_t length=0;
    while(length<n && name[length]!='.')length++;
    if(length>4)return true;
    for(size_t i=0;i<length;i++)stem[i]=(char)(name[i]>='a' && name[i]<='z'?name[i]-32:name[i]);
    if(!strcmp(stem,"CON") || !strcmp(stem,"PRN") || !strcmp(stem,"AUX") || !strcmp(stem,"NUL"))return false;
    if(length==4 && stem[3]>='1' && stem[3]<='9' &&
       ((!memcmp(stem,"COM",3)) || (!memcmp(stem,"LPT",3))))return false;
    return true;
}
static bool wfile_read_name(AotContext *ctx,uint64_t address,char name[WFILE_NAME_MAX+1],bool *valid) {
    *valid=false;
    for(unsigned i=0;i<=WFILE_NAME_MAX;i++) {
        if(address>UINT64_MAX-i){fault(ctx,AOT_BOUNDS,address,(uint64_t)i+1,GM_READ);return false;}
        AccessPlan plan;if(!plan_access(ctx,address+i,1,GM_READ,&plan))return false;
        name[i]=(char)*plan.byte[0];
        if(!name[i]){*valid=wfile_valid_name(name,i);return true;}
    }
    return true; /* bounded name too long; never pass the unterminated array to POSIX */
}
static WFileHandle *wfile_find_handle(uint64_t token) {
    if(!token)return NULL;
    for(unsigned i=0;i<WFILE_HANDLES;i++)if(wfile_session.handles[i].token==token)return &wfile_session.handles[i];
    return NULL;
}
static inline uint64_t wfile_create(AotContext *ctx,const uint64_t args[7]) {
    uint32_t access=(uint32_t)args[1],disposition=(uint32_t)args[4];
    if((uint32_t)args[2] || args[3] || (uint32_t)args[5]!=0x80 || args[6] ||
       !((access==0x40000000u && disposition==2) || (access==0x80000000u && disposition==3))) {
        wfile_session.last_error=WFILE_INVALID_PARAMETER;return UINT64_MAX;
    }
    char name[WFILE_NAME_MAX+1];bool valid;
    if(!wfile_read_name(ctx,args[0],name,&valid))return UINT64_MAX;
    if(!valid){wfile_session.last_error=WFILE_INVALID_NAME;return UINT64_MAX;}
    WFileHandle *slot=NULL;
    for(unsigned i=0;i<WFILE_HANDLES;i++)if(!wfile_session.handles[i].token){slot=&wfile_session.handles[i];break;}
    if(!slot || wfile_next_handle>UINT64_C(0x0000ffffffffffff)) {
        wfile_session.last_error=WFILE_TOO_MANY_OPEN_FILES;return UINT64_MAX;
    }
    int flags=O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK;
    bool existed=false;int fd;
    if(disposition==2) {
        fd=openat(wfile_session.rootfd,name,flags|O_WRONLY|O_CREAT|O_EXCL,0600);
        if(fd<0 && errno==EEXIST){existed=true;fd=openat(wfile_session.rootfd,name,flags|O_WRONLY);}
    } else fd=openat(wfile_session.rootfd,name,flags|O_RDONLY);
    if(fd<0){wfile_session.last_error=wfile_win_error(errno);return UINT64_MAX;}
    struct stat st;
    uint32_t error=0;
    if(fstat(fd,&st)!=0)error=wfile_win_error(errno);
    else if(!S_ISREG(st.st_mode) || st.st_nlink!=1)error=WFILE_ACCESS_DENIED;
    if(!error)for(unsigned i=0;i<WFILE_HANDLES;i++) {
        WFileHandle *other=&wfile_session.handles[i];
        if(other->token && other->device==st.st_dev && other->inode==st.st_ino) {error=WFILE_SHARING_VIOLATION;break;}
    }
    /* Do not truncate an existing object before checking file kind, hard links,
     * available handle capacity and this wfile_session's no-sharing contract. */
    if(!error && disposition==2 && ftruncate(fd,0)!=0)error=wfile_win_error(errno);
    if(error){if(close(fd)!=0)wfile_session.cleanup_errors++;wfile_session.last_error=error;return UINT64_MAX;}
    slot->token=UINT64_C(0xa07f000000000000)|wfile_next_handle++;
    slot->fd=fd;slot->rights=access;slot->device=st.st_dev;slot->inode=st.st_ino;
    if(disposition==2)wfile_session.last_error=existed?WFILE_ALREADY_EXISTS:0;
    return slot->token;
}
static inline uint64_t wfile_transfer(AotContext *ctx,const uint64_t args[5],bool reading) {
    uint32_t size=(uint32_t)args[2];AccessPlan count;WFileBuffer buffer;
    if(!plan_access(ctx,args[3],4,GM_WRITE,&count))return 0;
    if(size>WFILE_IO_MAX) {fault(ctx,AOT_UNSUPPORTED,args[1],size,reading?GM_WRITE:GM_READ);return 0;}
    if(!wfile_buffer(ctx,args[1],size,reading?GM_WRITE:GM_READ,&buffer))return 0;
    if(size && args[1]<args[3]+4 && args[3]<args[1]+size) {
        fault(ctx,AOT_UNSUPPORTED,args[3],4,GM_WRITE);return 0;
    }
    /* All guest access has been checked. From this point writes and file offset
     * changes are committed API effects, independent of instruction rollback. */
    wfile_write_count(&count,0);
    if(args[4]){wfile_session.last_error=WFILE_INVALID_PARAMETER;return 0;}
    WFileHandle *handle=wfile_find_handle(args[0]);
    if(!handle){wfile_session.last_error=WFILE_INVALID_HANDLE;return 0;}
    if(handle->rights!=(reading?0x80000000u:0x40000000u)) {wfile_session.last_error=WFILE_ACCESS_DENIED;return 0;}
    uint8_t *temporary=malloc(size?size:1);
    if(!temporary){wfile_session.last_error=WFILE_NOT_ENOUGH_MEMORY;return 0;}
    if(!reading)wfile_buffer_copy(&buffer,temporary,size,false);
    ssize_t actual;
    do {actual=reading?read(handle->fd,temporary,size):write(handle->fd,temporary,size);} while(actual<0 && errno==EINTR);
    if(actual<0) {uint32_t error=wfile_win_error(errno);free(temporary);wfile_session.last_error=error;return 0;}
    /* A short successful transfer is exposed to the PE, never hidden by a loop. */
    if(reading){wfile_buffer_copy(&buffer,temporary,(size_t)actual,true);wfile_session.bytes_read+=(uint64_t)actual;}
    else wfile_session.bytes_written+=(uint64_t)actual;
    wfile_write_count(&count,(uint32_t)actual);free(temporary);return 1;
}
static inline uint64_t wfile_close(uint64_t token) {
    WFileHandle *handle=wfile_find_handle(token);
    if(!handle){wfile_session.last_error=WFILE_INVALID_HANDLE;return 0;}
    int fd=handle->fd;handle->token=0;
    if(close(fd)!=0){wfile_session.last_error=wfile_win_error(errno);return 0;}
    return 1;
}
static inline void wfile_set_last_error(uint32_t value){wfile_session.last_error=value;}
/* Dispatcher calls this only after the helper returns without an AotFault.
 * A Win32 FALSE / INVALID_HANDLE return still counts as a completed API entry;
 * this is neither a count of successful POSIX calls nor file bytes changed. */
static inline bool wfile_record_call(uint32_t signature) {
    if(!wfile_session.configured || signature<4 || signature>8)return false;
    wfile_session.api_calls[signature]++;return true;
}
#endif
