/* Versioned process boundary over the audited restricted file bridge.
 * ExitProcess stops guest execution without RET, exception, longjmp or killing
 * the native host. Host call frames unwind through the ordinary AOT gates.
 * File helpers are unchanged from file_bridge/runtime.c at a6d1ca8. */
#define __remill_function_call aot_rejected_function_call
#define aot_execute aot_execute_base
#define aot_should_exit aot_engine_should_exit
#define aot_begin aot_engine_begin
#define aot_commit aot_engine_commit
#include "../integration_stage3/runtime.c"
#undef aot_commit
#undef aot_begin
#undef aot_should_exit
#undef aot_execute
#undef __remill_function_call
#include "runtime.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct { uint32_t call_rva,iat_rva,target_rva,signature; } AotImportCall;
#include "native_imports.h"
#ifndef AOT_IMPORT_CALL_COUNT
#define AOT_IMPORT_CALL_COUNT (sizeof(aot_import_calls)/sizeof(aot_import_calls[0]))
#endif
extern void *aot_import_ret(void *,uint64_t,void *);

static bool host_overlap(uintptr_t a,size_t an,uintptr_t b,size_t bn) {
    return an && bn && a<b+bn && b<a+an;
}
static bool bridge_memory_valid(AotState *s,AotContext *ctx) {
    /* C allocations/descriptors themselves are trusted. Reject backing aliases
     * which would violate Remill State noalias or mutate metadata mid-call. */
    uintptr_t state=(uintptr_t)s,context=(uintptr_t)ctx;
    uintptr_t table=(uintptr_t)ctx->instructions;
    size_t table_size=ctx->instruction_count*sizeof(AotInstruction);
    if(host_overlap(state,sizeof *s,context,sizeof *ctx) ||
       host_overlap(state,sizeof *s,table,table_size))return false;
    for(size_t i=0;i<ctx->region_count;i++) {
        GuestMemory *r=&ctx->regions[i];
        if(!gm_valid(r))return false;
        uintptr_t bytes=(uintptr_t)r->bytes,perms=(uintptr_t)r->permissions;
        if(r->size>UINTPTR_MAX-bytes || r->page_count>UINTPTR_MAX-perms)return false;
        if(host_overlap(bytes,r->size,state,sizeof *s) ||
           host_overlap(bytes,r->size,context,sizeof *ctx) ||
           host_overlap(bytes,r->size,table,table_size) ||
           host_overlap(perms,r->page_count,state,sizeof *s) ||
           host_overlap(perms,r->page_count,context,sizeof *ctx) ||
           host_overlap(perms,r->page_count,table,table_size))return false;
        for(size_t p=0;p<r->page_count;p++)
            if((r->permissions[p]&~7u) ||
               (r->permissions[p]&(GM_WRITE|AOT_EXEC))==(GM_WRITE|AOT_EXEC))return false;
        for(size_t j=0;j<ctx->region_count;j++) {
            GuestMemory *other=&ctx->regions[j];
            if(host_overlap(bytes,r->size,(uintptr_t)other->permissions,other->page_count))return false;
        }
    }
    return true;
}

enum { FILE_HANDLES=32, FILE_NAME_MAX=120, FILE_IO_MAX=1024*1024 };
enum { W_FILE_NOT_FOUND=2,W_TOO_MANY_OPEN_FILES=4,W_ACCESS_DENIED=5,
       W_INVALID_HANDLE=6,W_NOT_ENOUGH_MEMORY=8,W_CRC=23,W_SHARING_VIOLATION=32,
       W_NOT_SUPPORTED=50,W_INVALID_PARAMETER=87,W_DISK_FULL=112,
       W_INVALID_NAME=123,W_ALREADY_EXISTS=183 };
typedef struct { uint64_t token; int fd; uint32_t rights; dev_t device; ino_t inode; } FileHandle;
typedef struct {
    int rootfd;
    uint32_t configured,running,used,last_error,cleanup_closes,cleanup_errors;
    uint64_t api_calls[10],bytes_read,bytes_written;
    uintptr_t context_identity,state_identity; /* compared only; never dereferenced */
    uint32_t exit_requested,exit_code,exit_depth;
    uint64_t exit_pc,exit_rsp;
    FileHandle handles[FILE_HANDLES];
} FileSession;
static _Thread_local FileSession session;
static _Thread_local uint64_t next_handle=1; /* never reset by a new session */
static uint32_t win_error(int value) {
    switch(value) {
        case ENOENT:return W_FILE_NOT_FOUND;
        case EACCES:case EPERM:case ELOOP:case EISDIR:case ENOTDIR:return W_ACCESS_DENIED;
        case EBADF:return W_INVALID_HANDLE;
        case ENOMEM:return W_NOT_ENOUGH_MEMORY;
        case EMFILE:case ENFILE:return W_TOO_MANY_OPEN_FILES;
        case ENOSPC:case EDQUOT:return W_DISK_FULL;
        case EINVAL:return W_INVALID_PARAMETER;
        default:return W_CRC; /* restricted regular-file I/O error mapping */
    }
}
uint32_t aot_file_session_begin(const char *directory) {
    if(session.configured || session.running || !directory)return W_INVALID_PARAMETER;
    int fd=open(directory,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return win_error(errno);
    memset(&session,0,sizeof session);
    session.rootfd=fd;session.configured=1;
    return 0;
}
uint32_t aot_file_session_end(void) {
    if(!session.configured || session.running)return 0;
    for(unsigned i=0;i<FILE_HANDLES;i++)if(session.handles[i].token) {
        /* Do not retry close(EINTR): the descriptor's ownership may already
         * have ended. All tests use regular local files; failures are recorded. */
        if(close(session.handles[i].fd)==0)session.cleanup_closes++;
        else session.cleanup_errors++;
        session.handles[i].token=0;
    }
    if(close(session.rootfd)!=0)session.cleanup_errors++;
    session.rootfd=-1;session.configured=0;
    return session.cleanup_closes;
}
uint32_t aot_file_last_error(void){return session.last_error;}
uint32_t aot_file_open_handles(void) {
    uint32_t count=0;
    for(unsigned i=0;i<FILE_HANDLES;i++)count+=session.handles[i].token!=0;
    return count;
}
uint32_t aot_file_cleanup_closes(void){return session.cleanup_closes;}
uint32_t aot_file_cleanup_errors(void){return session.cleanup_errors;}
uint64_t aot_file_api_calls(uint32_t signature){return signature<10?session.api_calls[signature]:0;}
uint64_t aot_file_bytes_read(void){return session.bytes_read;}
uint64_t aot_file_bytes_written(void){return session.bytes_written;}
uint64_t aot_bridge_api_calls(void) {
    uint64_t count=0;for(unsigned i=0;i<10;i++)count+=session.api_calls[i];return count;
}
uint32_t aot_process_exit_requested(void){return session.exit_requested;}
uint32_t aot_process_exit_code(void){return session.exit_code;}
uint64_t aot_process_exit_pc(void){return session.exit_pc;}
uint64_t aot_process_exit_rsp(void){return session.exit_rsp;}
uint32_t aot_process_exit_depth(void){return session.exit_depth;}
static bool process_stopped(void *opaque) {
    return session.exit_requested && session.context_identity==(uintptr_t)opaque;
}
uint32_t aot_should_exit(void *opaque) {
    return process_stopped(opaque) || aot_engine_should_exit(opaque);
}
uint32_t aot_begin(void *state,uint64_t pc,void *opaque) {
    if(process_stopped(opaque))return 1;
    return aot_engine_begin(state,pc,opaque);
}
uint32_t aot_commit(void *state,uint64_t pc,void *opaque) {
    if(process_stopped(opaque))return 1;
    return aot_engine_commit(state,pc,opaque);
}
uint32_t aot_execute(AotEntry entry,AotState *s,AotContext *ctx,uint64_t pc) {
    if(!session.configured || session.running || session.used)return AOT_INVALID;
    if(!entry || !s || !ctx || ((uintptr_t)s&15) || !bridge_memory_valid(s,ctx))return AOT_INVALID;
    if(ctx->result.steps || ctx->in_instruction || ctx->result.returned || ctx->result.fault.status)return AOT_INVALID;
    session.running=1;session.used=1;
    session.context_identity=(uintptr_t)ctx;session.state_identity=(uintptr_t)s;
    entry(s,pc,ctx);
    uint32_t status=ctx->result.fault.status;
    if(!status && session.exit_requested) {
        /* Termination leaves the committed import CALL and its active shadow
         * frame intact. No guest instruction, including C3, has run afterward. */
        if(ctx->in_instruction || ctx->pending_size || ctx->result.returned ||
           session.exit_pc!=aot_get_register(s,AOT_RIP) ||
           session.exit_rsp!=aot_get_register(s,AOT_RSP) ||
           session.exit_depth!=ctx->result.call_depth) {
            fault(ctx,AOT_INVALID,aot_get_register(s,AOT_RIP),0,0);
            status=ctx->result.fault.status;
        } else status=AOT_PROCESS_EXITED;
    } else if(!status && (!ctx->result.returned || ctx->result.call_depth)) {
        ctx->current_pc=aot_get_register(s,AOT_RIP);fault(ctx,AOT_NOT_RETURNED,ctx->current_pc,0,0);
        status=ctx->result.fault.status;
    }
    /* Retain comparison-only identities until next session, so post-exit
     * begin/commit/should_exit also stop without changing State or Context. */
    session.running=0;
    return status;
}
static bool bridge_read(AotContext *ctx,uint64_t address,uint64_t *value) {
    AccessPlan plan;if(!plan_access(ctx,address,8,GM_READ,&plan))return false;
    *value=0;for(unsigned i=0;i<8;i++)*value|=(uint64_t)*plan.byte[i]<<(8*i);
    return true;
}
static void write_count(const AccessPlan *plan,uint32_t value) {
    for(unsigned i=0;i<4;i++)*plan->byte[i]=(uint8_t)(value>>(8*i));
}
typedef struct { const GuestMemory *region; size_t offset,size; } FileSpan;
typedef struct { unsigned count; FileSpan spans[AOT_MAX_REGIONS]; } FileBuffer;
static bool file_buffer(AotContext *ctx,uint64_t address,uint32_t size,uint32_t access,FileBuffer *out) {
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
        out->spans[out->count++]=(FileSpan){found,offset,chunk};
        remaining-=chunk;if(remaining)cursor+=chunk;
    }
    for(unsigned i=0;i<out->count;i++) {
        FileSpan *p=&out->spans[i];
        for(size_t page=p->offset/GM_PAGE;page<=(p->offset+p->size-1)/GM_PAGE;page++)
            if((p->region->permissions[page]&access)!=access) {
                fault(ctx,AOT_PROTECTION,address,size,access);return false;
            }
    }
    return true;
}
static void buffer_copy(const FileBuffer *buffer,uint8_t *temporary,size_t size,bool to_guest) {
    for(unsigned i=0;i<buffer->count && size;i++) {
        const FileSpan *p=&buffer->spans[i];size_t n=p->size<size?p->size:size;
        if(to_guest)memcpy(p->region->bytes+p->offset,temporary,n);
        else memcpy(temporary,p->region->bytes+p->offset,n);
        temporary+=n;size-=n;
    }
}
static bool ascii_alnum(unsigned char c) {
    return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9');
}
static bool valid_name(const char *name,size_t n) {
    if(!n || !ascii_alnum((unsigned char)name[0]) || name[n-1]=='.' || strstr(name,".."))return false;
    for(size_t i=0;i<n;i++)if(!ascii_alnum((unsigned char)name[i]) && name[i]!='.' && name[i]!='_' && name[i]!='-')return false;
    char stem[5]={0};size_t length=0;
    while(length<n && name[length]!='.')length++;
    if(length>4)return true;
    for(size_t i=0;i<length;i++)stem[i]=(char)(name[i]>='a' && name[i]<='z'?name[i]-32:name[i]);
    if(!strcmp(stem,"CON") || !strcmp(stem,"PRN") || !strcmp(stem,"AUX") || !strcmp(stem,"NUL"))return false;
    if(length==4 && stem[3]>='1' && stem[3]<='9' &&
       ((!memcmp(stem,"COM",3)) || (!memcmp(stem,"LPT",3))))return false;
    return true;
}
static bool read_name(AotContext *ctx,uint64_t address,char name[FILE_NAME_MAX+1],bool *valid) {
    *valid=false;
    for(unsigned i=0;i<=FILE_NAME_MAX;i++) {
        if(address>UINT64_MAX-i){fault(ctx,AOT_BOUNDS,address,(uint64_t)i+1,GM_READ);return false;}
        AccessPlan plan;if(!plan_access(ctx,address+i,1,GM_READ,&plan))return false;
        name[i]=(char)*plan.byte[0];
        if(!name[i]){*valid=valid_name(name,i);return true;}
    }
    return true; /* bounded name too long; never pass the unterminated array to POSIX */
}
static FileHandle *find_handle(uint64_t token) {
    if(!token)return NULL;
    for(unsigned i=0;i<FILE_HANDLES;i++)if(session.handles[i].token==token)return &session.handles[i];
    return NULL;
}
static uint64_t create_file(AotContext *ctx,const uint64_t args[7]) {
    uint32_t access=(uint32_t)args[1],disposition=(uint32_t)args[4];
    if((uint32_t)args[2] || args[3] || (uint32_t)args[5]!=0x80 || args[6] ||
       !((access==0x40000000u && disposition==2) || (access==0x80000000u && disposition==3))) {
        session.last_error=W_INVALID_PARAMETER;return UINT64_MAX;
    }
    char name[FILE_NAME_MAX+1];bool valid;
    if(!read_name(ctx,args[0],name,&valid))return UINT64_MAX;
    if(!valid){session.last_error=W_INVALID_NAME;return UINT64_MAX;}
    FileHandle *slot=NULL;
    for(unsigned i=0;i<FILE_HANDLES;i++)if(!session.handles[i].token){slot=&session.handles[i];break;}
    if(!slot || next_handle>UINT64_C(0x0000ffffffffffff)) {
        session.last_error=W_TOO_MANY_OPEN_FILES;return UINT64_MAX;
    }
    int flags=O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK;
    bool existed=false;int fd;
    if(disposition==2) {
        fd=openat(session.rootfd,name,flags|O_WRONLY|O_CREAT|O_EXCL,0600);
        if(fd<0 && errno==EEXIST){existed=true;fd=openat(session.rootfd,name,flags|O_WRONLY);}
    } else fd=openat(session.rootfd,name,flags|O_RDONLY);
    if(fd<0){session.last_error=win_error(errno);return UINT64_MAX;}
    struct stat st;
    uint32_t error=0;
    if(fstat(fd,&st)!=0)error=win_error(errno);
    else if(!S_ISREG(st.st_mode) || st.st_nlink!=1)error=W_ACCESS_DENIED;
    if(!error)for(unsigned i=0;i<FILE_HANDLES;i++) {
        FileHandle *other=&session.handles[i];
        if(other->token && other->device==st.st_dev && other->inode==st.st_ino) {error=W_SHARING_VIOLATION;break;}
    }
    /* Do not truncate an existing object before checking file kind, hard links,
     * available handle capacity and this session's no-sharing contract. */
    if(!error && disposition==2 && ftruncate(fd,0)!=0)error=win_error(errno);
    if(error){if(close(fd)!=0)session.cleanup_errors++;session.last_error=error;return UINT64_MAX;}
    slot->token=UINT64_C(0xa07f000000000000)|next_handle++;
    slot->fd=fd;slot->rights=access;slot->device=st.st_dev;slot->inode=st.st_ino;
    if(disposition==2)session.last_error=existed?W_ALREADY_EXISTS:0;
    return slot->token;
}
static uint64_t transfer_file(AotContext *ctx,const uint64_t args[5],bool reading) {
    uint32_t size=(uint32_t)args[2];AccessPlan count;FileBuffer buffer;
    if(!plan_access(ctx,args[3],4,GM_WRITE,&count))return 0;
    if(size>FILE_IO_MAX) {fault(ctx,AOT_UNSUPPORTED,args[1],size,reading?GM_WRITE:GM_READ);return 0;}
    if(!file_buffer(ctx,args[1],size,reading?GM_WRITE:GM_READ,&buffer))return 0;
    if(size && args[1]<args[3]+4 && args[3]<args[1]+size) {
        fault(ctx,AOT_UNSUPPORTED,args[3],4,GM_WRITE);return 0;
    }
    /* All guest access has been checked. From this point writes and file offset
     * changes are committed API effects, independent of instruction rollback. */
    write_count(&count,0);
    if(args[4]){session.last_error=W_INVALID_PARAMETER;return 0;}
    FileHandle *handle=find_handle(args[0]);
    if(!handle){session.last_error=W_INVALID_HANDLE;return 0;}
    if(handle->rights!=(reading?0x80000000u:0x40000000u)) {session.last_error=W_ACCESS_DENIED;return 0;}
    uint8_t *temporary=malloc(size?size:1);
    if(!temporary){session.last_error=W_NOT_ENOUGH_MEMORY;return 0;}
    if(!reading)buffer_copy(&buffer,temporary,size,false);
    ssize_t actual;
    do {actual=reading?read(handle->fd,temporary,size):write(handle->fd,temporary,size);} while(actual<0 && errno==EINTR);
    if(actual<0) {uint32_t error=win_error(errno);free(temporary);session.last_error=error;return 0;}
    /* A short successful transfer is exposed to the PE, never hidden by a loop. */
    if(reading){buffer_copy(&buffer,temporary,(size_t)actual,true);session.bytes_read+=(uint64_t)actual;}
    else session.bytes_written+=(uint64_t)actual;
    write_count(&count,(uint32_t)actual);free(temporary);return 1;
}
static uint64_t close_file(uint64_t token) {
    FileHandle *handle=find_handle(token);
    if(!handle){session.last_error=W_INVALID_HANDLE;return 0;}
    int fd=handle->fd;handle->token=0;
    if(close(fd)!=0){session.last_error=win_error(errno);return 0;}
    return 1;
}
void *__remill_function_call(void *state,uint64_t pc,void *opaque) {
    AotState *s=state;AotContext *ctx=opaque;
    if(!s || !ctx || aot_should_exit(ctx))return opaque;
    if(!session.running || session.context_identity!=(uintptr_t)ctx || session.state_identity!=(uintptr_t)s) {
        fault(ctx,AOT_INVALID,pc,0,0);return opaque;
    }
    const AotImportCall *binding=NULL;
    if(ctx->current && ctx->current->kind==AOT_CALL && !ctx->in_instruction &&
       ctx->result.call_depth && aot_get_register(s,AOT_RIP)==pc) {
        for(size_t i=0;i<AOT_IMPORT_CALL_COUNT;i++)
            if(aot_import_calls[i].call_rva==ctx->current->rva &&
               ctx->module_base<=UINT64_MAX-aot_import_calls[i].target_rva &&
               pc==ctx->module_base+aot_import_calls[i].target_rva) {binding=&aot_import_calls[i];break;}
    }
    ctx->current_pc=pc;
    if(!binding || binding->signature<4 || binding->signature>9) {fault(ctx,AOT_UNSUPPORTED,pc,0,AOT_EXEC);return opaque;}
    uint64_t rsp=aot_get_register(s,AOT_RSP),return_pc;
    if((rsp&15)!=8 || rsp>UINT64_MAX-64 || s->bytes[2075]) {fault(ctx,AOT_INVALID,rsp,0,0);return opaque;}
    /* Exit has no guest RET to execute. Its already committed CALL may consume
     * the final budget step; ordinary file calls still reserve a RET step. */
    if(ctx->result.steps>ctx->budget || (binding->signature!=9 && ctx->result.steps==ctx->budget)) {
        fault(ctx,AOT_BUDGET,pc,0,0);return opaque;
    }
    const AotInstruction *ret_ins=instruction(ctx,pc);AccessPlan executable;
    if(!ret_ins || ret_ins->kind!=AOT_RET || ret_ins->length!=1) {fault(ctx,AOT_BAD_INSTRUCTION,pc,1,AOT_EXEC);return opaque;}
    if(!plan_access(ctx,pc,1,AOT_EXEC,&executable))return opaque;
    if(*executable.byte[0]!=0xc3){fault(ctx,AOT_BAD_INSTRUCTION,pc,1,AOT_EXEC);return opaque;}
    if(binding->signature==9) {
        for(unsigned i=0;i<4;i++) {AccessPlan shadow;if(!plan_access(ctx,rsp+8+8*i,8,GM_READ|GM_WRITE,&shadow))return opaque;}
        /* Do not read or validate the return destination of a non-returning
         * guest API, and do not set ctx.returned or manufacture a RAX value. */
        session.exit_requested=1;session.exit_code=(uint32_t)aot_get_register(s,AOT_RCX);
        session.exit_pc=pc;session.exit_rsp=rsp;session.exit_depth=ctx->result.call_depth;
        session.api_calls[9]++;
        return opaque; /* This C helper RETURNS; it must never be LLVM noreturn. */
    }
    if(!bridge_read(ctx,rsp,&return_pc))return opaque;
    ReturnFrame frame=ctx->frames[ctx->result.call_depth-1];
    if(return_pc!=frame.pc || rsp+8!=frame.rsp) {fault(ctx,AOT_BAD_RETURN,return_pc,0,AOT_EXEC);return opaque;}
    for(unsigned i=0;i<4;i++) {AccessPlan shadow;if(!plan_access(ctx,rsp+8+8*i,8,GM_READ|GM_WRITE,&shadow))return opaque;}
    uint64_t args[7]={aot_get_register(s,AOT_RCX),aot_get_register(s,AOT_RDX),
        aot_get_register(s,AOT_R8),aot_get_register(s,AOT_R9),0,0,0};
    unsigned extra=binding->signature==4?3:(binding->signature==5 || binding->signature==6)?1:0;
    for(unsigned i=0;i<extra;i++)if(!bridge_read(ctx,rsp+40+8*i,&args[4+i]))return opaque;
    uint64_t value=0;
    switch(binding->signature) {
        case 4:value=create_file(ctx,args);break;
        case 5:value=transfer_file(ctx,args,false);break;
        case 6:value=transfer_file(ctx,args,true);break;
        case 7:value=close_file(args[0]);break;
        case 8:value=session.last_error;break;
        default:break;
    }
    if(ctx->result.fault.status)return opaque;
    session.api_calls[binding->signature]++;
    aot_set_register(s,AOT_RAX,value);
    aot_import_ret(state,pc,opaque);
    return opaque;
}
