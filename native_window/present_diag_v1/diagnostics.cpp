/* Native-only registry. No rendering/COM object is retained or dereferenced. */
#include "dxmt_present_diag_internal_v1.hpp"
#include <pthread.h>
#include <cstring>
#include <limits>

namespace {
pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
std::atomic<uint32_t> registry_error{0};
struct Registry {
    bool configured=false;
    uint64_t seen=0,live=0,closed=0;
    uint32_t flags=0;
    DXMTPresentDiagSnapshotV1 completed{};
} registry;
thread_local uint8_t owner_token;
bool lock() noexcept {
    if(pthread_mutex_lock(&mutex)==0)return true;
    registry_error.fetch_or(DXMT_PD_INTERNAL,std::memory_order_relaxed);return false;
}
void unlock() noexcept {
    if(pthread_mutex_unlock(&mutex)!=0)registry_error.fetch_or(DXMT_PD_INTERNAL,std::memory_order_relaxed);
}
}
namespace dxmt::present_diag_v1 {
uintptr_t thread_token() noexcept {return reinterpret_cast<uintptr_t>(&owner_token);}
void register_queue(Queue *q) noexcept {
    if(!lock())return;
    if(registry.seen==UINT64_MAX || registry.live==UINT64_MAX){registry.flags|=DXMT_PD_OVERFLOW;unlock();return;}
    q->id=++registry.seen;registry.live++;
    if(registry.configured) {
        if(registry.seen!=1)registry.flags|=DXMT_PD_MULTI_QUEUE;
        else {
            q->enabled=true;
            // CommandQueue's worker lane belongs to its construction thread.
            q->lanes[DXMT_PD_WORKER].owner.store(thread_token(),std::memory_order_relaxed);
        }
    }
    unlock();
}
void publish_queue(Queue *q,bool joined,uint64_t submitted,uint64_t completed) noexcept {
    if(!lock())return;
    if(!q->id || !registry.live){registry.flags|=DXMT_PD_INTERNAL;unlock();return;}
    registry.live--;registry.closed++;
    if(q->enabled) {
        // Explicit call is AFTER encoder, completion and event-listener joins, on the original
        // submitter/destructor thread. No active lane is read by this provider.
        if(!joined || completed<submitted)q->errors.fetch_or(DXMT_PD_UNFINISHED,std::memory_order_relaxed);
        bool correct_owner=q->lanes[DXMT_PD_WORKER].owner.load(std::memory_order_relaxed)==thread_token();
        if(!correct_owner)q->errors.fetch_or(DXMT_PD_OWNER,std::memory_order_relaxed);
        registry.flags|=q->errors.load(std::memory_order_relaxed);
        registry.completed.queue_id=q->id;
        registry.completed.submitted_chunks=submitted;
        registry.completed.completed_chunks=completed;
        // For an incomplete constructor/destructor do not read potentially
        // active data; the outcome is invalid regardless of existing records.
        if(joined && correct_owner)for(unsigned lane=0;lane<DXMT_PRESENT_DIAG_LANES_V1;lane++)
            registry.completed.lanes[lane]=q->lanes[lane].data;
    }
    unlock();
}
}
extern "C" uint32_t DXMTPresentDiagConfigureV1(const DXMTPresentDiagConfigV1 *config) {
    if(!config || config->version!=DXMT_PRESENT_DIAG_VERSION_V1 || config->size!=sizeof(*config))return DXMT_PD_ARGUMENT;
    if(!lock())return DXMT_PD_INVALID;
    uint32_t result=DXMT_PD_OK;
    if(registry.configured || registry.seen || registry.live)result=DXMT_PD_ALREADY_STARTED;
    else registry.configured=true;
    if(registry_error.load(std::memory_order_relaxed))result=DXMT_PD_INVALID;
    unlock();return registry_error.load(std::memory_order_relaxed)?DXMT_PD_INVALID:result;
}
extern "C" uint32_t DXMTPresentDiagReadV1(DXMTPresentDiagSnapshotV1 *out,uint32_t size) {
    if(!out || size!=sizeof(*out))return DXMT_PD_ARGUMENT;
    if(!lock())return DXMT_PD_INVALID;
    DXMTPresentDiagSnapshotV1 value{};
    if(registry.configured && registry.live==0)value=registry.completed;
    value.version=DXMT_PRESENT_DIAG_VERSION_V1;value.size=sizeof(value);
    value.flags=registry.flags|registry_error.load(std::memory_order_relaxed);
    value.configured=registry.configured;value.queues_seen=registry.seen;
    value.queues_live=registry.live;value.queues_closed=registry.closed;
    uint32_t result=DXMT_PD_OK;
    if(!registry.configured || registry.live || !registry.seen)result=DXMT_PD_NOT_READY;
    else if(value.flags || registry.seen!=1 || registry.closed!=1)result=DXMT_PD_INVALID;
    // Copy immutable finalized data while holding the publication mutex.
    // The caller owns this independent flat copy, never a COM/TLS pointer.
    *out=value;unlock();
    const uint32_t error=registry_error.load(std::memory_order_relaxed);
    if(error){out->flags|=error;return DXMT_PD_INVALID;}
    return result;
}
