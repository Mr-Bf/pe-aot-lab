/* Private C++ storage and hooks for the native-window diagnostic profile. */
#pragma once
#include "dxmt_present_diagnostics_v1.h"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <ratio>

namespace dxmt::present_diag_v1 {
static_assert(sizeof(DXMTPresentDiagConfigV1)==8);
static_assert(sizeof(DXMTPresentDiagRecordV1)==88);
static_assert(sizeof(DXMTPresentDiagLaneV1)==22544);
static_assert(sizeof(DXMTPresentDiagSnapshotV1)==45152);
struct Lane {
    std::atomic<uintptr_t> owner{0};
    DXMTPresentDiagLaneV1 data{}; // Only the successfully claimed owner writes.
};
struct Queue {
    std::atomic<uint32_t> errors{0};
    uint64_t id=0;
    bool enabled=false,closed=false;
    Lane lanes[DXMT_PRESENT_DIAG_LANES_V1];
    Queue() noexcept;
    ~Queue() noexcept;
    void close(bool joined,uint64_t submitted,uint64_t completed) noexcept;
};
/* Provider lives only in winemetal.dylib. Both dxgi/d3d11 must resolve this same
 * provider; a future build gate checks exports/undefined symbols/actual graph. */
DXMT_PRESENT_DIAG_EXPORT uintptr_t thread_token() noexcept;
DXMT_PRESENT_DIAG_EXPORT void register_queue(Queue *queue) noexcept;
DXMT_PRESENT_DIAG_EXPORT void publish_queue(Queue *queue,bool joined,uint64_t submitted,uint64_t completed) noexcept;
inline Queue::Queue() noexcept { register_queue(this); }
inline Queue::~Queue() noexcept { if(!closed)close(false,0,0); }
inline void Queue::close(bool joined,uint64_t submitted,uint64_t completed) noexcept {
    if(closed)return;
    publish_queue(this,joined,submitted,completed);closed=true;
}
/* No clock reads, explicit allocation, mutexes, output, COM calls or callbacks.
 * First TLS access may initialize runtime storage; this is not zero overhead.
 * CAS ownership is checked before touching any non-atomic lane data. */
template<class Rep,class Period>
inline void record(Queue *queue,uint32_t lane,uint32_t kind,uint64_t frame,uint64_t chunk,
                   std::chrono::duration<Rep,Period> elapsed,uint64_t wait_value=0,uint32_t max_latency=0,
                   uint32_t sync_interval=0,uint32_t present_flags=0,int64_t preferred_rate=0,
                   bool sampled=true) noexcept {
    static_assert(std::ratio_equal<Period,std::nano>::value,"fixed native clock must use nanoseconds");
    static_assert(std::numeric_limits<Rep>::is_signed && sizeof(Rep)<=sizeof(int64_t),"signed bounded native duration");
    if(!queue || !queue->enabled)return;
    if(lane>=DXMT_PRESENT_DIAG_LANES_V1){queue->errors.fetch_or(DXMT_PD_INTERNAL,std::memory_order_relaxed);return;}
    Lane &target=queue->lanes[lane];
    uintptr_t token=thread_token(),unclaimed=0;
    target.owner.compare_exchange_strong(unclaimed,token,std::memory_order_relaxed);
    if(target.owner.load(std::memory_order_relaxed)!=token){queue->errors.fetch_or(DXMT_PD_OWNER,std::memory_order_relaxed);return;}
    if(elapsed.count()<0 || (!sampled && elapsed.count()!=0)){queue->errors.fetch_or(DXMT_PD_CLOCK,std::memory_order_relaxed);return;}
    if(target.data.seen==UINT64_MAX){queue->errors.fetch_or(DXMT_PD_OVERFLOW,std::memory_order_relaxed);return;}
    uint64_t sequence=target.data.seen++;
    if(target.data.stored==DXMT_PRESENT_DIAG_CAPACITY_V1){queue->errors.fetch_or(DXMT_PD_OVERFLOW,std::memory_order_relaxed);return;}
    target.data.records[target.data.stored++]={lane,kind,static_cast<uint32_t>(sampled),0,
        queue->id,frame,chunk,sequence,static_cast<uint64_t>(elapsed.count()),wait_value,
        max_latency,sync_interval,present_flags,0,preferred_rate};
}
}
