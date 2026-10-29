/* Trusted host diagnostic ABI; no COM/guest/TLS pointers are exported. */
#ifndef DXMT_PRESENT_DIAGNOSTICS_V1_H
#define DXMT_PRESENT_DIAGNOSTICS_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define DXMT_PRESENT_DIAG_VERSION_V1 1u
#define DXMT_PRESENT_DIAG_LANES_V1 2u
#define DXMT_PRESENT_DIAG_CAPACITY_V1 256u
#define DXMT_PRESENT_DIAG_EXPORT __attribute__((visibility("default")))
enum { DXMT_PD_OK=0, DXMT_PD_ARGUMENT=1, DXMT_PD_NOT_READY=2,
       DXMT_PD_INVALID=3, DXMT_PD_ALREADY_STARTED=4 };
enum { DXMT_PD_MULTI_QUEUE=1u, DXMT_PD_OWNER=2u, DXMT_PD_OVERFLOW=4u,
       DXMT_PD_CLOCK=8u, DXMT_PD_UNFINISHED=16u, DXMT_PD_INTERNAL=32u };
enum { DXMT_PD_WORKER=0, DXMT_PD_ENCODER=1 };
enum { DXMT_PD_COMMIT_WAIT=1, DXMT_PD_PRESENT_WAIT=2,
       DXMT_PD_ENCODE_PREPARE=3, DXMT_PD_ENCODE_FLUSH=4, DXMT_PD_DRAWABLE_ENCODE=5, DXMT_PD_PRESENT_META=6 };
typedef struct DXMTPresentDiagConfigV1 { uint32_t version,size; } DXMTPresentDiagConfigV1;
typedef struct DXMTPresentDiagRecordV1 {
    uint32_t lane,kind,sampled,reserved;
    uint64_t queue_id,frame_id,chunk_id,sequence,duration_ns,wait_value;
    uint32_t max_latency,sync_interval,present_flags,reserved2;
    int64_t preferred_max_frame_rate;
} DXMTPresentDiagRecordV1;
typedef struct DXMTPresentDiagLaneV1 {
    uint64_t seen,stored;
    DXMTPresentDiagRecordV1 records[DXMT_PRESENT_DIAG_CAPACITY_V1];
} DXMTPresentDiagLaneV1;
typedef struct DXMTPresentDiagSnapshotV1 {
    uint32_t version,size,flags,configured;
    uint64_t queues_seen,queues_live,queues_closed,queue_id,submitted_chunks,completed_chunks;
    DXMTPresentDiagLaneV1 lanes[DXMT_PRESENT_DIAG_LANES_V1];
} DXMTPresentDiagSnapshotV1;
/* Once per process, before any CommandQueue constructor. An error invalidates
 * diagnosis only; callers must not skip or alter the real rendering operation. */
DXMT_PRESENT_DIAG_EXPORT uint32_t DXMTPresentDiagConfigureV1(const DXMTPresentDiagConfigV1 *config);
/* Trusted caller allocates sizeof snapshot. No active queue storage is read.
 * NOT_READY may copy only stable registry metadata; all lane data remains zero.
 * Repeated reads are identical while no subsequent queue is constructed.
 * Return OK requires one closed queue, no overflow/owner/unfinished errors. */
DXMT_PRESENT_DIAG_EXPORT uint32_t DXMTPresentDiagReadV1(DXMTPresentDiagSnapshotV1 *out,uint32_t size);
#ifdef __cplusplus
}
#endif
#endif
