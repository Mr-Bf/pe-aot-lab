/* Standalone tests of the actual prepared provider, not a replacement model.
 * No DXMT device, COM, renderer, guest, GUI or GPU is instantiated. */
#include "dxmt_present_diag_internal_v1.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

using dxmt::present_diag_v1::Queue;
using dxmt::present_diag_v1::record;
using ns=std::chrono::nanoseconds;
static unsigned checks=0,business_calls=0;
static void check(bool ok,const char *what) {
    ++checks;
    if(!ok){std::fprintf(stderr,"FAIL: %s\n",what);std::exit(1);}
}
static void configure() {
    DXMTPresentDiagConfigV1 c{1,sizeof(c)};
    check(DXMTPresentDiagConfigureV1(&c)==DXMT_PD_OK,"configure once");
}
static DXMTPresentDiagSnapshotV1 read(uint32_t expected) {
    DXMTPresentDiagSnapshotV1 s{};
    check(DXMTPresentDiagReadV1(&s,sizeof(s))==expected,"read status");
    check(s.version==1 && s.size==sizeof(s),"snapshot header");
    return s;
}
static void empty(const DXMTPresentDiagLaneV1 &lane) {
    DXMTPresentDiagLaneV1 zero{};
    check(std::memcmp(&lane,&zero,sizeof(zero))==0,"no active/rejected lane data");
}
static void publish(Queue &q) {q.close(true,11,11);}
static void worker(Queue &q,uint64_t frame,uint64_t chunk) {
    record(&q,DXMT_PD_WORKER,DXMT_PD_PRESENT_WAIT,frame,chunk,ns(0),0,3,0,0,0,false);
}
static void arguments() {
    check(DXMTPresentDiagConfigureV1(nullptr)==DXMT_PD_ARGUMENT,"null config");
    DXMTPresentDiagConfigV1 c{2,sizeof(c)};
    check(DXMTPresentDiagConfigureV1(&c)==DXMT_PD_ARGUMENT,"version reject");
    c={1,sizeof(c)-1};
    check(DXMTPresentDiagConfigureV1(&c)==DXMT_PD_ARGUMENT,"config size reject");
    DXMTPresentDiagSnapshotV1 s{},before{};
    check(DXMTPresentDiagReadV1(nullptr,sizeof(s))==DXMT_PD_ARGUMENT,"null output");
    check(DXMTPresentDiagReadV1(&s,sizeof(s)-1)==DXMT_PD_ARGUMENT,"small output reject");
    check(std::memcmp(&s,&before,sizeof(s))==0,"bad size no output write");
    auto prior=read(DXMT_PD_NOT_READY);
    check(prior.configured==0 && prior.queues_seen==0,"before config state");
    configure();
    c={1,sizeof(c)};
    check(DXMTPresentDiagConfigureV1(&c)==DXMT_PD_ALREADY_STARTED,"repeat config reject");
    auto after=read(DXMT_PD_NOT_READY);
    check(after.configured==1 && after.queues_seen==0,"config does not invent queue");
}
static void normal() {
    configure();Queue q;
    for(uint64_t f=1;f<=3;++f)worker(q,f,7+f);
    record(&q,DXMT_PD_WORKER,DXMT_PD_PRESENT_WAIT,4,11,ns(9),1,3);
    auto active=read(DXMT_PD_NOT_READY);
    check(active.queues_seen==1 && active.queues_live==1 && active.queues_closed==0,"active registry");
    empty(active.lanes[0]);empty(active.lanes[1]);
    std::thread encoder([&]{
        record(&q,DXMT_PD_ENCODER,DXMT_PD_DRAWABLE_ENCODE,3,11,ns(6));
        record(&q,DXMT_PD_ENCODER,DXMT_PD_ENCODE_PREPARE,3,11,ns(2));
        record(&q,DXMT_PD_ENCODER,DXMT_PD_ENCODE_FLUSH,3,11,ns(8));
    });encoder.join();publish(q);
    auto s=read(DXMT_PD_OK),again=read(DXMT_PD_OK);
    check(std::memcmp(&s,&again,sizeof(s))==0,"repeat immutable snapshot");
    check(s.flags==0 && s.queues_seen==1 && s.queues_live==0 && s.queues_closed==1 && s.queue_id==1,"closed registry");
    check(s.submitted_chunks==11 && s.completed_chunks==11,"completion evidence");
    check(s.lanes[0].seen==4 && s.lanes[0].stored==4 && s.lanes[1].seen==3 && s.lanes[1].stored==3,"both lane counts");
    for(unsigned i=0;i<4;++i) {
        auto &r=s.lanes[0].records[i];
        check(r.queue_id==1 && r.sequence==i && r.frame_id==i+1 && r.chunk_id==i+8,"worker IDs");
        check(r.lane==DXMT_PD_WORKER && r.kind==DXMT_PD_PRESENT_WAIT && r.max_latency==3,"worker metadata");
        check(r.sampled==(i==3) && r.duration_ns==(i==3?9u:0u) && r.wait_value==(i==3?1u:0u),"unsampled first three vs measured wait");
    }
    const unsigned kinds[]={DXMT_PD_DRAWABLE_ENCODE,DXMT_PD_ENCODE_PREPARE,DXMT_PD_ENCODE_FLUSH};
    const unsigned durations[]={6,2,8};
    for(unsigned i=0;i<3;++i) {
        auto &r=s.lanes[1].records[i];
        check(r.lane==1 && r.kind==kinds[i] && r.duration_ns==durations[i] && r.sampled==1,"encoder exact copied duration");
        check(r.frame_id==3 && r.chunk_id==11 && r.sequence==i && r.queue_id==1,"encoder IDs");
    }
}
static void owner() {
    configure();Queue q;worker(q,1,1);
    std::thread wrong([&]{worker(q,2,2);++business_calls;});wrong.join();publish(q);
    auto s=read(DXMT_PD_INVALID);
    check(s.flags==DXMT_PD_OWNER,"wrong worker diagnostic flag");
    check(s.lanes[0].seen==1 && s.lanes[0].stored==1 && s.lanes[0].records[0].frame_id==1,"wrong owner did not write records");
    check(business_calls==1,"diagnostic rejection did not skip dummy business");
}
static void overflow() {
    configure();Queue q;
    for(unsigned i=0;i<257;++i)worker(q,i,i);
    publish(q);auto s=read(DXMT_PD_INVALID);
    check(s.flags==DXMT_PD_OVERFLOW && s.lanes[0].seen==257 && s.lanes[0].stored==256,"bounded overflow explicit");
    for(unsigned i=0;i<256;++i)check(s.lanes[0].records[i].sequence==i && s.lanes[0].records[i].frame_id==i,"no ring overwrite");
}
static void clock_error() {
    configure();Queue q;
    record(&q,0,DXMT_PD_COMMIT_WAIT,0,1,ns(-1));++business_calls;
    record(&q,0,DXMT_PD_PRESENT_META,0,1,ns(1),0,0,0,0,0,false);++business_calls;
    publish(q);auto s=read(DXMT_PD_INVALID);
    check(s.flags==DXMT_PD_CLOCK,"negative or impossible unsampled duration rejected");
    empty(s.lanes[0]);check(business_calls==2,"clock errors do not skip dummy business");
}
static void unfinished_join() {
    configure();
    {Queue q;worker(q,1,1);} // actual fallback destructor: no explicit join proof
    auto s=read(DXMT_PD_INVALID);
    check(s.flags==DXMT_PD_UNFINISHED && s.queues_closed==1 && s.queues_live==0,"fallback close invalid");
    empty(s.lanes[0]);empty(s.lanes[1]);
}
static void unfinished_work() {
    configure();Queue q;worker(q,1,1);q.close(true,2,1);
    auto s=read(DXMT_PD_INVALID);
    check(s.flags==DXMT_PD_UNFINISHED && s.submitted_chunks==2 && s.completed_chunks==1,"pending work explicit");
    check(s.lanes[0].stored==1,"joined data available but invalid");
}
static void close_owner() {
    configure();Queue q;worker(q,1,1);
    std::thread wrong([&]{publish(q);});wrong.join();
    auto s=read(DXMT_PD_INVALID);
    check(s.flags==DXMT_PD_OWNER,"wrong destruction owner rejected");
    empty(s.lanes[0]);empty(s.lanes[1]);
}
static void multi() {
    configure();
    {Queue q;worker(q,1,1);publish(q);}
    auto first=read(DXMT_PD_OK);
    {Queue q;worker(q,2,2);auto active=read(DXMT_PD_NOT_READY);check(active.queues_seen==2,"second queue tracked");publish(q);}
    auto s=read(DXMT_PD_INVALID);
    check(s.flags==DXMT_PD_MULTI_QUEUE && s.queues_seen==2 && s.queues_closed==2 && s.queues_live==0,"sequential queues invalidate diagnosis");
    check(std::memcmp(s.lanes,first.lanes,sizeof(s.lanes))==0,"second disabled queue did not replace first records");
}
static void late() {
    {Queue q;publish(q);}
    DXMTPresentDiagConfigV1 c{1,sizeof(c)};
    check(DXMTPresentDiagConfigureV1(&c)==DXMT_PD_ALREADY_STARTED,"configuration after closed queue rejected");
    auto s=read(DXMT_PD_NOT_READY);
    check(s.configured==0 && s.queues_seen==1 && s.queues_closed==1,"unconfigured history retained");
    empty(s.lanes[0]);empty(s.lanes[1]);
}
int main(int argc,char **argv) {
    if(argc!=2)return 64;
    struct Case {const char *name;void (*run)();};
    const Case cases[]={{"arguments",arguments},{"normal",normal},{"owner",owner},{"overflow",overflow},
      {"clock",clock_error},{"unfinished_join",unfinished_join},{"unfinished_work",unfinished_work},
      {"close_owner",close_owner},{"multi",multi},{"late",late}};
    for(const auto &item:cases)if(std::strcmp(argv[1],item.name)==0) {
        item.run();std::printf("{\"status\":\"PASS_PROVIDER_COMPONENT\",\"case\":\"%s\",\"checks\":%u,\"dummy_business_calls\":%u,\"gpu_calls\":0}\n",item.name,checks,business_calls);return 0;
    }
    return 64;
}
