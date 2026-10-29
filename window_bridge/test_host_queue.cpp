#include "message_queue.h"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <thread>
static unsigned checks=0;
static void check(bool value,const char *why){checks++;if(!value){fprintf(stderr,"FAIL: %s\n",why);std::abort();}}
static void waiting(WBMessageQueue &q) {
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    for(;;){WBHostStats s={};q.stats(s);if(s.waits)return;
        if(std::chrono::steady_clock::now()>deadline){fprintf(stderr,"no blocked wait\n");std::abort();}std::this_thread::yield();}
}
int main(){
    {WBMessageQueue q;WBHostMessage m={};check(q.take(&m)==-1,"unbound get");check(q.bind(),"bind");check(!q.bind(),"second bind");
     bool wrong=false;std::thread other([&]{wrong=q.take(&m)==-1&&!q.bind();});other.join();check(wrong,"foreign thread denied");}
    {WBMessageQueue q;WBHostMessage got={};std::atomic<int> result{-99};
     std::thread t([&]{if(!q.bind())std::abort();result=q.take(&got);});waiting(q);
     check(result.load()==-99,"empty queue is blocked");WBHostMessage m={};m.hwnd=123;m.message=0x100;m.wparam=0x25;m.lparam=0x414b0001;m.origin=WB_ORIGIN_TEST_QUEUE;
     check(q.push(m),"wake message accepted");t.join();check(result==1&&got.hwnd==123&&got.origin==WB_ORIGIN_TEST_QUEUE&&got.lparam==m.lparam&&got.sequence==1,"wake preserves repeat/source");}
    {WBMessageQueue q;check(q.bind(),"FIFO bind");WBHostMessage m={};m.message=0x100;m.origin=WB_ORIGIN_TEST_QUEUE;check(q.push(m),"key before quit");m={};m.message=0x12;m.wparam=0x12345678;m.origin=WB_ORIGIN_GUEST_QUEUE_API;check(q.push(m),"post quit");
     WBHostMessage got={};check(q.take(&got)==1&&got.message==0x100,"pre-quit FIFO");check(q.take(&got)==0&&got.message==0x12&&got.wparam==0x12345678&&got.hwnd==0&&got.origin==4,"actual QUIT result");}
    {WBMessageQueue q;WBHostMessage got={};std::atomic<int> result{-99};std::thread t([&]{if(!q.bind())std::abort();result=q.take(&got);});waiting(q);q.end();t.join();
     check(result==-1&&got.message==0,"end wakes error not fake quit");check(!q.push({})&&!q.running(),"end permanent");q.end();WBHostStats s={};q.stats(s);check(s.error==1&&s.stopped==1&&s.pending_messages==0,"idempotent end state");}
    {WBMessageQueue q;check(q.bind(),"overflow bind");WBHostMessage m={};m.message=0x100;m.origin=3;bool accepted=true;for(size_t i=0;i<q.capacity;i++)accepted&=q.push(m);check(accepted,"capacity accepted");check(!q.push(m),"overflow rejected");WBHostMessage got={};check(q.take(&got)==-1,"overflow fail closed");WBHostStats s={};q.stats(s);check(s.queue_overflows==1&&s.error==2,"overflow reason");}
    {WBMessageQueue q;check(q.bind(),"paint bind");q.invalidate(44);WBHostMessage key={};key.hwnd=44;key.message=0x100;key.origin=3;check(q.push(key),"ordinary before paint");WBHostMessage got={};check(q.take(&got)==1&&got.message==0x100,"FIFO paint priority");check(q.take(&got)==1&&got.message==0xf&&got.hwnd==44&&got.origin==2,"invalid paint generated");check(q.take(&got)==1&&got.message==0xf,"unvalidated paint remains");q.validate(44);WBHostStats s={};q.stats(s);check(!s.paint_invalid,"validate clears");}
    {WBMessageQueue q;check(q.bind(),"destroy bind");WBHostMessage m={};m.hwnd=44;m.message=0x100;m.origin=3;q.push(m);m.hwnd=55;q.push(m);m.hwnd=0;m.message=0x12;m.origin=4;q.push(m);q.invalidate(44);q.remove_window(44);WBHostMessage got={};check(q.take(&got)==1&&got.hwnd==44,"stale HWND retained for runtime discard");check(q.take(&got)==1&&got.hwnd==55,"other HWND retained");check(q.take(&got)==0&&got.hwnd==0,"QUIT survives window destruction");}
    {WBMessageQueue q;check(q.bind(),"sent bind");WBHostMessage m={};m.message=0x100;m.origin=3;q.push(m);m.message=7;m.delivery=1;m.origin=2;q.push(m);m.message=0x12;m.delivery=0;m.origin=4;q.push(m);m.message=8;m.delivery=1;m.origin=2;q.push(m);WBHostMessage got={};check(q.take(&got)==1&&got.message==7&&got.delivery==1,"sent precedes posted");check(q.take(&got)==1&&got.message==8,"all pending sent before posted including QUIT");check(q.take(&got)==1&&got.message==0x100,"posted FIFO retained");check(q.take(&got)==0&&got.message==0x12,"QUIT retains posted FIFO order");}
    {WBMessageQueue q;check(q.bind(),"origins bind");WBHostMessage m={};m.message=0x100;for(unsigned i=1;i<=5;i++){m.origin=i;check(q.push(m),"source accepted");}WBHostStats s={};q.stats(s);check(s.cocoa_key_events==1&&s.cocoa_window_events==1&&s.test_queue_events==1&&s.guest_queue_events==1&&s.focus_recovery_events==1,"origins separately counted");}
    printf("{\"status\":\"PASS\",\"checks\":%u,\"cocoa_initializations\":0,\"windows\":0,\"gpu_calls\":0,\"guest_executions\":0}\n",checks);return 0;
}
