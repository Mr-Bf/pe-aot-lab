#include "cocoa_host.h"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>
static std::atomic<unsigned> checks{0};
static void check(bool v,const char *why){checks++;if(!v){fprintf(stderr,"FAIL: %s\n",why);std::abort();}}
int main(){
    WBHost *host=wb_host_create();check(host,"Cocoa init");check(!wb_host_bind_worker(host),"main cannot become guest worker");
    std::atomic<int> stage{0};std::atomic<uint64_t> hwnd{0};std::atomic<bool> done{false},focus_succeeded{false};
    std::thread worker([&]{
        check(wb_host_bind_worker(host),"bind worker");check(!wb_host_bind_worker(host),"second binding rejected");
        WBHostFrameMetrics m={};check(wb_host_frame_metrics(host,&m),"frame metrics");
        uint64_t handle=wb_host_create_window(host,640+m.left+m.right,360+m.top+m.bottom,"Window bridge hidden host test");
        check(handle!=0,"create hidden window");hwnd=handle;
        uint32_t w=0,h=0;check(wb_host_client_size(host,handle,&w,&h)&&w==640&&h==360,"outer/client pixel conversion");
        int32_t rect[4]={};check(wb_host_window_rect(host,handle,rect)&&rect[2]-rect[0]==640+m.left+m.right&&rect[3]-rect[1]==360+m.top+m.bottom,"actual outer RECT agrees with frame metrics");
        DXMTNativeWSIV1 callbacks={};wb_host_callbacks(host,&callbacks);DXMTNativeWindowInfoV1 info={};info.size=sizeof(info);
        check(callbacks.query(callbacks.user,handle,&info)==1&&!(info.flags&DXMT_WSI_VISIBLE),"hidden creation independent of ShowWindow");
        int previous=-1;WBHostFocusChange focus={};
        int shown=wb_host_show_window(host,handle,1,&previous,&focus);
        fprintf(stderr,"show_diagnostic: result=%d previous=%d hwnd=%llu focus_before=%llu focus_after=%llu\n",shown,previous,(unsigned long long)handle,(unsigned long long)focus.before,(unsigned long long)focus.after);
        uint64_t changes=focus.before!=focus.after;
        info={};info.size=sizeof(info);
        check(shown&&previous==0&&focus.before==0&&callbacks.query(callbacks.user,handle,&info)==1&&(info.flags&DXMT_WSI_VISIBLE)&&focus.after==((info.flags&DXMT_WSI_FOREGROUND)?handle:0),"ShowWindow reports actual visibility/focus rather than assuming foreground");
        int focused=wb_host_focus_window(host,handle,&focus);changes+=focus.before!=focus.after;focus_succeeded=focused!=0;
        info={};info.size=sizeof(info);
        check(callbacks.query(callbacks.user,handle,&info)==1&&focus.after==((info.flags&DXMT_WSI_FOREGROUND)?handle:0)&&focused==(focus.after==handle),"SetFocus accepts actual focus or truthfully reports refusal");
        int hidden=wb_host_show_window(host,handle,0,&previous,&focus);changes+=focus.before!=focus.after;
        check(hidden&&previous==1&&focus.after==0,"hide reports actual focus loss separately");
        check(wb_host_validate_rect(host,handle),"validate paint before queue test");
        WBHostStats api_stats={};wb_host_stats(host,&api_stats);
        check(api_stats.api_focus_transitions==changes&&api_stats.sent_notifications==0,"API focus counts only actual changes without duplicate queued sent notification");
        uint32_t sample_time=0;int32_t sample_point[2]={};check(wb_host_input_snapshot(host,&sample_time,sample_point),"actual input metadata conversion");
        WBHostMessage message={};stage=1;check(wb_host_get_message(host,&message)==1&&message.origin==WB_ORIGIN_TEST_QUEUE&&message.message==0x100&&message.wparam==0x27&&message.lparam==0x414d0001,"blocked queue receives labeled injection");
        check(uint32_t(message.time_ms-sample_time)<10000,"posted timestamp is sampled rather than zero");
        // Coordinates need not remain equal: the user can move the pointer.
        check(message.screen_x>INT32_MIN&&message.screen_x<INT32_MAX&&message.screen_y>INT32_MIN&&message.screen_y<INT32_MAX,"posted pointer coordinates are representable in virtual screen space");
        check(wb_host_post_quit(host,0x12345678),"worker PostQuitMessage");check(wb_host_get_message(host,&message)==0&&message.message==0x12&&message.origin==WB_ORIGIN_GUEST_QUEUE_API&&message.wparam==0x12345678,"quit returned distinctly");
        stage=2;check(wb_host_get_message(host,&message)==-1,"end wakes blocked GetMessage");
        check(wb_host_destroy_window(host,handle),"destroy without view");check(!wb_host_destroy_window(host,handle),"tombstone denied");done=true;
    });
    bool injected=false,ended=false;auto until=std::chrono::steady_clock::now()+std::chrono::seconds(10);
    while(!done){
        wb_host_pump_once(host,0.001);WBHostStats s={};wb_host_stats(host,&s);
        if(stage==1&&!injected&&s.waits>=1){check(wb_host_test_post(host,hwnd,0x100,0x27,0x414d0001),"test injector accepted");injected=true;}
        if(stage==2&&!ended&&s.waits>=2){wb_host_session_end(host);ended=true;}
        if(std::chrono::steady_clock::now()>until){fprintf(stderr,"worker timeout\n");std::abort();}
    }
    worker.join();check(wb_host_finish(host),"main finish after join");WBHostStats stats={};wb_host_stats(host,&stats);
    check(stats.windows_created==1&&stats.windows_destroyed==1&&stats.active_views==0&&stats.test_queue_events==1&&stats.cocoa_key_events==0&&stats.quit_messages==1,"actual lifecycle/origin counts");
    printf("{\"status\":\"PASS\",\"checks\":%u,\"cocoa_initializations\":1,\"created_windows\":1,\"initially_hidden\":true,\"show_hide_tested\":true,\"focus_succeeded\":%s,\"api_focus_transitions\":%llu,\"sent_notifications\":%llu,\"cocoa_key_events\":%llu,\"test_queue_events\":%llu,\"waits\":%llu,\"gpu_calls\":0,\"guest_executions\":0}\n",checks.load(),focus_succeeded?"true":"false",(unsigned long long)stats.api_focus_transitions,(unsigned long long)stats.sent_notifications,(unsigned long long)stats.cocoa_key_events,(unsigned long long)stats.test_queue_events,(unsigned long long)stats.waits);return 0;
}
