#ifndef PE_AOT_WINDOW_MESSAGE_QUEUE_H
#define PE_AOT_WINDOW_MESSAGE_QUEUE_H
#include "cocoa_host.h"
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <algorithm>

/* The production queue is also tested without Cocoa/GPU. No queue mutex may
 * be held while dispatching to main or executing any guest/native callback. */
class WBMessageQueue {
    mutable std::mutex mutex;
    std::condition_variable cv;
    std::deque<WBHostMessage> messages;
    std::thread::id worker;
    bool bound=false,ended=false;
    uint32_t error=0;
    uint64_t paint_window=0,next_sequence=1;
    WBHostStats counts={};
public:
    static constexpr size_t capacity=256;
    bool bind() {
        std::lock_guard<std::mutex> l(mutex);
        if(bound || ended)return false;
        worker=std::this_thread::get_id();bound=true;return true;
    }
    bool is_worker() const {
        std::lock_guard<std::mutex> l(mutex);
        return bound && worker==std::this_thread::get_id();
    }
    bool running() const {
        std::lock_guard<std::mutex> l(mutex);return !ended && !error;
    }
    void fail(uint32_t reason) {
        std::lock_guard<std::mutex> l(mutex);
        if(!error)error=reason;
        cv.notify_all();
    }
    bool push(WBHostMessage m) {
        std::lock_guard<std::mutex> l(mutex);
        if(ended || error)return false;
        if(messages.size()==capacity) {
            error=WB_HOST_ERROR_QUEUE_FULL;counts.queue_overflows++;cv.notify_all();return false;
        }
        m.sequence=next_sequence++;messages.push_back(m);
        if(m.delivery==WB_DELIVERY_SENT_NOTIFICATION)counts.sent_notifications++;
        switch(m.origin) {
            case WB_ORIGIN_COCOA_KEY:counts.cocoa_key_events++;break;
            case WB_ORIGIN_COCOA_WINDOW:counts.cocoa_window_events++;break;
            case WB_ORIGIN_TEST_QUEUE:counts.test_queue_events++;break;
            case WB_ORIGIN_GUEST_QUEUE_API:counts.guest_queue_events++;break;
            case WB_ORIGIN_FOCUS_RECOVERY:counts.focus_recovery_events++;break;
        }
        cv.notify_one();return true;
    }
    void invalidate(uint64_t hwnd) {
        std::lock_guard<std::mutex> l(mutex);
        if(!ended && !error){paint_window=hwnd;cv.notify_one();}
    }
    void validate(uint64_t hwnd) {
        std::lock_guard<std::mutex> l(mutex);
        if(paint_window==hwnd)paint_window=0;
    }
    void remove_window(uint64_t hwnd) {
        std::lock_guard<std::mutex> l(mutex);
        // Posted and sent stale-HWND records remain for the runtime to discard
        // without callbacks. Only generated paint state belongs to this HWND.
        if(paint_window==hwnd)paint_window=0;
    }
    int take(WBHostMessage *out) {
        if(!out)return -1;
        *out={};std::unique_lock<std::mutex> l(mutex);
        if(!bound || worker!=std::this_thread::get_id())return -1;
        if(!ended && !error && messages.empty() && !paint_window) {
            counts.waits++;cv.wait(l,[&]{return ended || error || !messages.empty() || paint_window;});
        }
        if(ended || error)return -1;
        if(!messages.empty()) {
            auto sent=std::find_if(messages.begin(),messages.end(),[](const auto &m){return m.delivery==WB_DELIVERY_SENT_NOTIFICATION;});
            auto selected=sent==messages.end()?messages.begin():sent;*out=*selected;messages.erase(selected);
        }
        else {*out={};out->hwnd=paint_window;out->message=0x000f;out->origin=WB_ORIGIN_COCOA_WINDOW;out->sequence=next_sequence++;}
        counts.messages_taken++;
        if(out->message==0x0012){counts.quit_messages++;return 0;}
        return 1;
    }
    void end() {
        std::lock_guard<std::mutex> l(mutex);
        ended=true;if(!error)error=WB_HOST_ERROR_STOPPED;
        messages.clear();paint_window=0;cv.notify_all();
    }
    void stats(WBHostStats &s) const {
        std::lock_guard<std::mutex> l(mutex);
        s.cocoa_key_events=counts.cocoa_key_events;s.cocoa_window_events=counts.cocoa_window_events;
        s.test_queue_events=counts.test_queue_events;s.focus_recovery_events=counts.focus_recovery_events;
        s.guest_queue_events=counts.guest_queue_events;s.messages_taken=counts.messages_taken;
        s.sent_notifications=counts.sent_notifications;
        s.waits=counts.waits;s.quit_messages=counts.quit_messages;s.queue_overflows=counts.queue_overflows;
        s.pending_messages=static_cast<uint32_t>(messages.size());s.error=error;s.stopped=ended;
        s.worker_bound=bound;s.paint_invalid=paint_window!=0;
    }
};
#endif
