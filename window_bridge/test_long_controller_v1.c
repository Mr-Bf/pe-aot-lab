/* Pure CPU synthetic monotonic values. Never calls Cocoa, DXMT or guest code. */
#include "long_controller_v1.h"
#include <string.h>
static unsigned checks,scenarios;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static LongController c;
static uint64_t base=UINT64_C(10000000000000000);
static void fresh(uint64_t duration,int smoke){memset(&c,0,sizeof c);CHECK(lc_configure(&c,duration,250,smoke));c.start_ns=base;CHECK(lc_offer(&c,base+1,0)==-1);CHECK(c.ready_ns==0);CHECK(lc_offer(&c,base+2,1)==-1);CHECK(c.ready_ns==base+2);}
static void cycle(uint64_t duration,int smoke){
    scenarios++;fresh(duration,smoke);uint64_t now=c.ready_ns;unsigned count=0;
    while(!c.escape_end_ns){CHECK(count<LC_CAPACITY);now=c.next_ns;int k=lc_offer(&c,now,1);CHECK(k>=0);lc_posted(&c,(unsigned)k,now,now,count+1,1);CHECK(!c.error);count++;}
    CHECK(c.phase==0);CHECK((c.posted-1)%4==0);CHECK(c.escape_begin_ns-c.ready_ns>=duration*LC_NS_PER_MS);
    CHECK(c.max_gap_ns==250*LC_NS_PER_MS);CHECK(c.max_lateness_ns==0);CHECK(c.smoke==(uint32_t)smoke);
    CHECK(c.posted==4*(duration/1000)+1);CHECK(lc_offer(&c,c.next_ns,1)==-1);
}
int main(void){
    scenarios++;memset(&c,0,sizeof c);CHECK(!lc_configure(&c,1799999,250,0));CHECK(!lc_configure(&c,2047001,250,0));CHECK(!lc_configure(&c,1800000,249,0));CHECK(!lc_configure(&c,10000,250,0));CHECK(!lc_configure(&c,1800000,250,1));CHECK(!lc_configure(&c,10001,250,1));CHECK(!lc_configure(&c,10000,250,2));
    cycle(10000,1);cycle(1800000,0);cycle(2047000,0);
    scenarios++;fresh(1800000,0);uint64_t late=c.ready_ns+1200*LC_NS_PER_MS;CHECK(lc_offer(&c,late,1)==0);lc_posted(&c,0,late,late+10,1,1);CHECK(!c.error);CHECK(c.next_ns==late+10+250*LC_NS_PER_MS);CHECK(lc_offer(&c,late+11,1)==-1);CHECK(c.posted==1);
    scenarios++;fresh(1800000,0);CHECK(lc_offer(&c,c.ready_ns+5000*LC_NS_PER_MS,0)==-1);CHECK(!c.error);CHECK(lc_offer(&c,c.ready_ns+5000*LC_NS_PER_MS+1,0)==-1);CHECK(c.error==LC_STALLED);
    scenarios++;fresh(1800000,0);uint64_t when=c.next_ns;lc_posted(&c,0,when,when+5000*LC_NS_PER_MS+1,1,1);CHECK(c.posted==1);CHECK(c.error==LC_STALLED);
    scenarios++;fresh(1800000,0);c.phase=1;c.ready_ns=base-1800000*LC_NS_PER_MS;c.start_ns=c.ready_ns;c.next_ns=base;/* Last actual post anchors stall separately from ready. */c.events[0]=(LCEvent){0,1,base-250*LC_NS_PER_MS,base-250*LC_NS_PER_MS};c.posted=1;c.last_wait=1;CHECK(lc_offer(&c,base,1)==1);lc_posted(&c,1,base,base,2,1);CHECK(c.phase==2);CHECK(!c.escape_end_ns);
    scenarios++;fresh(10000,1);c.posted=LC_CAPACITY;c.events[LC_CAPACITY-1].end_ns=c.ready_ns;CHECK(lc_offer(&c,c.next_ns,1)==-1);CHECK(c.error==LC_CAP_EXCEEDED);
    scenarios++;fresh(10000,1);lc_posted(&c,0,c.next_ns,c.next_ns,1,0);CHECK(c.error==LC_POST_FAILED);CHECK(c.requested==1&&c.posted==0);
    scenarios++;fresh(10000,1);lc_posted(&c,1,c.next_ns,c.next_ns,1,1);CHECK(c.error==LC_CLOCK_INVALID&&c.posted==0);
    scenarios++;fresh(10000,1);CHECK(lc_offer(&c,base-1,1)==-1&&c.error==LC_CLOCK_INVALID);
    scenarios++;fresh(10000,1);lc_posted(&c,4,c.next_ns,c.next_ns,1,1);CHECK(c.error==LC_CLOCK_INVALID&&!c.escape_end_ns);
    scenarios++;fresh(10000,1);uint64_t due=c.next_ns;CHECK(lc_offer(&c,due-1,1)==-1);CHECK(lc_offer(&c,due,0)==-1);CHECK(lc_offer(&c,due,1)==0);lc_posted(&c,0,due,due,1,1);due=c.next_ns;lc_posted(&c,1,due,due,1,1);CHECK(c.error==LC_CLOCK_INVALID);
    printf("{\"status\":\"PASS_SYNTHETIC_CONTROLLER_ONLY\",\"scenarios\":%u,\"checks\":%u,\"guest_executions\":0,\"gpu_executions\":0,\"elapsed_duration_claim\":false}\n",scenarios,checks);return 0;
}
