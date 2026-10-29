#ifndef PE_AOT_LONG_CONTROLLER_V1_H
#define PE_AOT_LONG_CONTROLLER_V1_H
/* Trusted TEST_QUEUE controller only. No guest pointer or game state access. */
#include "cocoa_host.h"
#include <errno.h>
#include <inttypes.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>

enum { LC_CAPACITY=8192, LC_PERIOD_MS=250, LC_MIN_DURATION_MS=1800000,
       LC_MAX_DURATION_MS=2047000, LC_SMOKE_MS=10000, LC_PROTECT_MS=2100000,
       LC_STALL_MS=5000 };
enum { LC_NONE=0, LC_POST_FAILED=1, LC_CAP_EXCEEDED=2, LC_STALLED=3,
       LC_CLOCK_INVALID=4, LC_EARLY_EXIT=5, LC_RESOURCE_FAILED=6, LC_PROTECT_TIMEOUT=7 };
#define LC_NS_PER_MS UINT64_C(1000000)
typedef struct {uint32_t message;uint64_t key;int64_t bits;const char *name;} LCSpec;
typedef struct {uint32_t kind;uint64_t wait_count,begin_ns,end_ns;} LCEvent;
typedef struct {
    uint32_t smoke,error,phase;uint64_t duration_ms,start_ns,ready_ns,next_ns,last_wait;
    uint64_t escape_begin_ns,escape_end_ns,finish_ns,max_gap_ns,max_lateness_ns;
    uint32_t requested,posted;LCEvent events[LC_CAPACITY];
} LongController;
typedef struct {
    uint32_t queried;int usage_status,usage_errno;uint32_t mach_status;
    uint64_t timestamp_ns,user_cpu_ns,system_cpu_ns,maxrss_native;
    uint64_t resident_bytes,resident_peak_bytes,virtual_bytes;
    uint64_t minor_faults,major_faults,voluntary_switches,involuntary_switches;
} LCResource;

static uint64_t lc_now_ns(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t) || t.tv_sec<0 || t.tv_nsec<0 || t.tv_nsec>=1000000000 ||
       (uint64_t)t.tv_sec>UINT64_MAX/UINT64_C(1000000000))abort();
    uint64_t whole=(uint64_t)t.tv_sec*UINT64_C(1000000000);
    if((uint64_t)t.tv_nsec>UINT64_MAX-whole)abort();
    return whole+(uint64_t)t.tv_nsec;
}
static const LCSpec *lc_spec(unsigned kind) {
    static const LCSpec table[]={
        {0x100,0x27,0x014d0001,"right"},{0x101,0x27,0xc14d0001,"right-up"},
        {0x100,0x25,0x014b0001,"left"},{0x101,0x25,0xc14b0001,"left-up"},
        {0x100,0x1b,0x00010001,"escape"}};
    if(kind>=sizeof table/sizeof *table)abort();return &table[kind];
}
static int lc_configure(LongController *c,uint64_t duration_ms,uint64_t period_ms,int smoke) {
    if(!c || period_ms!=LC_PERIOD_MS || (smoke!=0 && smoke!=1))return 0;
    if(smoke?duration_ms!=LC_SMOKE_MS:(duration_ms<LC_MIN_DURATION_MS || duration_ms>LC_MAX_DURATION_MS))return 0;
    /* Complete four-event cycles plus Escape, including the no-lateness case. */
    if(4*((duration_ms+4*LC_PERIOD_MS-1)/(4*LC_PERIOD_MS))+1>LC_CAPACITY)return 0;
    c->smoke=(uint32_t)smoke;c->duration_ms=duration_ms;return 1;
}
/* Return a due key index or -1. This function never posts or touches guest
 * memory. Eligibility comes from an actually observed HWND and GetMessage idle.
 * Once ready, a long stall is a failure even if no new idle boundary arrives. */
static int lc_offer(LongController *c,uint64_t now,int eligible) {
    if(c->error || c->escape_end_ns)return -1;
    if(now<c->start_ns || (c->ready_ns && now<c->ready_ns) ||
       (c->posted && now<c->events[c->posted-1].end_ns)){c->error=LC_CLOCK_INVALID;return -1;}
    if(!c->ready_ns) {
        if(!eligible)return -1;
        if(!now || now>UINT64_MAX-LC_PERIOD_MS*LC_NS_PER_MS){c->error=LC_CLOCK_INVALID;return -1;}
        c->ready_ns=now;c->next_ns=now+LC_PERIOD_MS*LC_NS_PER_MS;return -1;
    }
    uint64_t previous=c->posted?c->events[c->posted-1].end_ns:c->ready_ns;
    if(now-previous>LC_STALL_MS*LC_NS_PER_MS){c->error=LC_STALLED;return -1;}
    if(!eligible || now<c->next_ns)return -1;
    if(c->posted>=LC_CAPACITY){c->error=LC_CAP_EXCEEDED;return -1;}
    if(c->phase==0 && now-c->ready_ns>=c->duration_ms*LC_NS_PER_MS)return 4;
    return (int)c->phase;
}
static void lc_posted(LongController *c,unsigned kind,uint64_t begin,uint64_t end,uint64_t wait,int success) {
    c->requested++;
    if(!success){c->error=LC_POST_FAILED;return;}
    if(c->error || c->posted>=LC_CAPACITY || kind>4 || begin<c->ready_ns || begin<c->next_ns ||
       end<begin || end>UINT64_MAX-LC_PERIOD_MS*LC_NS_PER_MS || wait<=c->last_wait ||
       (kind==4?(c->phase!=0 || begin-c->ready_ns<c->duration_ms*LC_NS_PER_MS):kind!=c->phase)) {
        c->error=LC_CLOCK_INVALID;return;
    }
    uint64_t previous=c->posted?c->events[c->posted-1].end_ns:c->ready_ns;
    uint64_t gap=begin-previous,lateness=begin-c->next_ns;
    if(gap>c->max_gap_ns)c->max_gap_ns=gap;
    if(lateness>c->max_lateness_ns)c->max_lateness_ns=lateness;
    c->events[c->posted++]=(LCEvent){kind,wait,begin,end};c->last_wait=wait;
    /* Never advance a past deadline in a catch-up loop: no burst replay. */
    c->next_ns=end+LC_PERIOD_MS*LC_NS_PER_MS;
    if(kind==4){c->escape_begin_ns=begin;c->escape_end_ns=end;}
    else c->phase=(c->phase+1)%4;
    /* Preserve the actual post record even if posting itself was stalled. */
    if(gap>LC_STALL_MS*LC_NS_PER_MS || end-begin>LC_STALL_MS*LC_NS_PER_MS)c->error=LC_STALLED;
}
static uint64_t lc_timeval_ns(struct timeval t) {
    if(t.tv_sec<0 || t.tv_usec<0 || t.tv_usec>=1000000 ||
       (uint64_t)t.tv_sec>UINT64_MAX/UINT64_C(1000000000))abort();
    uint64_t base=(uint64_t)t.tv_sec*UINT64_C(1000000000),rest=(uint64_t)t.tv_usec*1000;
    if(rest>UINT64_MAX-base)abort();return base+rest;
}
static void lc_resource(LCResource *r) {
    r->queried=1;r->timestamp_ns=lc_now_ns();struct rusage u={0};errno=0;
    r->usage_status=getrusage(RUSAGE_SELF,&u);r->usage_errno=r->usage_status?errno:0;
    if(!r->usage_status) {
        r->user_cpu_ns=lc_timeval_ns(u.ru_utime);r->system_cpu_ns=lc_timeval_ns(u.ru_stime);
        r->maxrss_native=(uint64_t)u.ru_maxrss;r->minor_faults=(uint64_t)u.ru_minflt;r->major_faults=(uint64_t)u.ru_majflt;
        r->voluntary_switches=(uint64_t)u.ru_nvcsw;r->involuntary_switches=(uint64_t)u.ru_nivcsw;
    }
    mach_task_basic_info_data_t info={0};mach_msg_type_number_t count=MACH_TASK_BASIC_INFO_COUNT;
    r->mach_status=(uint32_t)task_info(mach_task_self(),MACH_TASK_BASIC_INFO,(task_info_t)&info,&count);
    if(r->mach_status==KERN_SUCCESS) {
        r->resident_bytes=info.resident_size;r->resident_peak_bytes=info.resident_size_max;r->virtual_bytes=info.virtual_size;
    }
}
static int lc_resource_ok(const LCResource *r) {return r->queried && !r->usage_status && !r->mach_status;}
static void lc_print_resource(const LCResource *r) {
    printf("{\"queried\":%u,\"usage_status\":%d,\"usage_errno\":%d,\"mach_status\":%u,",r->queried,r->usage_status,r->usage_errno,r->mach_status);
#define LC_U(field) printf("\"" #field "\":%" PRIu64 ",",r->field)
    LC_U(timestamp_ns);LC_U(user_cpu_ns);LC_U(system_cpu_ns);LC_U(maxrss_native);LC_U(resident_bytes);LC_U(resident_peak_bytes);LC_U(virtual_bytes);LC_U(minor_faults);LC_U(major_faults);LC_U(voluntary_switches);
#undef LC_U
    printf("\"involuntary_switches\":%" PRIu64 "}",r->involuntary_switches);
}
static void lc_print(const LongController *c,uint64_t worker_done_ns) {
    printf("{\"profile\":\"bounded-duration-controller-v1\",\"mode\":\"%s\",\"duration_ms\":%" PRIu64 ",\"event_period_ms\":%u,\"capacity\":%u,\"protection_ms\":%u,\"stall_limit_ms\":%u,\"controller_error\":%u,\"phase\":%u,\"clock\":\"CLOCK_MONOTONIC\",",c->smoke?"SMOKE_10_SECONDS":"FORMAL_AT_LEAST_30_MINUTES",c->duration_ms,LC_PERIOD_MS,LC_CAPACITY,LC_PROTECT_MS,LC_STALL_MS,c->error,c->phase);
    printf("\"start_ns\":%" PRIu64 ",\"first_ready_ns\":%" PRIu64 ",\"escape_begin_ns\":%" PRIu64 ",\"escape_end_ns\":%" PRIu64 ",\"worker_done_ns\":%" PRIu64 ",\"finish_ns\":%" PRIu64 ",\"max_gap_ns\":%" PRIu64 ",\"max_lateness_ns\":%" PRIu64 "}",c->start_ns,c->ready_ns,c->escape_begin_ns,c->escape_end_ns,worker_done_ns,c->finish_ns,c->max_gap_ns,c->max_lateness_ns);
}
#endif
