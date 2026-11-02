/* Observe Darwin clock behavior without asserting cross-clock equivalence.
 * This is not a calibrated reference clock or an optimization benchmark.
 * The raw samples are intentionally printed without filtering or subtraction. */
#include <errno.h>
#include <inttypes.h>
#include <mach/mach_time.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#if !defined(__APPLE__) || !defined(__aarch64__)
#error Native Apple Silicon is required
#endif

enum { CLOCKS=4, WALLS=3, READ_PAIRS=128, WINDOWS=16, WORK_ITERATIONS=65536 };
static const clockid_t clocks[CLOCKS]={CLOCK_MONOTONIC,CLOCK_MONOTONIC_RAW,
    CLOCK_UPTIME_RAW,CLOCK_THREAD_CPUTIME_ID};
static const char *names[CLOCKS]={"CLOCK_MONOTONIC","CLOCK_MONOTONIC_RAW",
    "CLOCK_UPTIME_RAW","CLOCK_THREAD_CPUTIME_ID"};
typedef struct { uint64_t first,second; } ReadPair;
typedef struct { uint64_t wall_start,cpu_start,cpu_end,wall_end,checksum; } Window;
static volatile uint64_t sink;

static void require(bool value,const char *message) {
    if(!value){fprintf(stderr,"clock_probe: %s (errno=%d)\n",message,errno);exit(2);}
}
static uint64_t nanoseconds(struct timespec t) {
    require(t.tv_sec>=0 && t.tv_nsec>=0 && t.tv_nsec<1000000000,"invalid timespec");
    require((uint64_t)t.tv_sec <= (UINT64_MAX-(uint64_t)t.tv_nsec)/UINT64_C(1000000000),"timespec overflow");
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static uint64_t now(clockid_t clock) {
    struct timespec t;require(clock_gettime(clock,&t)==0,"clock_gettime");return nanoseconds(t);
}
/* Volatile recurrence makes all iterations observable. Its duration is not a
 * reference value and is never used to claim a clock's accuracy. */
__attribute__((noinline)) static uint64_t work(void) {
    volatile uint64_t value=UINT64_C(0x29dff4c8a1076e35);
    for(unsigned i=0;i<WORK_ITERATIONS;i++)
        value=(value^((uint64_t)i+UINT64_C(0x9e3779b97f4a7c15)))*UINT64_C(0xbf58476d1ce4e5b9);
    sink=value;return value;
}

int main(int argc,char **argv) {
    (void)argv;require(argc==1,"no arguments expected");
    uint64_t resolutions[CLOCKS];ReadPair reads[CLOCKS][READ_PAIRS];Window windows[WALLS][WINDOWS];
    mach_timebase_info_data_t timebase;
    require(mach_timebase_info(&timebase)==KERN_SUCCESS && timebase.numer && timebase.denom,"mach_timebase_info");
    for(unsigned c=0;c<CLOCKS;c++) {
        struct timespec t;require(clock_getres(clocks[c],&t)==0,"clock_getres");resolutions[c]=nanoseconds(t);
        require(resolutions[c]>0,"nonpositive reported resolution");
        for(unsigned i=0;i<READ_PAIRS;i++) {
            reads[c][i].first=now(clocks[c]);
            reads[c][i].second=now(clocks[c]);
        }
    }
    uint64_t expected=work();
    /* Rotate wall-source order to avoid always observing one source first. */
    for(unsigned i=0;i<WINDOWS;i++) {
        for(unsigned offset=0;offset<WALLS;offset++) {
            unsigned c=(i+offset)%WALLS;Window *w=&windows[c][i];
            w->wall_start=now(clocks[c]);w->cpu_start=now(CLOCK_THREAD_CPUTIME_ID);
            w->checksum=work();
            w->cpu_end=now(CLOCK_THREAD_CPUTIME_ID);w->wall_end=now(clocks[c]);
            require(w->checksum==expected,"workload checksum differs");
        }
    }
    printf("{\"schema\":1,\"status\":\"CLOCK_OBSERVATIONS_RECORDED\","
           "\"timebase_numer\":%u,\"timebase_denom\":%u,\"read_pairs_per_clock\":%u,"
           "\"windows_per_wall_clock\":%u,\"work_iterations\":%u,\"warmup_work_calls\":1,"
           "\"work_checksum\":%" PRIu64 ",\"sample_order\":\"wall_start,cpu_start,work,cpu_end,wall_end\","
           "\"clocks\":[",timebase.numer,timebase.denom,READ_PAIRS,WINDOWS,WORK_ITERATIONS,expected);
    for(unsigned c=0;c<CLOCKS;c++) {
        printf("%s{\"name\":\"%s\",\"resolution_ns\":%" PRIu64 ",\"adjacent_reads\":[",c?",":"",names[c],resolutions[c]);
        for(unsigned i=0;i<READ_PAIRS;i++)
            printf("%s[%" PRIu64 ",%" PRIu64 "]",i?",":"",reads[c][i].first,reads[c][i].second);
        printf("],\"work_windows\":[");
        if(c<WALLS)for(unsigned i=0;i<WINDOWS;i++) {
            Window *w=&windows[c][i];
            printf("%s{\"round\":%u,\"wall_start\":%" PRIu64 ",\"cpu_start\":%" PRIu64 ","
                   "\"cpu_end\":%" PRIu64 ",\"wall_end\":%" PRIu64 ",\"checksum\":%" PRIu64 "}",
                   i?",":"",i,w->wall_start,w->cpu_start,w->cpu_end,w->wall_end,w->checksum);
        }
        printf("]}");
    }
    puts("],\"scope\":\"Clock observations only; resolution is not an accuracy guarantee. Raw-source elapsed intervals and CPU intervals remain separate; no tolerance, filtering or subtraction.\"}");
    return 0;
}
