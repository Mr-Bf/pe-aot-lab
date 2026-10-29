"""Exact controller-only delta from the frozen short-run native host."""
from pathlib import Path
import hashlib
HERE=Path(__file__).resolve().parent
HOST_SHA='b83c847bf33e98fefab70d8c01ce7db64b2eb846024a40b1ccda2f8f450c1c38'
MAIN_START=r'''    Run r={0};r.base=kPreferredBase;r.budget=UINT64_C(100000000);
    static LongController control;LCResource resource_start={0},resource_ready={0},resource_finish={0};
    uint64_t duration_ms=0,period_ms=LC_PERIOD_MS;int mode=0;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--data-dir")&&i+1<argc)r.directory=argv[++i];
        else if(!strcmp(argv[i],"--base")&&i+1<argc){if(!number(argv[++i],&r.base))return host_error("invalid base");}
        else if(!strcmp(argv[i],"--budget")&&i+1<argc){if(!number(argv[++i],&r.budget)||!r.budget||r.budget>100000000)return host_error("invalid bounded budget");}
        else if(!strcmp(argv[i],"--duration-ms")&&i+1<argc){if(mode||!number(argv[++i],&duration_ms))return host_error("one explicit duration mode required");mode=1;}
        else if(!strcmp(argv[i],"--smoke-duration-ms")&&i+1<argc){if(mode||!number(argv[++i],&duration_ms))return host_error("one explicit duration mode required");mode=2;}
        else if(!strcmp(argv[i],"--event-period-ms")&&i+1<argc){if(!number(argv[++i],&period_ms))return host_error("invalid period");}
        else return host_error("usage: --data-dir directory (--duration-ms 1800000 | --smoke-duration-ms 10000) [--event-period-ms 250] [--base value] [--budget value]");
    }
    if(!mode||!lc_configure(&control,duration_ms,period_ms,mode==2))return host_error("unsupported bounded duration profile");
'''
LOOP=r'''    int timed_out=0,queue_stopped=0;
    while(!atomic_load_explicit(&r.done,memory_order_acquire)){
        wb_host_pump_once(r.host,0.005);WBHostStats stats={0};wb_host_stats(r.host,&stats);
        uint64_t hwnd=atomic_load_explicit(&observed_hwnd,memory_order_acquire),now=lc_now_ns();
        if(now<control.start_ns){control.error=LC_CLOCK_INVALID;}
        else if(now-control.start_ns>=LC_PROTECT_MS*LC_NS_PER_MS){timed_out=1;if(!control.error)control.error=LC_PROTECT_TIMEOUT;}
        int eligible=hwnd&&stats.waits>control.last_wait&&!stats.pending_messages&&!stats.paint_invalid;
        uint64_t old_ready=control.ready_ns;int kind=lc_offer(&control,now,eligible);
        if(!old_ready&&control.ready_ns){lc_resource(&resource_ready);if(!lc_resource_ok(&resource_ready))control.error=LC_RESOURCE_FAILED;}
        if(kind>=0&&!control.error){
            const LCSpec*spec=lc_spec((unsigned)kind);uint64_t begin=lc_now_ns();
            int success=wb_host_test_post(r.host,hwnd,spec->message,spec->key,spec->bits);
            lc_posted(&control,(unsigned)kind,begin,lc_now_ns(),stats.waits,success);
        }
        if(control.error&&!queue_stopped){wb_host_session_end(r.host);queue_stopped=1;}
    }
'''
POST_FINISH=r'''    control.finish_ns=lc_now_ns();lc_resource(&resource_finish);
    if(!control.error&&!control.escape_end_ns)control.error=LC_EARLY_EXIT;
    if(!control.error&&(!lc_resource_ok(&resource_start)||!lc_resource_ok(&resource_ready)||!lc_resource_ok(&resource_finish)))control.error=LC_RESOURCE_FAILED;
    int inject_error=(int)control.error;
'''
PRINT_EVENTS=r'''for(unsigned i=0;i<control.posted;i++){
        const LCEvent*e=&control.events[i];
        printf("%s{\"name\":\"%s\",\"origin\":%u,\"wait_count\":%" PRIu64 ",\"elapsed_ms\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 ",\"post_begin_ns\":%" PRIu64 ",\"post_end_ns\":%" PRIu64 "}",i?",":"",lc_spec(e->kind)->name,WB_ORIGIN_TEST_QUEUE,e->wait_count,(e->begin_ns-control.ready_ns)/LC_NS_PER_MS,e->begin_ns-control.ready_ns,e->begin_ns,e->end_ns);
    }printf("]},\"observations\":{");'''

def expected_host():
    original=(HERE/'window_host.c').read_bytes()
    if hashlib.sha256(original).hexdigest()!=HOST_SHA:raise ValueError('frozen host changed')
    text=original.decode()
    def replace(before,after):
        nonlocal text
        if text.count(before)!=1:raise ValueError('host delta anchor differs: '+before[:80])
        text=text.replace(before,after)
    replace('#include "cocoa_host.h"\n','#include "cocoa_host.h"\n#include "long_controller_v1.h"\n')
    replace(',MAX_TEST_EVENTS=64','')
    replace('    atomic_bool done;','    atomic_bool done;uint64_t worker_done_ns;')
    a=text.index('static uint64_t milliseconds(');b=text.index('static int host_error(',a);text=text[:a]+text[b:]
    replace('wb_host_session_end(r->host);atomic_store_explicit','wb_host_session_end(r->host);r->worker_done_ns=lc_now_ns();atomic_store_explicit')
    a=text.index('typedef struct {uint32_t message;uint64_t key;int64_t bits;const char*name;} TestEvent;');b=text.index('static void print_file(',a);text=text[:a]+text[b:]
    a=text.index('    Run r={0};r.base=kPreferredBase;');b=text.index('    if(!r.directory',a);text=text[:a]+MAIN_START+text[b:]
    replace('    r.host=wb_host_create();','    control.start_ns=lc_now_ns();lc_resource(&resource_start);\n    if(!lc_resource_ok(&resource_start))return host_error("resource snapshot failed");\n    r.host=wb_host_create();')
    a=text.index('    uint64_t start=milliseconds()');b=text.index('    int join_status=',a);text=text[:a]+LOOP+text[b:]
    replace('    const char*outcome=',POST_FINISH+'    const char*outcome=')
    replace(r'\"requested\":%zu,\"posted\":%zu',r'\"requested\":%u,\"posted\":%u')
    replace('event_count,posted,inject_error,atomic_load','control.requested,control.posted,inject_error,atomic_load')
    a=text.index('    for(size_t i=0;i<posted;i++)');b=text.index('\n    for(size_t i=0;i<kObservationCount',a);text=text[:a]+'    '+PRINT_EVENTS+text[b:]
    replace('print_file(r.directory);printf("}\\n");','print_file(r.directory);printf(",\\"long_run\\":");lc_print(&control,r.worker_done_ns);printf(",\\"resources\\":{\\"start\\":");lc_print_resource(&resource_start);printf(",\\"first_ready\\":");lc_print_resource(&resource_ready);printf(",\\"finished\\":");lc_print_resource(&resource_finish);printf("}}\\n");')
    return text

if __name__=='__main__':
    path=HERE/'window_host_long_v1.c'
    with path.open('x') as stream:stream.write(expected_host())
