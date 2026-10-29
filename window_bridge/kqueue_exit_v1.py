"""Darwin non-parent exit observation; never sends signals or starts processes.

Call register while the authenticated target is still alive, before permitting
its exit, then wait. This observes a PID, not an executable identity: callers
must bind process/path/start identity separately and must reject registration
races. No retry attaches to a replacement PID. Requires macOS 11+ permissions.
"""
from __future__ import annotations
import errno,os,select,sys
# Darwin ABI values, independently checked against the installed SDK in tests.
NOTE_EXITSTATUS=0x04000000
EV_RECEIPT=0x0040


def _require(value,message):
    if not value:raise ValueError(message)


def event_dict(event):
    return {key:int(getattr(event,key)) for key in ('ident','filter','flags','fflags','data','udata')}


def decode_wait_status(status):
    _require(type(status) is int and 0<=status<=0xffff,'invalid raw wait status')
    exited=os.WIFEXITED(status);signaled=os.WIFSIGNALED(status)
    _require(exited!=signaled,'event is not a terminal wait status')
    return {'raw_wait_status':status,'exited':exited,'exit_code':os.WEXITSTATUS(status) if exited else None,
            'signaled':signaled,'signal':os.WTERMSIG(status) if signaled else None,
            'core_dumped':bool(os.WCOREDUMP(status)) if hasattr(os,'WCOREDUMP') else None,
            'python_returncode':os.waitstatus_to_exitcode(status)}


class ExitWatch:
    """One non-retrying EVFILT_PROC registration, explicitly acknowledged."""
    def __init__(self,pid):
        _require(sys.platform=='darwin','Darwin-only NOTE_EXITSTATUS contract')
        _require(type(pid) is int and 1<pid<=0x7fffffff and pid!=os.getpid(),'invalid target PID')
        self.pid=pid;self.queue=select.kqueue();self.registration=None;self.consumed=False
        try:
            change=select.kevent(pid,filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD|select.KQ_EV_ENABLE|select.KQ_EV_ONESHOT|EV_RECEIPT,
                fflags=select.KQ_NOTE_EXIT|NOTE_EXITSTATUS)
            receipts=self.queue.control([change],1,0)
            _require(len(receipts)==1,'registration has no unique acknowledgement')
            ack=receipts[0];self.registration=event_dict(ack)
            _require(ack.ident==pid and ack.filter==select.KQ_FILTER_PROC and ack.flags&select.KQ_EV_ERROR,'unexpected registration acknowledgement')
            if ack.data:raise OSError(int(ack.data),os.strerror(int(ack.data)))
        except BaseException:self.close();raise

    def wait(self,timeout=5):
        _require(type(timeout) in (int,float) and 0<timeout<=2160,'bounded timeout required')
        _require(not self.consumed and self.queue is not None,'watch already consumed/closed')
        events=self.queue.control(None,1,timeout)
        if not events:raise TimeoutError('target did not exit within kqueue wait')
        _require(len(events)==1,'ambiguous process event')
        event=events[0]
        _require(event.ident==self.pid and event.filter==select.KQ_FILTER_PROC,'event belongs to another process')
        if event.flags&select.KQ_EV_ERROR:raise OSError(int(event.data),os.strerror(int(event.data)))
        _require(event.fflags&select.KQ_NOTE_EXIT and event.fflags&NOTE_EXITSTATUS,'exit status unavailable; do not infer success from zero data')
        result=decode_wait_status(int(event.data));self.consumed=True
        return {'pid':self.pid,'registration':self.registration,'event':event_dict(event),'termination':result}

    def close(self):
        if self.queue is not None:self.queue.close();self.queue=None

    def __enter__(self):return self
    def __exit__(self,*unused):self.close()
