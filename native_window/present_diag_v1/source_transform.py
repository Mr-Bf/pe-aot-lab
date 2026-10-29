"""Exact native-window-v2 source derivation; pure strings, no execution."""
TARGETS = ('src/dxmt/dxmt_command_queue.hpp', 'src/dxmt/dxmt_command_queue.cpp',
           'src/dxmt/dxmt_context.cpp', 'src/d3d11/d3d11_swapchain.cpp',
           'src/nativemetal/meson.build')

def derive(original):
    if set(original)!=set(TARGETS): raise ValueError('exact source target set')
    result=dict(original);changes=[]
    def edit(path,old,new):
        if result[path].count(old)!=1:raise ValueError('unique source shape: '+path+' '+old[:70])
        result[path]=result[path].replace(old,new)
        changes.append({'path':path,'old':old,'new':new})
    h=TARGETS[0];c=TARGETS[1];context=TARGETS[2];swap=TARGETS[3];meson=TARGETS[4]
    edit(h,'#include "dxmt_statistics.hpp"', '#include "dxmt_statistics.hpp"\n#include "dxmt_present_diag_internal_v1.hpp"')
    edit(h,'    statistics.encode_flush_interval += (t2 - t1);', '''    statistics.encode_flush_interval += (t2 - t1);
    present_diag_v1::record(diagnostics_, DXMT_PD_ENCODER, DXMT_PD_ENCODE_PREPARE,
                           frame_, chunk_id, t1 - t0);
    present_diag_v1::record(diagnostics_, DXMT_PD_ENCODER, DXMT_PD_ENCODE_FLUSH,
                           frame_, chunk_id, t2 - t1);''')
    edit(h,'  uint64_t signal_frame_latency_fence_;', '  uint64_t signal_frame_latency_fence_;\n  present_diag_v1::Queue *diagnostics_ = nullptr;')
    edit(h,'  dxmt::thread encodeThread;', '''  // Constructed before either encoder/completion thread starts.
  present_diag_v1::Queue present_diagnostics_;
  dxmt::thread encodeThread;''')
    edit(h,'''  FrameStatistics& CurrentFrameStatistics() {
    return statistics.at(frame_count);
  }''','''  FrameStatistics& CurrentFrameStatistics() {
    return statistics.at(frame_count);
  }

  present_diag_v1::Queue& PresentDiagnosticsV1() { return present_diagnostics_; }''')
    edit(h,'''      statistics.at(frame_count).present_latency_interval += (t1 - t0);
    }
    statistics.at(frame_count).latency = max_latency_;''','''      statistics.at(frame_count).present_latency_interval += (t1 - t0);
      present_diag_v1::record(&present_diagnostics_, DXMT_PD_WORKER, DXMT_PD_PRESENT_WAIT,
                             frame_count, CurrentSeqId() - 1, t1 - t0,
                             frame_count - max_latency_, max_latency_);
    } else {
      // Original early frames have NO clock sample, rather than a measured zero.
      present_diag_v1::record(&present_diagnostics_, DXMT_PD_WORKER, DXMT_PD_PRESENT_WAIT,
                             frame_count, CurrentSeqId() - 1, clock::duration::zero(),
                             0, max_latency_, 0, 0, 0, false);
    }
    statistics.at(frame_count).latency = max_latency_;''')
    edit(c,'''    chunk.queue = this;
    chunk.reset();''','''    chunk.queue = this;
    chunk.diagnostics_ = &present_diagnostics_;
    chunk.reset();''')
    edit(c,'''  TRACE("Destructing command queue");
  stopped.store(true);''','''  TRACE("Destructing command queue");
  const uint64_t diagnostic_submitted = ready_for_encode.load(std::memory_order_acquire) - 1;
  stopped.store(true);''')
    edit(c,'''  event_listener_thread.join();
  TRACE("Destructed command queue");''','''  event_listener_thread.join();
  // Preserve all original joins/reset order. No new GPU drain or wait is added.
  present_diagnostics_.close(true, diagnostic_submitted, cpu_coherent.signaledValue());
  TRACE("Destructed command queue");''')
    edit(c,'''  statistics.commit_interval += (t1 - t0);''','''  statistics.commit_interval += (t1 - t0);
  present_diag_v1::record(&present_diagnostics_, DXMT_PD_WORKER, DXMT_PD_COMMIT_WAIT,
                         frame_count, chunk_id, t1 - t0, kCommandChunkCount - 1);''')
    edit(context,'''      currentFrameStatistics().drawable_blocking_interval += (t1 - t0);''','''      currentFrameStatistics().drawable_blocking_interval += (t1 - t0);
      present_diag_v1::record(&queue_.PresentDiagnosticsV1(), DXMT_PD_ENCODER,
                             DXMT_PD_DRAWABLE_ENCODE, currentFrameId(), currentSeqId(), t1 - t0);''')
    edit(swap,'''    auto &cmd_queue = device_->GetDXMTDevice().queue();
    auto chunk = cmd_queue.CurrentChunk();''','''    auto &cmd_queue = device_->GetDXMTDevice().queue();
    present_diag_v1::record(&cmd_queue.PresentDiagnosticsV1(), DXMT_PD_WORKER,
                           DXMT_PD_PRESENT_META, cmd_queue.CurrentFrameSeq() - 1,
                           cmd_queue.CurrentSeqId(), clock::duration::zero(), 0,
                           cmd_queue.GetMaxLatency(), SyncInterval, PresentFlags,
                           preferred_max_frame_rate, false);
    auto chunk = cmd_queue.CurrentChunk();''')
    edit(meson,"  'native_wsi.c',", "  'native_wsi.c',\n  'present_diagnostics_v1.cpp',")
    return result,changes
