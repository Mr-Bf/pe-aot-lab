# DXMT 终止生命周期修复

本目录是固定 DXMT `d162ea44a31fbf9089ea09977337f0beb30bd082` 的本地独立补丁与构建入口，继承原 DXMT 许可。原始后端、清屏验收及失败时的二进制不修改。它没有修改 guest PE、Remill 语义或 Draw 方法，也没有在每次 Draw 加入等待。

## 触发与修复理由

同一个 Draw PE 在预算 190 结束时，已经提交 Draw，但尚未调用 Map。旧后端在三个独立进程的会话清理中均 SIGSEGV，栈落在着色器编译线程。完整反例在 [lifetime-failure](../../build/draw-bridge/lifetime-failure/README.md)。正常 Map 路径会同步先前工作，所以正常绘制通过不能推出提前终止安全。

补丁有三个相互配合的修改：

1. `MTLD3D11DeviceImpl` 析构体在 context/cache/Device 仍存活时调用已有 `WaitUntilGPUIdle()`。源码中该 fence 在 finish 线程完成 `waitUntilCompleted()`、重置 command chunk 后发出；它不是仅提交或完成编码的通知。
2. `PipelineCache::scheduler_` 移到最后一个数据成员。C++ 逆序析构因此先停止并 join 编译线程，再销毁 Shader、CompiledShader、pipeline 与依赖容器。GPU EVENT 完成并不等于所有编译线程已 join；这一步也处理未提交到 GPU 的编译任务。
3. scheduler 停止时在 `worker_mutex_` 内设置 `destroyed`，解锁后通知，随后在锁外 join。否则线程可能在读到 false 后、正式等待前错过通知。该交错来自条件变量的谓词检查与等待语义；是代码审查发现的风险，未把它伪称为本轮已观察到的卡死。[C++ 工作草案：condition_variable](https://eel.is/c++draft/thread.condition.condvar)

当前只支持单一 guest 调用线程的终止。没有证明任意后端线程执行最终 Release 时不会自等待，也没有承诺 GPU 永久挂起时有超时恢复。已有 `WaitCPUFence` 无超时；运行验证有外部测试进程监督，不能将它写成产品级设备丢失恢复。

## 版本与证据

第一候选只包含前两项，完成了干净构建和 Program 链接，**没有执行**。第三项在独立复审中加入后，该候选的代码、补丁和记录按哈希归档到 `build/graphics-stage5/lifetime-v2/history/`；原始 source/build 目录仍保留。正式候选 r2 使用新的源码/构建目录，避免覆盖原构建日志。

```sh
/opt/homebrew/bin/python3.13 graphics_stage5/lifetime_v2/build.py --jobs 2
/opt/homebrew/bin/python3.13 graphics_stage5/lifetime_v2/build.py --verify
```

首条仅适用于尚无该版本 source/build/evidence 的环境；已有尝试须保留记录，不会默认覆盖重建。`--verify` 只读核验固定基础树、精确补丁变换、实际工具、LLVM 安装树、完整新库集合和加载图，不启动 GPU 或 guest。

构建结果位于 `build/graphics-stage5/lifetime-v2-r2/evidence.json`。实际 guest 使用 `draw_bridge/bindings_v2.py`，仍保留原 `bindings.py` 以核对旧普通矩阵。新输出根名必须以 `-v2` 结束，防止写入旧验收目录。构建本身不是运行验收。本版后续已经通过[实际普通矩阵](../../build/draw-bridge/program-tests-v2/README.md)和[LLVM/C 插桩复核](../../docs/DRAW_BRIDGE_REVIEW.md)，具体计数、失败与限制分别记录。
