# Real lifted WndProc CPU component baseline

本模块对已冻结的 v6 产品中的真实 ARM64 `aot_window_proc_1000` 对象做有界测量。它直接调用 `aot_execute`，使用相同的 transaction engine，以及明确拒绝调用的 API stub。它不启动 App，不调用外层 `aot_wndproc_invoke` ABI 分发器，不执行 Cocoa 或 GPU，也没有接入旧的 block fastpath。因此结果不能解释为游戏 FPS、完整回调耗时或某次优化的加速比。

先做正确性验收，再单独允许测量。两个命令的输出目录都必须从未存在；失败日志保留，不能覆盖重跑。

```sh
python3.13 -B -m window_callback_bench_v1 prepare \
  --product /absolute/path/to/app-build-0001 \
  --probe /absolute/path/to/accepted-callback-probe \
  --out /absolute/path/to/new-prepare-01

python3.13 -B -m window_callback_bench_v1 measure \
  --prepared /absolute/path/to/new-prepare-01 \
  --out /absolute/path/to/new-measure-01 \
  --iterations 4096 --rounds 12
```

需要原生 Apple Silicon macOS、Python 3.13 及 Xcode command-line tools。`prepare` 会重新校验真实产品清单、PE/profile、回调根 manifest、switch candidate proof、实际对象、既有 probe 的 raw stdout 与完整响应；重新构造两基址的 image、permissions 和生成头文件，并逐项绑定产品实际编译源和当前 runtime 字节身份。使用 `clang -M` 收集真正参与编译的依赖，记录工具、依赖、源码、全部命令和产物 SHA-256。

`prepare` 将 harness/runtime 固定编译为 O3，分别链接产品原有 O0/O3 lifted 对象。在 preferred/rebased 两个 PE 基址、8 个 RIGHT 起点执行共 32 个回调；新输出的完整 State/image/stack 必须与原 probe golden 逐字节相同，且整个阶段不能调用计时器。O0 在这里仅是差分正确性基线。

`measure` 在任何原生执行之前重新检查全部身份和 32 例验收证据，只运行已经冻结的 O3 二进制。每个场景和路径先预热 256 次；每轮旋转场景顺序，execute/reset 路径交替。每批计时前额外执行 1 次并做完整比对；计时后也完整比对。每个计时迭代都包括完整 State/Context/image/stack 复位、关键不变量检查和 checksum。`reset` 控制路径同样执行复位、检查和 checksum，单列统计，**不做时间相减**。

最后一轮 execute 的实际 live State/image/stack 在计时区间之外复制进预分配快照，所有计时结束后再输出 `final-case-i.bin`；它必须再次与 golden 完全相同。计时样本保留原始 wall/thread CPU ns、执行次数和 checksum，Python 只按每次迭代计算 median/min/max，不删除慢样本。独立 reader 对 CPU 大于 wall 的记录保留 `CLOCK_ANOMALY_REQUIRES_REVIEW`，runner 的记录验收 PASS 不能替代性能时钟验收。首轮实测出现 7 条小逆差及调度扰动，仅发布描述性成本观察，见 [完整报告](../docs/WINDOW_CALLBACK_BENCH_V1.md)。

单基址、N iterations、R rounds 的执行账本为：timed callbacks = `8*R*N`；untimed callbacks = `8 + 8*256 + 8*R`；reset control iterations = `8*256 + 8*R*(N+1)`；所有 reset 次数 = `2*timed + 2*(untimed-8) + 8`。`reset_bytes_per_iteration` 是四个大 payload 的总字节数，另有 rejected-API 标量计数器复位。文件 I/O、分配、配置及完整快照比对不计入 batch 时间；复位、checksum、每迭代关键检查计入。

这是单机、顺序、热缓存的 CPU 组件基线；没有固定 CPU 亲和性、频率或温度，不能从这些数据推导 Wine/Rosetta 对比或端到端体验。CLI 限制 iterations 1..65536、rounds 1..20；Python `-O` 不会移除验收门禁。

Python 拒绝路径单测无需 native 执行：

```sh
python3.13 -B -m unittest window_callback_bench_v1.test_runner window_callback_bench_v1.test_review
python3.13 -O -B -m unittest window_callback_bench_v1.test_runner window_callback_bench_v1.test_review
```

`review.py` 是另行实现的只读证据复核器，不导入 runner 验收函数、不运行 native 命令；使用 `python3.13 -B -m window_callback_bench_v1.review --help` 查看其入口。检查通过仍只证明这里明确覆盖的 8 个 RIGHT 路径。
