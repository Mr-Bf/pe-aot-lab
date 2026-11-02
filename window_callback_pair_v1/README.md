# 同进程指令查找配对实验

本模块测试事务运行时的精确 RVA 查找：reference 使用既有 `bsearch`，candidate 使用专用二分查找。它在新输出目录复制运行时，并仅替换唯一、逐字匹配的 `instruction()` 函数；既有生产运行时、App 和 `window_callback_bench_v1` 保持原样。两路径使用同一 lifted ARM64 对象，并共同计入每条有效查找的 volatile 策略分派成本。这是实验实现，不等同于部署了某个单策略优化版本。

需要原生 Apple Silicon、Python 3.13、Xcode，以及上一模块已验的 prepare 目录；不需要 Steam 或新的 LLVM 构建。两个输出目录必须全新。

```sh
python3.13 -B -m window_callback_pair_v1 prepare \
  --baseline-prepared /absolute/path/to/window-callback-bench-v1/prepare-01 \
  --out /absolute/path/to/new-pair-prepare
python3.13 -B -m window_callback_pair_v1 measure \
  --prepared /absolute/path/to/new-pair-prepare \
  --out /absolute/path/to/new-pair-measure --iterations 4096 --rounds 12
```

prepare 复用旧产品/probe/32例来源验收，绑定全部源码、工具与真实编译依赖，编译原生 O0/O3 对象组合。它分别运行两基址、两优化级别：每个进程16个完整正常响应匹配原 probe，364个预算切点逐一比较两策略，合计2976次真实回调（正常64、预算2912）。每个预算切点的完整 State/私有 Context/映像/栈比较在 C 进程内完成；记录的是故障、深度、步数和 checksum，独立 reader 不声称重新读取了完整预算状态文件。lookup 检查另与线性 oracle 比较实际表和多种合成表，覆盖精确地址、指令内部地址、首末边界、缺失、变基址与整数边界。

时钟 probe 对四种时间源分别保存128对相邻读取，对三种 wall 源分别保存16个确定性工作窗口。校验单个时间源的单调性、正间隔和工作 checksum；保留所有跨时钟差异。它不是经过参考仪器校准的准确度证明。正式计时预先固定 `CLOCK_MONOTONIC_RAW` 为 wall 主指标，线程 CPU 只用于诊断，既不强制 CPU≤wall，也不按观测结果更换有利时间源。

measure 先后复核全部身份与准备证据，仅运行 O3。每个场景两策略和 reset 控制分别预热256次；偶数轮执行ABBA，奇数轮BAAB，场景按轮旋转，reset 控制按奇偶交替放在四个 execute 批次之前/之后。每批包含完整输入重置、回调、关键不变量检查和 checksum；完整状态比较、末态复制及文件IO在计时外。所有样本保留，不扣 reset。最终输出的两策略末态均须逐字节匹配原 probe。

对每个基址/场景/轮次，先将两个 candidate wall 区间求和，再除以两个 reference wall 区间之和；按轮列出比例，并报告 median/min/max 和快/慢/相同次数。不同基址或场景不混算，不给显著性、置信区间或游戏提速结论。共享分派、完整重置、热缓存、调度/频率/温度未隔离以及原组件没有外层 ABI/App/GPU 的限制均保留。

默认每基址：计时回调1572864次、未计时4496次，实际1577360次；reset控制395360次，额外创建reset参考态8次，总reset1972728次。两个基址共960条原始批次记录；新prepare和测量计数分开保存。只读独立复核入口：

```sh
python3.13 -B -m window_callback_pair_v1.review --help
python3.13 -B -m unittest window_callback_pair_v1.test_runner
python3.13 -O -B -m unittest window_callback_pair_v1.test_runner
```

公开源码不携带原产品、provider、基准二进制及本机全部原始日志；复核旧证据要求绑定的原始文件仍可访问。prepare 的成功不自动触发测量或 App 启动，也不表示完整 Windows ABI、一般 PE 或游戏兼容性已经扩大。
