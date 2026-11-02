# 正式 switch 回调的 CPU 成本基线

2026-11-02，本批**实现、原生构建、32 例完整状态检查、原始采样与独立证据复核通过**。计时存在时钟逆差和调度扰动，只作为描述性成本观察；严格双时钟与稳定性能验收未通过，也没有优化提速结论。新增组件没有改变产品运行时或扩大游戏兼容范围。

## 本次测量对象

输入沿用公开源码 `99a271d` 在 fresh07 独立构建的正式窗口 App，以及已经通过完整状态检查的 callback probe。复用该产品实际生成的 `aot_window_proc_1000` O0/O3 ARM64 对象，不重新编译 Windows 源码替代二进制翻译。新增 `window_callback_bench_v1`，既有事务引擎与产品保持原样。

固定 WM_KEYDOWN/RIGHT，初始位置为 0–7；位置 0–6 执行 45 条 guest 指令，位置 7 执行 41 条。原始 probe 轨迹中每次均有一次内部 CALL、一次 switch 和两次 RET。preferred/rebased 两个映像基址分别为 `0x140000000` 与 `0x180000000`。不在本基准中执行导入 API、Cocoa、GPU 或 App；API stub 对调用明确拒绝。

**计时范围是完整输入重置 + 事务回调执行 + 关键不变量检查 + checksum。** 未执行外层 `aot_wndproc_invoke`，因此不包含完整 host→guest ABI 分派、TLS、回调帧保存/恢复与 Windows API 成本。当前产品没有集成旧 `window_block_fast_v1` / session 前缀快路径，状态为 `NOT_INTEGRATED`，不能表述成已启用但未命中，也不能引用旧实验收益作为本次收益。

## 正确性和计时协议

1. `prepare` 绑定产品、PE、proof、原始 probe stdout、完整状态文件、实际对象、运行时源码和编译器依赖；用 ARM64 clang 编译基准。运行时和 harness 始终 O3、无 LTO，O0/O3 标签仅指被链接的提升对象。
2. 先运行两基址 × 两优化级别 × 八输入，共 32 次不计时检查，完整 State、映像、栈逐字节匹配已验 probe。`measure` 在启动前重新校验全部绑定，任何变更均拒绝；计时后再次校验。
3. 正式计时只用 O3；每种输入及路径预热 256 次，默认每批 4096 次、12 轮。轮次旋转场景顺序，execute/reset 路径交替顺序。reset 控制保持相同循环、重置、关键检查和 checksum，但不调用提升函数，结果单列且不相减。
4. 每次迭代检查执行状态、steps、switch、返回和调用深度、API 拒绝计数及 checksum。完整 State、私有 Context、映像、栈、权限及指令表在每批前后核对；不能称每个计时迭代都做了完整逐字节比较。
5. 最后一轮实际 execute 批次的 live State/映像/栈在计时外复制到预分配缓冲区，全部计时完成后统一写出 `final-case-N.bin`，再次逐字节匹配原 probe。不是把初始预检的输出充当计时末态。
6. 记录 `CLOCK_MONOTONIC` 和 `CLOCK_THREAD_CPUTIME_ID`，顺序为 wall_start→cpu_start→batch→cpu_end→wall_end；保存全部原始样本，不删除慢样本。分配、绑定、文件 IO、完整比较与末态复制均在计时外。

基准按完整快照重置输入以固定工作量，属于热缓存、单进程顺序组件实验，不能等同于真实消息循环。没有固定 CPU 核、频率或温度，也没有 Windows/Wine＋Rosetta 配对。

## 本机实测与独立复核

环境为原生 ARM64 macOS 26.3.1、Python 3.13.5、Xcode 16.2。`prepare-01` 与 `measure-01` 均首次执行正常退出。State 3504 B、Context 5792 B、映像 20480 B、栈 65536 B，合计每次重置 95312 B，另有 API 标量计数器复位。

- prepare：32 个完整 State/映像/栈响应相同，零计时器调用。
- measure：两基址合计 790736 次真实回调，其中计时 786432 次、预热/校验 4304 次；另执行 790720 次 reset 控制。384 条原始批次记录全保留，计时末态 16 个完整响应与原 probe 相同。加上 prepare，本轮两个正式阶段共 790768 次回调；先前单独 C smoke 的 8 次不混入此账本。
- 独立 reader 不调用 runner 验收函数，也不启动进程：重新读取 4047 个文件身份、32 个准备响应、16 个计时末态及全部 384 条记录；普通和 `python -O` 报告逐字节相同。
- runner 的 10 项测试、独立 reader 的 26 项反例均在普通/`-O` 下通过，覆盖身份变更、矩阵/原始数据/完整输出、计时前拒绝及超时日志等边界。它们是纯 Python 验收测试，不能增加 native 或游戏成功数量。

下表单位为 **微秒/迭代**。“场景中位数范围”取八个场景各自 12 个样本的中位数，再列其最小/最大；不是置信区间。execute 包含完整重置及检查，reset 单列且没有相减。

| 基址 / 路径 | 场景 wall 中位数范围 | execute 全部原始样本范围 |
| --- | ---: | ---: |
| preferred / execute | 5.168–5.797 | 3.986–24.265 |
| rebased / execute | 5.462–7.353 | 4.601–18.792 |
| preferred / reset 控制 | 1.372–1.713 | — |
| rebased / reset 控制 | 1.532–2.002 | — |

**计时限制保留为未解决项。** 384 条中有 7 条 thread CPU 大于 wall，两条 execute、五条 reset，整批逆差为 166–500 ns；wall 报告分辨率 1000 ns，CPU 42 ns。这个差异与时钟量化/采样边界相容，但本轮没有证明根因，不删除样本、不扣除逆差、不任意设容差放行。独立结果保留 `performance_clock_status=CLOCK_ANOMALY_REQUIRES_REVIEW`。最大 wall/CPU 比约 4.013，亦说明有调度扰动；两基址顺序采样的差异不能归因于重定位成本。

`PASS_CALLBACK_CPU_BASELINE_MEASURED` 仅表示 runner 接受执行和原始记录；`PASS_INDEPENDENT_CALLBACK_CPU_REVIEW` 表示身份、输出及重算通过。两者均不能覆盖上述单独的性能时钟状态。下一轮先改进时钟/配对协议并实测验证，再评价优化。复核后附加的宿主观察中，CPU 品牌/内存的 `sysctl` 被沙箱拒绝，失败记录原样保留；不声称本轮控制了 CPU 频率或内存压力。

主要本机证据位于 `build/window-callback-bench-v1/`：

| 记录 | SHA-256 |
| --- | --- |
| `prepare-01/result.json` | `f5e9fe0ed99058f8df530a84b3934857ca8ebc767a544738489fd17fc1ffe45f` |
| `measure-01/result.json` | `7e2cb3097aa482ccbe270e4b16d2e9e4a23dfdaf8b4e980e328b926f8b336a3d` |
| `measurement-review-ordinary-01.json` 与 optimized 同字节 | `d996750d695c37615154153f40529e73ab91fef0937d056af692560cb4e52244` |

来源绑定：产品回执 `bb66b1c7a8de5569c951d9570be3ccde5642d4eb47d1da7619c86b610abc073d`，原 probe 回执 `6ee0375dd9cab3d0fcc67197d5f1e15bf5c95bfb35cbcdfa6171a78ba62bda0e`。C harness 摘要为 `387cfeb079052967307dad895b3e2e5eb43c87c127021a8bbd63ae1cbd0bcb6b`；完整源码、工具和依赖摘要由 prepare 回执保存。

## 复现实验入口

先按 [公开源码整链复现](PUBLIC_REPRODUCTION_V1.md) 取得一个 v6 switch 产品，并使用 `window_switch_v1.callback_probe` 对该产品取得 32 例正确性记录。以下变量必须指向同一产品和它的 probe；输出使用全新目录。需要原生 Apple Silicon、Python 3.13、Xcode/SDK；不需要 Steam、游戏账号或重新构建 LLVM。

```sh
python3.13 -B -m window_callback_bench_v1 prepare \
  --product "$product" --probe "$probe" --out "$prepare_out"
python3.13 -B -m window_callback_bench_v1 measure \
  --prepared "$prepare_out" --out "$measure_out" --iterations 4096 --rounds 12
python3.13 -B -m window_callback_bench_v1.review \
  --prepared "$prepare_out" --measured "$measure_out" --out "$review_json"
python3.13 -O -B -m window_callback_bench_v1.review \
  --prepared "$prepare_out" --measured "$measure_out" --out "$review_optimized_json"
python3.13 -B -m unittest window_callback_bench_v1.test_runner window_callback_bench_v1.test_review
python3.13 -O -B -m unittest window_callback_bench_v1.test_runner window_callback_bench_v1.test_review
```

review 输出文件应位于 prepare/measure 目录外，避免改变冻结目录的文件集。公开仓库仅携带源码、测试及本报告，不上传本机 provider、原始 App、基准二进制或完整实验日志。复核既有记录需要原始文件仍在其绑定位置；报告中的摘要本身不能替代原始证据。

## 后续开发边界

本批工具/采样验收完成，性能稳定性保持未完成。下一 AI 批次先校准时间源与成对采样协议；首个最小优化候选是 `transaction_v1.c` 的指令地址查找，保持精确起始地址、越界和 rebased 语义，保留完整状态和故障回滚。源码显示每条指令复制 State，不代表已经测得该项成本占比，暂不冒险删除快照。随后补外层 ABI 生命周期与真实消息负载成本。没有应用性能证据前，不关闭 S7 性能与交付阶段，也不宣布更快于 Wine＋Rosetta。

真实游戏验证另设入口：取得合法 Windows PE 和固定版本，先盘点指令、导入、模块、图形、线程/TLS/异常及 Steamworks 需求，再决定是否进入转换。当前自制样本通过不构成 Steam 游戏可迁移结论。
