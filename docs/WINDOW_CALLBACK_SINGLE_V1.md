# 无选择器的独立指令查找产物

2026-11-02，reference/candidate 独立产物已构建并通过完整状态验证；96 个交替进程完成采样。16 个基址/输入场景的配对 wall 中位比值对应约 **5.9%–8.6%** 耗时下降，192 组中 189 组候选更快、3 组更慢。按计时前固定规则，**Go：版本化接入正式运行时并做 App 回归**。当前仍是 CPU 组件结果，正式 App 未改动，不能推断完整 ABI、游戏 FPS 或 Wine/Rosetta 优势。

## 本批实现

新增 `window_callback_single_v1`，复用 v1 已验准备目录中的真实提升 O0/O3 ARM64 对象。reference 使用原运行时文件；candidate 在新输出目录仅精确替换唯一 `instruction()` 函数为专用 RVA 二分查找。两个策略分别编译为不同 Mach-O；没有上一批共同的 volatile 策略选择器，构建宏只选择输出标签。

四个实际二进制均记录编译依赖、`nm -u/-a` 与 `otool -tvV` 输出。reference O0/O3 均保留 `_bsearch` 引用；candidate O0/O3 均无该引用，均无原选择器符号。结合精确源码差分和实际反汇编检查确认实验对象；这些检查不是穷尽机器码语义证明。旧事务运行时、旧基准、产品和所有旧证据保持原样。

原来精确指令起始地址、PC/RVA 范围、权限、完整 State 快照、CALL/RET、switch、预算和回滚逻辑保留。未知指令或非法地址没有被静默放行。本批未执行任何 Steam、Cocoa、GPU 或外层 `aot_wndproc_invoke` 路径。

## 完整状态与故障验证

准备阶段覆盖两策略 × 两提升优化级别 × 两基址，8 个进程：正常响应 64 份；每进程 364 个预算截断点，共 2912 次预算回调，加正常回调共 **2976 次**。零预算仍仅在测试内部注入，构造器合同不变。每配置 53 个查找 Context、169987 个逻辑查询对线性 oracle，通过首末、间隙、指令内部、整数上界与高基址等边界。

本批新增导出全部预算状态，使用系统 zlib 压缩。每记录包含场景/预算/状态头、完整 State、映像、栈和规范化 Context；每个配置解压后 34699392 B，单份压缩约 1.5 MB。正常与实际计时末态均另存 State/映像/栈文件和规范化 Context 文件。

跨进程比较前只规范化 Context 的宿主指针：验证 instructions 的身份、将 current 编码为表元素序号、区域指针编码为区域序号、pending 指针映射回 guest 地址；NULL 保留，D3D 权限指针必须为空。其他字节完整保留，未将指针字段直接清零以掩盖不同引用。完整状态和预算结果均来自实际执行，不由宿主重写 guest 逻辑。

独立读取 2912 个完整预算记录并校验 gzip 长度/尾字节、结果、原 trace 与 Context；在每个基址以第一份配置对照另外三份，共 **2184 次完整预算记录比较**，另比较正常 Context。与上一批只导出预算摘要的证据范围明确区分。

## 固定测量方法

使用 `CLOCK_MONOTONIC_RAW` 为 wall 主指标，线程 CPU 只用于诊断；时间源依据和有限观测见 [前批报告](WINDOW_CALLBACK_PAIR_V1.md)。没有外部准确度校准或 CPU 亲和性/频率/温度隔离。

每基址 12 组，偶组进程顺序 ABBA、奇组 BAAB，共 96 个 O3 进程。每进程执行八场景，各自预热 256 次，execute/reset 每批 4096 次，场景及路径顺序旋转。每组/场景以两次 candidate 批次总 wall 除以两次 reference 批次总 wall，再汇总 12 个比值。不同基址/场景不混算，不滤慢样本、不扣 reset。

计时包含完整重置、真实回调、关键检查及 checksum；分配、进程启动、配置、完整状态比较及文件写入均不计。每批前后完整比较，实际计时末态再写出，与原 probe 和准备阶段 Context 核对。全新的进程、地址布局和预热条件与上一批不同，因此不能把两轮收益范围之差直接归因于选择器成本。

计时前协议保存在 `work/window-callback-single-protocol-01.json`：16 场景中位比值均小于 1，且各至少 8/12 配对更快，才推进运行时集成。它是工程筛选规则，不是显著性或稳定性能证明。

## 实测结果

| 起点 | preferred 中位 candidate/reference | rebased 中位 candidate/reference | preferred / rebased 更快组数 |
| --- | ---: | ---: | ---: |
| 0 | 0.938625 | 0.922297 | 12/12、12/12 |
| 1 | 0.935563 | 0.928891 | 12/12、12/12 |
| 2 | 0.920533 | 0.941109 | 12/12、10/12 |
| 3 | 0.927229 | 0.934570 | 12/12、11/12 |
| 4 | 0.933405 | 0.927255 | 12/12、12/12 |
| 5 | 0.927136 | 0.914080 | 12/12、12/12 |
| 6 | 0.936095 | 0.929637 | 12/12、12/12 |
| 7 | 0.931187 | 0.939397 | 12/12、12/12 |

测量阶段实际 **3343872 次回调**，其中计时 3145728 次、预热/检查 198144 次；reset 控制另有 3343104 次。1536 条原始批次全部保留，768 个实际计时末态与规范化 Context 通过。加准备阶段，两个正式阶段共 3346848 次回调；独立 smoke 的 744 次另记。

本次未观察到 CPU>wall。仍有显著慢例：rebased 第 10 组 slot 0 的 reference/场景 5，wall 72408875 ns、CPU 29486625 ns，比约 2.456；rebased 场景 2 的最高配对比值为 1.577532。三组候选更慢的记录未删除。不能用极端比值或零逆差宣称调度干扰消失。

独立 reader 普通/`-O` 报告逐字节相同，核对 7856 个文件身份、64 个准备正常响应、2912 个完整预算记录、2184 次跨产物比较、测量阶段的 768 个正常响应与 768 个计时末态，以及全部 1536 条记录。runner 11 项、reader 24 项反例测试普通/`-O` 通过；覆盖源变更、gzip 截断/尾字节/完整状态差异、Context 规范化、进程次序与样本保留等门禁。

prepare 和 measure 均首次执行成功。原始证据在 `build/window-callback-single-v1/`。prepare 回执 SHA-256 为 `925e63fc4664cfe035d86061343c10eb5b4d94bff45c87eb0963f4676d5957ce`；measure 为 `fbef94bf8ec37c5aa61996f55cdb4a03eb33bfab1198a86cdb51037b4bc14002`；独立报告为 `acc49a9ab876b689f8c688a2000176477f488544fbd23bf1e58a598d58534fb8`。公开源码不上传本机 provider、完整状态或基准二进制，不能仅凭文中摘要替代原始读验。

## 开发入口与下一批

```sh
python3.13 -B -m window_callback_single_v1 prepare --baseline-prepared "$baseline_prepared" --out "$prepare_out"
python3.13 -B -m window_callback_single_v1 measure --prepared "$prepare_out" --out "$measure_out" --iterations 4096 --rounds 12
python3.13 -B -m window_callback_single_v1.review --prepared "$prepare_out" --measured "$measure_out" --out "$review_json"
python3.13 -O -B -m window_callback_single_v1.review --prepared "$prepare_out" --measured "$measure_out" --out "$review_opt_json"
python3.13 -B -m unittest window_callback_single_v1.test_runner window_callback_single_v1.test_review
python3.13 -O -B -m unittest window_callback_single_v1.test_runner window_callback_single_v1.test_review
```

prepare/measure 输出必须为新目录；review 输出必须为尚不存在的 JSON 文件，并位于准备/测量目录之外。需要原生 Apple Silicon、Python 3.13、Xcode 与已验 v1 准备目录；无需重建 LLVM 或提供 Steam 游戏。

下一 AI 批次为版本化 runtime/producer 接入，生成新的正式 App，保留 baseline 对照；重新验证真实入口、callback、图形、存取档、退出与搬移。通过后再测完整 ABI 和真实消息负载的成本。当前收益仅为八种受控 RIGHT 路径；一般 PE、线程/TLS/SEH、更广图形和实际游戏适配仍未完成。
