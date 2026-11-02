# 指令查找优化：RAW 时钟与同进程成对实验

2026-11-02，本批实现、原生构建、正确性和独立采样复核通过。专用 RVA 二分查找在 16 个基址/输入场景中的配对 wall 中位耗时比为 **0.919087–0.928948**，各场景配对中位比值对应约 **7.1%–8.1%** 的耗时下降。192 组配对中 191 组候选更快、1 组更慢，所有样本保留。结论为 **Go：进入去掉实验选择器的单策略产物验证**；尚未改动正式产品运行时，也不构成 App、完整 ABI 或游戏提速结论。

## 与上一批的区别

新增 `window_callback_pair_v1`，原 `window_callback_bench_v1`、正式 `transaction_v1.c`、产品及原始 probe 保持原样，旧证据仍可读验。新构建复制六个运行时文件，只精确替换唯一的 `instruction()` 函数：保留原 PC 下界、32 位 RVA 范围和精确指令起始地址要求，reference 使用原 libc `bsearch`，candidate 直接在排序表中二分，返回同一个表元素指针或 NULL。

同一进程、同一 Context/State/映像/栈，通过共同的 volatile 策略读取与分支选择两条路径。这一额外开销计入两侧；它是受控实验，不能把本次比值当作去掉选择器后的部署性能。其他事务、权限检查、完整 State 快照、内部 CALL/RET、switch 和故障回滚均未改动。旧前缀快路径仍为 `NOT_INTEGRATED`。

## 时间源核对与观测

Apple 公开 Libc 的普通 `CLOCK_MONOTONIC` 路径经过微秒 `timeval`，RAW 路径使用 Mach 时间；这是与本机量化现象相容的实现解释，未证明公开 main 源码等于本机 Libc 的实际字节。[Apple 实现](https://raw.githubusercontent.com/apple-oss-distributions/Libc/main/gen/clock_gettime.c)

公开手册说明 RAW 不受时间/频率调整影响，`clock_getres` 的数值不是实际精度保证。本实验只对同一时间源的起止值作差，wall 主指标采用 `CLOCK_MONOTONIC_RAW`，线程 CPU 保持诊断项，不强制跨时钟不等式，不设任意容差、不扣除逆差。[Apple 手册](https://raw.githubusercontent.com/apple-oss-distributions/Libc/main/gen/clock_gettime.3)

独立 `clock-observation-01` 在本机 ARM64 上实际编译/执行，四个时钟各取 128 对相邻读数、三个 wall 时钟各取 16 个固定工作窗口；独立重算全部读数与工作 checksum：

| 时间源 | 报告分辨率 | 128 对读数中相等次数 | 本次 16 窗口 CPU>wall |
| --- | ---: | ---: | --- |
| MONOTONIC | 1000 ns | 121 | 2 条，125/417 ns |
| MONOTONIC_RAW | 42 ns | 7 | 0 |
| UPTIME_RAW | 42 ns | 6 | 0 |
| THREAD_CPUTIME | 42 ns | 0 | 不单独作为 wall 测窗口 |

这不是外部标准时钟校准。正式 prepare 又独立执行一次同样 probe，结果单列；不能混成一个实验。上一批 7 条逆差保持原记录，不删除、不改为通过。本批 960 条 callback 样本未见 CPU>wall，仍不能保证未来不会出现，也没有控制 CPU 亲和性、频率、温度或其他系统负载。

## 正确性与测量方法

- 继续链接 fresh07 已验产品的真实提升对象；harness/runtime 为 O3、无 LTO，正确性覆盖 O0/O3 两个提升对象、两基址和八个 RIGHT 起点。
- 正常输出共 64 份，完整 State/映像/栈逐字节匹配原 probe；同进程 candidate 与 reference 的私有 Context 亦完整比较。
- 每个场景从预算 0 到完成步数逐点比较，共 1456 对、2912 次回调，加正常 64 次，prepare 总计 2976 次。预算 0 是测试内部注入，不开放构造器的零预算输入。**完整预算状态比较在 C 中完成**；独立 reader 读取代码身份、成功退出和故障/trace/checksum 摘要，没有逐份导出的预算完整快照。
- 每配置 53 个查找 Context、169987 个逻辑查询，两策略分别与线性 oracle 核对指针结果；四配置合计 679948 个逻辑查询。包括反序输入后的排序、表首尾、空隙、指令内部、PC 下溢、32 位上界和高基址。查询前后 Context 与表均不变。
- 正式测量只运行 O3、两基址，每基址 8 场景 × 12 轮，每批 4096 次。偶轮 ABBA、奇轮 BAAB，场景顺序旋转；每组单列一次 reset 控制，在组前/后交替。每策略/场景预热 256 次。每组的 candidate 两批总 wall 除以 reference 两批总 wall，得到一个配对比值，再按基址/场景列 12 个比值，**不跨场景混算，不扣 reset，不滤慢样本**。
- 计时包含完整重置、真实事务回调、关键状态检查与 checksum；完整比较在每批前后，文件 IO/分配/最终快照复制在计时外。最后实际计时输出 32 份完整快照与原 probe 相同。没有外层 `aot_wndproc_invoke`、Cocoa、GPU、Steam 或游戏执行。

## 实测与决定

正式 `prepare-01`、`measure-01` 均首次执行成功。measure 两基址合计 **3154720 次实际回调**，其中计时 3145728 次、预热/检查 8992 次；另有 790720 次 reset 控制。加上 prepare，两个正式阶段共 3157696 次回调。独立 C smoke 的 744 次另记，时钟 workload 不计为回调。

| 起点 | preferred 中位 candidate/reference | rebased 中位 candidate/reference | preferred / rebased 更快组数 |
| --- | ---: | ---: | ---: |
| 0 | 0.928912 | 0.923164 | 12/12、12/12 |
| 1 | 0.923907 | 0.923616 | 12/12、12/12 |
| 2 | 0.928909 | 0.921306 | 11/12、12/12 |
| 3 | 0.919087 | 0.923089 | 12/12、12/12 |
| 4 | 0.921668 | 0.928948 | 12/12、12/12 |
| 5 | 0.924905 | 0.926063 | 12/12、12/12 |
| 6 | 0.922550 | 0.927298 | 12/12、12/12 |
| 7 | 0.927411 | 0.925249 | 12/12、12/12 |

正常变动与慢例均保留：preferred 起点 2 有一组候选更慢，ratio 1.026971；rebased 第 9 轮起点 5 的一条 reference 记录 wall 123834000 ns、CPU 26263750 ns，wall/CPU 约 4.715，对应异常低的配对比值 0.238284。不能用该慢例报告“提速四倍”，也不据零逆差宣布调度扰动已消除。

正式计时前已在 `work/window-callback-pair-protocol-01.json` 固定工程筛选规则：16 个场景中位比值都小于 1，且各自至少 8/12 配对更快，才进入单策略实验。此次全部满足。这个规则不是显著性检验、置信区间、稳定性能或部署验收；下一批仍须取得新产物的独立证据。

独立 reader 普通/`-O` 复核 4228 个文件身份、64 个正常完整响应、32 个实际计时末态、1456 对预算摘要和全部 960 条原始记录。runner 10 项、reader 22 项反例均在普通/`-O` 通过。reader 不导入 runner 的验收或汇总函数，独立验证精确 overlay、真实编译依赖/argv、查找计数、原 trace、ABBA 次序与所有比值。

证据位于 `build/window-callback-pair-v1/`：prepare 回执 SHA-256 `6657b9fec2d8789abae35c32b5e0a1835fadbe7ce26eca4dd93f0db019a9e7ea`；measure 回执 `f0fa2ba4f0912940cbdc873c0d94374a20f081251b24e9570166d806d2384dda`；普通/`-O` 独立报告逐字节相同，SHA `16f44811c3e627ce12c5b992e8c0a3990d3b99246e2f24693b71f377d941918b`。独立开发决定记录绑定计时前协议摘要。公开源码不携带本机 provider、基准二进制或完整原始数据；摘要不能替代原始文件的独立读验。

## 复现入口与下一批

先在同一源码位置取得 [v1 已验准备目录](WINDOW_CALLBACK_BENCH_V1.md)，以下输出均须使用新目录；review JSON 放在 prepare/measure 目录之外。需要原生 Apple Silicon、Python 3.13 和 Xcode，不需要 Steam。

```sh
python3.13 -B -m window_callback_pair_v1 prepare --baseline-prepared "$baseline_prepared" --out "$prepare_out"
python3.13 -B -m window_callback_pair_v1 measure --prepared "$prepare_out" --out "$measure_out" --iterations 4096 --rounds 12
python3.13 -B -m window_callback_pair_v1.review --prepared "$prepare_out" --measured "$measure_out" --out "$review_json"
python3.13 -O -B -m window_callback_pair_v1.review --prepared "$prepare_out" --measured "$measure_out" --out "$review_opt_json"
python3.13 -B -m unittest window_callback_pair_v1.test_runner window_callback_pair_v1.test_review
python3.13 -O -B -m unittest window_callback_pair_v1.test_runner window_callback_pair_v1.test_review
```

下一 AI 批次生成没有共享选择器的 reference/candidate 单策略产物，保持精确 lookup/故障语义和所有原状态门禁，检查编译产物并做交替进程对照；先验证组件收益能否保留，再考虑版本化接入正式运行时。其后才是外层 ABI、实际消息负载及 App 回归。本批不关闭一般 PE/线程/TLS/SEH、真实游戏、干净机器、整链性能和交付任务。
