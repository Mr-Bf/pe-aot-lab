# 独立单策略回调产物

本模块分别构建 reference/candidate ARM64 二进制，不包含上一实验的 volatile 策略选择器。reference 使用原运行时六个文件的完整字节；candidate 仅替换精确匹配的 `instruction()` 查找函数。两者链接同一既有产品的真实提升对象，现有生产源码、App、v1基准与pair实验不修改。

```sh
python3.13 -B -m window_callback_single_v1 prepare \
  --baseline-prepared /absolute/path/to/window-callback-bench-v1/prepare-01 \
  --out /absolute/path/to/new-single-prepare
python3.13 -B -m window_callback_single_v1 measure \
  --prepared /absolute/path/to/new-single-prepare \
  --out /absolute/path/to/new-single-measure --iterations 4096 --rounds 12
```

需要原生 Apple Silicon macOS、Python 3.13、Xcode及系统zlib，不需要Steam或重新构建LLVM。输出目录必须全新；失败命令及原始记录保留，不覆盖重试。prepare不会自动开始计时。

prepare 复核既有v1的产品/probe/源身份，生成两份运行时副本，编译2策略×O0/O3提升对象。harness/runtime保持O3、无LTO。每个真实二进制保存nm undefined/full symbols与otool反汇编；reference须有外部`_bsearch`、candidate须无此导入，均无实验selector符号。该工具核对结合精确源码生成，不宣称是完整机器代码语义证明。

每策略/提升优化级别/基址实际执行8个正常回调和364个预算切点；8进程合计2976回调，其中正常64、预算2912，零回调计时。每个预算导出State、映像、栈与规范化Context，按固定95328字节record保存为gzip stream；读取时验证header、偏移、精确总长及EOF，不向磁盘展开约277MB预算原始数据。两个基址各用reference/O0作锚，与另外三个产物逐record完整比较，计2184次比较；这与逻辑预算位置或回调次数分别列账。

Context仅将明确的宿主指针槽规范化：instructions固定tag、current转表索引、两个region的backing/permission转region tag、pending host byte指针转guest VA、NULL保持零；所有其他Context字节均保留，包含未激活条目、快照与padding。规范化前C核对指针所属对象/范围；Python校验规范化布局声明并跨产物逐字节比较。不能跨进程直接比较未规范化的宿主地址。

measure按两个基址，各12组，偶组ABBA、奇组BAAB启动四个独立O3进程，共96进程。每进程旋转8场景，各计一批execute与一批reset，每批默认4096次；两路径各预热256次，reset前后顺序交替。计时区间只含完整输入重置、回调、关键不变量和checksum；分配、进程启动、完整比较、快照复制及文件IO在计时外。正常Context还须匹配prepare，实际计时末态须匹配原golden和本进程正常Context。

默认每进程计时32768次、未计时2064次、实际34832次回调，另34824次reset控制，总reset69656次。96进程共3343872次回调，其中计时3145728、未计时198144；1536条计时记录全部保留。对每个基址/场景/组的两个candidate wall区间求和，再除两个reference wall区间之和，保留12组ratio及快/慢/相同次数，不扣reset、不滤样本、不跨场景混算。

`CLOCK_MONOTONIC_RAW`为主时间源，线程CPU仅诊断；逆差仍报告，不设任意容差。多进程启动和调度、温度/频率、热缓存状态均可能影响批次，未控制CPU亲和性。这是独立CPU组件，不等于正式App runtime已接入，没有外层ABI、图形、Steam游戏或Wine/Rosetta对照结论。

```sh
python3.13 -B -m window_callback_single_v1.review --help
python3.13 -B -m unittest window_callback_single_v1.test_runner window_callback_single_v1.test_review
python3.13 -O -B -m unittest window_callback_single_v1.test_runner window_callback_single_v1.test_review
```

独立reader不调用runner验收函数；公开副本仅携带源码与测试，不含原产品/provider、测量二进制和本机原始现场。复核既有记录需其绑定的完整文件仍可访问。
