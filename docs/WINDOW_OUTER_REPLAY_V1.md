# 外层 ABI 同地址重放 v1：实际实验报告

日期：2026-11-02。最终状态：`PASS_UNTIMED_OUTER_REPLAY_INDEPENDENTLY_REVIEWED`，以修复后的reader02验收。**固定自制PE的两个正常消息边界已在同一原生进程、同一组地址上重复执行并恢复真实continuation**；四个配置全部原生正常退出。自审发现的12项reader漏验已修复，两种Python模式重新读验同一批原始证据通过，各通过51项测试并拒绝396项轨迹副本变异。首版01仅作有已知缺口的历史记录。本轮没有转换新的第三方应用或游戏，也没有测量性能。

设计约束见[同地址重放合同](WINDOW_OUTER_REPLAY_CONTRACT_V1.md)，前批无重放结果见[single-pass报告](WINDOW_OUTER_ABI_V1.md)。[完整外层设计](WINDOW_OUTER_ABI_NEXT_V1.md)仍保留为历史路线，本次通过只关闭其中限定的正常路径纵切，不等于整个A0／A3／性能阶段完成。

## 1. 实际运行了什么

本轮新增`window_outer_replay_v1`生成器、恢复观察层、构建/运行入口、独立reader和纯文件测试。生产runtime、User32、callback、guest PE和前批single-pass版本没有被改写。生成器在新目录中仅改名原import/callback入口、加入RET观察点及新诊断代码；reference保留原bsearch查找，inline替换为已冻结的inline lookup。

复用的产品是仓库内`build/window-lookup-v1/app-01`，receipt SHA256为`cd28493d3f7f3afd3851af9586cbb7d79a44250801c40df73f73f2815924419a`。其原PE为自制`switch_tile.exe`，SHA256为`39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`。本轮直接复用已经提升的main、WndProc、import RET及三份后端对象，分别选取guest O0/O3对象；**没有重新提升第三方程序，也没有重建第三方工具链或生成新的生产App**。

新编译部分是带参数的原host和两个诊断runtime，均为O3、无LTO；原产品的noarg入口shim没有参与链接。四个程序为reference／inline × guest O0／O3。运行于本机Apple Silicon macOS，实际编译器回执为Apple clang16.0.0、target `arm64-apple-darwin25.3.0`。新可执行文件通过ARM64 Mach-O与签名检查，dyld日志包含实际已冻结D3D11／DXGI／WineMetal后端路径。

每个进程使用独立空data/cache目录，从真实PE main初始化Cocoa／Metal／User32／callback会话，通过明确标注的`TEST_QUEUE right,right-up,escape`进入两个正常DispatchMessageA边界。没有手写owner启动状态，没有直接调用孤立WndProc代替main，没有模拟返回结果；输入不是系统键盘事件。全部进程只调用一次顶层`aot_execute`。

## 2. 重放与恢复合同的实际落地

观察点只允许正常主循环signature214、RVA5839／`0x16cf`、R12、目标`base+0xf00d6000`，实际RET返回RVA5842。退出drain循环6051／RDI仍不接受。KEYUP内部真实DefWindowProcA为signature212、RVA4248／`0x1098`、目标`base+0xf00d4000`；未知或额外nested API在执行前被拒绝。

每个选定消息先捕获原始边界，随后执行diag0、原地址恢复、diag1、再次原地址恢复、continuation。前两轮只固定MSG偏移32…43的12B：time=`0x12345678`、坐标100／200，字节为`7856341264000000c8000000`。最后一轮恢复真实GetMessage生成的完整原始MSG。HWND、message、WPARAM、LPARAM和padding从未列入修改白名单。

恢复对象包括完整3504B State、5792B Context和六个guest backing的全部字节，始终使用原地址；instruction table和region descriptor先核验身份及内容。权限表逐字节确认不变，保持原指针原内容，**不写入const权限表**。固定host的六个backing由malloc/calloc分配；Map arena是native映射的独立CPU shadow，不是Metal共享映射。

构建器和reader新增固定host源SHA门禁：`window_bridge/window_host.c`必须为`9b79aa34c0cfc6302f34d354b39d6bae9678b6b7efe6fe805ddbd7d072e04919`，并同时出现在已审产品与新编译输入账本中。因此不会把“有六个region”误当成任意loader都可写回的证明。恢复前还拒绝fault、Exit latch、returned以及未完成的instruction/pending事务；nested212显式检查原返回对象、owner、原frame RIP/RSP/depth和真实RET数量。

宿主D3D、File、User32、Callback和Cocoa会话不恢复。D3D和文件业务状态保持原样；User32／callback只允许实际发生的API、posted、callback calls/returns及max-depth变化。Context.steps/switch_commits随guest边界恢复，诊断执行量则记在外部单调账本，原TLS计数真实累加。

## 3. 原生执行结果

`build/window-outer-replay-v1/build-01`执行24条编译、依赖、链接及签名命令，全部exit0。`run-01`按以下顺序串行运行；每个进程之前和之后的项目进程检查均为空，没有超时或中断。

| 配置 | 实际PID | OS退出码 | proc_translated / errno | 事件 / 完整快照 | 最终guest steps / switch |
|---|---:|---:|---|---|---|
| reference-O0 | 43198 | 0 | 0 / 0 | 50 / 26 | 809 / 1 |
| inline-O0 | 43211 | 0 | 0 / 0 | 50 / 26 | 809 / 1 |
| reference-O3 | 43220 | 0 | 0 / 0 | 50 / 26 | 809 / 1 |
| inline-O3 | 43223 | 0 | 0 / 0 | 50 / 26 | 809 / 1 |

四个host均报告`PROCESS_EXITED`、setup_status0、guest exit_code0、host_finished=true。内部`aot_status=11`表示当前runtime的正常process-exit枚举，不是OS退出码11。`proc_translated=0`及errno0支持这四个实际进程没有经Rosetta运行；不把它外推为任意第三方依赖或其他程序均已验证。

每个进程产生六个选定调用区间：RIGHT三轮和KEYUP三轮，其中四轮诊断、两轮continuation、四次原地址reset。四进程合计200个事件、104份完整快照、24个选定callback区间（16诊断＋8continuation）。**实际native进程数是4，重复reader、单元测试和单进程中的诊断轮都不增加native进程数。**

| 每轮真实调用链 | RIGHT（每进程3轮） | KEYUP（每进程3轮） |
|---|---:|---:|
| guest steps | 46 | 18 |
| callback区间steps | 45 | 17 |
| import RET数 | 1 | 2 |
| 嵌套真实212次数 | 0 | 1 |
| switch_commits增量 | 1 | 0 |
| 独立语义 | position3→4、moves+1、keydowns+1、dirty=1、返回0 | sample/Observations无修改、真实DefWindowProcA返回0 |

每进程selected账本最终为`diagnostic_calls=4, continuation_calls=2, reset_count=4, total_guest_steps=192, total_switch_commits=3`。最终原main的Context仍为809步／1次switch；两次RIGHT诊断额外92步、两次KEYUP诊断额外36步，共128步，因此按分账推导全过程实际执行809+128=937个guest步骤。该推导解释重复执行量，不是计时或吞吐量结果。

宿主最终callback calls=returns=13、rejections=0、depth=0、max_depth=1，User32 callbacks13、posted_dispatches8。生产main保留一次RIGHT语义，诊断没有把tile推进三次。四进程均真实Present3次／Draw3次，创建8个D3D对象并由guest释放8个；cleanup后live_objects、active_maps、active_views和open file handles均为0。

真实保存文件均为20B：`434f573101000000040000000100000003000000`，对应magic COW1、version1、position4、moves1、draws3；SHA256均为`dbfd6f46801dc7186f3ab2b70e777e74feb62110b1c33fb478c9b40fce3661cf`。文件写入20B、LastError0、清理错误0，存档字节同时与host最终window_state观察相符。Escape真实退出路径未被重放。

## 4. 独立读验通过了哪些关系

修复后的普通Python与`python -O`最终`review-ordinary-02.json`和`review-optimized-02.json`各核验4060个唯一文件，内容完全相同，SHA256为`ae64d702cbfe1eba832de0571f5b24b447f8a83cccf489a62b92797182ae351a`。reader只读文件，不执行native、不调用producer验证器；它将固定前批parser/语义规则和新的恢复、重复性及账本校验组合，并记录自身源码及直接Python依赖身份。首版01报告SHA`b3e670d9f03ae1aecc908108d8beecf07663d85b22a82412558fb4b90b6c37f0`有下节所述已知漏验，只保留为历史，不作为最终验收依据。

通过的核心关系包括：

- 每个进程同一个消息的两轮诊断，在outer-before、callback-before、callback-after、outer-after四个对应点，完整State／Context／instruction table／全部guest backing和权限逐字节相等；宿主统计按真实增量核验。
- continuation-before与最初original捕获完整相等；continuation各对应点只按明确的MSG12B原值转换与诊断轮比较，其他guest字节相等。原始MSG时间和坐标确实因进程／消息而异，没有当作规范化值伪造保存。
- 每轮callback完整3504B State恢复，5792B Context只允许steps/switch两个精确字段按预期变化；外层与嵌套真实RET另验RIP/RSP、frame/depth和步骤数。
- 独立重建outer-before→callback-before的完整guest转换，以及callback-after→outer-after真实RET的完整State／Context／guest转换；三类已导出host session在每个phase按精确字节和计数关系验收，layout的全部字段、大小、offset及类型固定，不能通过三轮同步伪造或截短TLS绕过。
- RIGHT／KEYUP有独立的guest image语义oracle；除单独按oracle检查的image外，其他非stack区域与所有region权限不变；outer RSP及以上栈不变；callback marker/shadow40B有固定PE对应的精确oracle。
- 生成来源、编译依赖、引用对象、运行PID、原始日志／快照文件闭包、真实保存退出、宿主计数没有被reset掩盖，均由原始证据相互校验。

reader明确保留以下范围标志：`replay_verified=true`、`same_process_diagnostic_guest_full_byte_equivalence=true`、`outer_dispatcher_entry_and_ret_full_guest_transition_verified=true`；`cross_process_full_byte_equivalence=false`、`stack_below_outer_rsp_exact_oracle=false`、`host_sessions_restored=false`、`timing_verified=false`。

完整RSP以下stack这次获得了**同输入重放结果一致**的证据，但除已单独验证的marker/shadow外，仍没有全部栈字节的独立语义oracle；一致的错误仍可能在两轮重复出现。独立reader也不核对完整FileSession原始字节：FileSession、next_handle、files_ready由冻结C runtime的完整副本guard检查，导出的文件证据仅含LastError、9个API计数和读写字节。Cocoa队列、主线程事件和Metal内部状态没有全进程快照，不宣称整个宿主确定性。

## 5. 测试、拒绝证据与自审

最终`unit-02/result.json`记录16个生成器、8个工具、27个reader测试，共51个，普通Python与`-O`两模式均通过，sources_unchanged=true，全部不执行native。早期`unit-01`的45项和`reader-unit-01`的21项保留为旧版本记录，不能再加到51项上称为新增覆盖；完整最终版本以`unit-02`及对应源码摘要为准。

真实锁实验`lock-probe-01.json`持有旧`window-outer-abi-v1/.run.lock`，再调用新runner；结果为`PASS_LEGACY_LOCK_REJECTS_REPLAY_BEFORE_ANY_CHILD`，捕获BlockingIOError，Popen尝试数0、native执行数0。`lock-rejection-01/failure.json`保留失败。新runner按旧锁→新锁顺序同时持有非阻塞flock，再检查已有项目App/诊断进程，防止两个版本同时扫到空场后启动。超时或中断只清理自己创建的child，原始失败目录不覆盖。

本轮源码复审曾补强三个边界：权限表含const，恢复改为不变检查；nested212需显式验证真实RET完成且返回原Context；新产品host必须匹配既定malloc/calloc分配源SHA。FileTLS未独立导出的限制也被写入reader范围。最终四次native执行均通过；前批single-pass误选cleanup位点的run01/02是历史失败，未删除，也没有算作本轮失败或成功。

首版reader通过后，再次独立自审构造出12个最小漏验反例：6个Context身份／预算／frame变化、2个guest桥接变化、2个通过layout截短TLS的变化、2个callback中间阶段host桥接变化。例如同时修改同一消息三轮outer-after Context中的`regions[0].bytes`（offset72）、permissions（80）、instructions（32）、budget（8）或未激活frame字节（1912），旧reader可能接受，因为三轮彼此仍一致。该发现证明重复性检查不能代替每轮独立合法性检查，也不能只检查首尾TLS而漏掉中间阶段。

实际runtime已有映射／table／budget身份guard，原始native运行未因此失败；缺口属于reader对伪造证据的拒绝能力。修复增加了完整entry／RET guest精确转换、每个phase的三类宿主session精确计数变化，以及全部layout字段、数值与类型的固定检查。RET转换根据真实metadata和原frame重建完整State／Context，保留所有未激活frame和pending字段，并没有扩大允许差分的mask；layout截短不能再省掉TLS后半段。修复后同一批原始记录两模式重新通过；另一名审查者保存的12项最小反例在两模式均全部拒绝，baseline仍正常通过，证据见`reader-gap-01/comparison.json`。旧01 PASS及变异回执不改写，也没有重新运行native来替换原始证据。

最终真实trace内存副本变异在普通／`-O`模式各拒绝396项：48类×8个实际消息组，另加12项最终callback及消息间累计账本反例。每个模式先确认8个原始组通过，再变异副本；`raw_inputs_modified=false`、`native_executions=0`。最终回执为`actual-mutations-{ordinary,optimized}-02.json`，脚本`actual-mutations-02.py`的SHA256为`c4e12e34cdca97341c204b5fdad56ce7c0e16a0e2958b3b891a7e18238a03647`。两模式的396是同一套覆盖的两种执行模式，不应相加成792种不同负例，也不是396个native ABI故障场景。旧01每模式244项覆盖有上述已知盲点，保留历史而不作为最终完整性依据。预算、fault、ABI破坏、未知DefWindowProc、ExitProcess等完整重放矩阵仍待后续实现与实际执行。

`review-mode-parity-02.json`绑定最终reader源码、51项模块测试、27项reader测试子集、4060文件的相同报告、12项漏验修前/修后对照及396项变异回执。最终完整报告、单元测试和两种模式的变异记录已一致收口，原build-01／run-01及其四次native执行没有重跑或改写。

## 6. 证据位置与版本身份

以下路径相对仓库根目录。`build/`原始工件在本机保留，不表示公开仓库分发了本机工具链、第三方构建目录或所有二进制。

| 证据 | 路径 | SHA256 |
|---|---|---|
| 预先固定协议 | `build/window-outer-replay-v1/protocol-01.json` | `143437f1018756bcf9af725e5a5011e01e7800fadf8a0e72d51f1b6a28c31645` |
| 构建回执 | `build/window-outer-replay-v1/build-01/build.json` | `777b5218238574ad1ddeca7e1310747946ce24a2ece8fbbc9a6e5d7f50c9633c` |
| 运行回执 | `build/window-outer-replay-v1/run-01/run.json` | `1824b773328ba8c92e55d938180df21667929336d021edf7ba2c8cbcbfa971fb` |
| 最终两模式独立报告 | `build/window-outer-replay-v1/review-{ordinary,optimized}-02.json` | `ae64d702cbfe1eba832de0571f5b24b447f8a83cccf489a62b92797182ae351a` |
| 有已知漏验的历史报告 | `build/window-outer-replay-v1/review-{ordinary,optimized}-01.json` | `b3e670d9f03ae1aecc908108d8beecf07663d85b22a82412558fb4b90b6c37f0` |
| 最终模块测试 | `build/window-outer-replay-v1/unit-02/result.json` | `2e588fff3ec00cd7c5d451898ec93482bcbd60545df63f9bcdf028b447a5fe88` |
| 锁实测回执 | `build/window-outer-replay-v1/lock-probe-01.json` | `dbb8b435b0801d5e7bb49ad8e30bc7c0ab6a97a26d4b61bf7402803606273750` |
| 普通模式最终变异拒绝 | `build/window-outer-replay-v1/actual-mutations-ordinary-02.json` | `c709554ff893cf5e473b00e8b34c66f67361d88ab97250d38ea361ccaa8a1a12` |
| 优化模式最终变异拒绝 | `build/window-outer-replay-v1/actual-mutations-optimized-02.json` | `a7083766104e3bf6a28498df1f9c3e5dd1eb8fd79a1b95f7ba52e1f925de86d4` |
| 12项独立漏洞复现对照 | `build/window-outer-replay-v1/reader-gap-01/comparison.json` | `cfdbb6390af7a3fff0e51e9e6f392b368328f50a6a9435062dc680cd463a8f46` |
| 最终模式一致性回执 | `build/window-outer-replay-v1/review-mode-parity-02.json` | `3e1349d658700069975724b7422c2789277c695a6d28c0e506f61218c039b079` |

每个`run-01/<configuration>/`包含command、launched、execution、processes-before/after、stdout/stderr、`data/switch-tile.bin`及diagnostic目录；每份diagnostic含layout、50条events及26份二进制快照。每条构建命令的argv、环境、stdout、stderr、返回码和摘要位于`build-01/commands/`。编译前后依赖图和单调哈希账本保留原身份，不接受后来的同名不同hash覆盖；这是工作区输入一致性证据，不是恶意宿主的远程证明。

| 实现 | 最终实际版本SHA256 |
|---|---|
| `window_outer_replay_v1/instrumentation.inc` | `77f12100c17f1ddfab6dd96c8de9efde6c18725498718c2626853257c1ed2fd2` |
| `window_outer_replay_v1/generate.py` | `96e3f282f9b726757da2bca124a030e679e0e8f39f0204da7229bbe091b4efae` |
| `window_outer_replay_v1/build.py` | `4d8da9acfde1f58e04fa2234f67a8ba1d3630b3dc184acb80e9dec75b3f23597` |
| `window_outer_replay_v1/run.py` | `1746c9d787ee290716fbc4930b2bf7e0e37064c137abeb2f8fbd8ed6ad29dae1` |
| `window_outer_replay_v1/review.py` | `eb6650fd85f957d54b30fdcc32305bbbc62a38530a7a46cd04c6d97bb909211d` |
| 复用single-pass reader | `89d117570453413f90d2769e986c09cd56a8d7ddaf5cae23de4b5ff0a9522219` |

## 7. 可复现实验入口

在仓库根目录执行。下面以本机既有v7产品为输入；其他机器需先按[安装入口](../migration_install_v3/README.md)生成并审查相同固定样例的产品，保持源码和host pin一致。公开源码本身不包含这些本地产品及已安装后端，不能直接据此宣称干净机器一条命令已验。

```sh
PRODUCT="$PWD/build/window-lookup-v1/app-01"
python3.13 -B -m window_outer_replay_v1 build \
  --product "$PRODUCT" \
  --out build/window-outer-replay-v1/build-reproduce-01

python3.13 -B -m window_outer_replay_v1 run \
  --build build/window-outer-replay-v1/build-reproduce-01 \
  --out build/window-outer-replay-v1/run-reproduce-01 --timeout 60

python3.13 -B -m window_outer_replay_v1.review \
  --build build/window-outer-replay-v1/build-reproduce-01 \
  --run build/window-outer-replay-v1/run-reproduce-01 \
  --out build/window-outer-replay-v1/review-reproduce-ordinary-01.json

python3.13 -B -O -m window_outer_replay_v1.review \
  --build build/window-outer-replay-v1/build-reproduce-01 \
  --run build/window-outer-replay-v1/run-reproduce-01 \
  --out build/window-outer-replay-v1/review-reproduce-optimized-01.json

python3.13 -B -m unittest window_outer_replay_v1.test_generate \
  window_outer_replay_v1.test_tools window_outer_replay_v1.test_review -v
python3.13 -B -O -m unittest window_outer_replay_v1.test_generate \
  window_outer_replay_v1.test_tools window_outer_replay_v1.test_review -v
```

build/run目录必须是`build/window-outer-replay-v1`的全新直接子目录，不能覆盖旧回执。run需要可用的macOS图形会话并会串行运行四个真实窗口；build和reader不启动native窗口。reader输出也必须是新文件且不能写进受审build/run/product。只重读既有证据时，将上面的build/run参数改为`build-01`／`run-01`并使用新的review输出名，无需重新执行native。

## 8. Go／No-Go与接近真实应用的剩余工作

**Go：** 当前固定PE、首选基址`0x140000000`、真实main会话中的RIGHT和KEYUP正常路径，同进程原地址恢复、两轮诊断重复性、原输入continuation及宿主计数双账已有四配置实际证据。可以据此扩展可审查的负例和终止路径，并开始固定第三方目标的只读准入盘点。

**No-Go：** 不能标记“完整A0已完成”“跨进程全部字节等价”“完整A3负例矩阵通过”“性能目标达成”或“真实游戏迁移完成”。原始32／1456矩阵本轮没有重跑；两基址及更多输入、预算终止、fault/ABI破坏、Exit等边界还没有这套重放证据。全过程的重复拷贝和文件I/O属于诊断成本，本轮无计时，不能用O3或lookup名称推断FPS提升，也不能给出与Wine＋Rosetta的实测性能比。

**真实第三方应用／游戏成功转换数量仍为0。** 已有的是自制受限PE到ARM64执行、窗口/图形/保存及验证基础设施。距离第一个真实应用还有多少，取决于该二进制实际使用的指令、间接控制流、运行库、TLS／SEH、线程同步、API、图形和资源格式；目前没有固定第三方目标的完整盘点，给出剩余百分比会把未知工作量伪装成已测进度。

后续按AI开发里程碑推进，不用周数作完成承诺：

| 里程碑 | 当前状态 | 下一步可验收输出 |
|---|---|---|
| 正常消息同地址重放纵切 | 本轮完成 | 本报告与冻结原始证据；后续扩展不得改写本批结果 |
| 异常／终止重放合同 | 待开发 | 预算、fault、返回ABI破坏、212拒绝、Exit的保存/禁止恢复规则及真实负例回执 |
| 完整外层可比矩阵 | 待扩展 | 两基址、额外场景、精确跨进程差分规则及未覆盖字段清单 |
| 首个真实第三方目标准入 | 尚未完成 | 固定合法版本PE/DLL清单与hash，指令/API/控制流/数据及图形缺口表，明确可启动的最小路径 |
| 首个第三方转换闭环 | 未开始验证 | 真实目标达到初始化→受控交互→保存/退出，完整失败清单和原生执行证据 |
| 性能收益验证 | 未完成 | 在正确性门禁后独立计时，分离提升执行、API、图形和诊断开销，与明确环境下的基线比较 |

最能降低“还差多少”不确定性的下一项是固定一个合法、无需DRM/反作弊处理的简单第三方目标，先读取PE及依赖，列出**真实缺口**再据此选择开发顺序。该盘点可以与边界负例开发并行；不应继续仅靠扩大自制样例测试数量来估算真实应用兼容率。当前不需要把Steam安装／登录或商业游戏获取当作本报告已完成的前提。
