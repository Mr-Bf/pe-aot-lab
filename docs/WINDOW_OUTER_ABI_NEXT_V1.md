# 完整外层 WndProc ABI：下一批正确性与性能实验草案 v1

状态：`DESIGN_ONLY_NOT_IMPLEMENTED_NOT_BUILT_NOT_EXECUTED_NOT_MEASURED`。日期：2026-11-02。

本文件来自只读源码核对。本文没有增加可运行模块，没有执行 native、App 或 GPU，没有产生新的性能结论。`migration_install_v3` 本批冻结安装源不包含本草案，也没有被本次工作修改。以下命名、矩阵、验收规则均为下一批开发提案；实现时须另立源码冻结清单与实验目录。

## 1. 本批要回答的问题

现有 CPU 内核基准已能执行真实 PE 提升后的 WndProc 和 switch8，但它直接用 transaction engine 的 `aot_execute(aot_window_proc_1000, ...)` 启动这个回调。它不经过完整窗口运行时的 owner session、User32 分发和 `aot_wndproc_invoke`。因此，内核查表优化的收益不能直接作为完整回调 ABI、App 或游戏帧率的收益。

下一批先测清一个有边界的工作负载：**真实 PE 主程序发出 DispatchMessageA 后，从其已提交的 import CALL 边界，经完整 User32 分发、WndProc ABI、真实提升回调、必要的嵌套 API 和 import RET，返回到 guest 调用点。** 初始化窗口、绘图、消息等待、磁盘保存和进程启动不在这个计时区间。

先交付这条路径的正确性和可信计时，再决定是否优化 `wnd_save` / `wnd_restore`；此时不删保护、不缩减 State、不改变终止语义。

## 2. 已核对的源事实

| 代码 | 已核对的行为 | 旧 CPU 内核基准遗漏的部分 |
| --- | --- | --- |
| `window_callback_single_v1/benchmark.c` | 直接包含 transaction，实现拒绝 API 的 dispatcher；直接执行真实提升的 `aot_window_proc_1000` | 不包含完整 `window_runtime/runtime.c`、`callback_v1.inc`、`user32_v1.inc` |
| `window_bridge/window_runtime/runtime.c:aot_execute` | 对真实 Context/State 绑定 owner；设置 TLS session.running/used；只允许 session 使用一次；收口 guest 返回或 ExitProcess | owner 绑定、一次性生命周期、完整进程退出校验 |
| `runtime.c:__remill_function_call` | 校验活跃 owner、IAT/寄存器/COM 绑定、RSP/DF、预算、C3/RX thunk、guest 返回槽和四个 shadow operands；实际调用 User32；成功后清 binding、设置 RAX、执行真实提升的 RET shim | 外层 import 前后处理和嵌套 import 的相同开销 |
| `user32_v1.inc:wui_dispatch/wui_callback` | 读取真实 guest MSG、校验 HWND 和消息白名单、累计分发计数，进入 `aot_wndproc_invoke` | MSG 内存访问、User32 TLS、callback 计数和分发 |
| `callback_v1.inc:aot_wndproc_invoke` | 校验已提交 import 边界、owner、注册根、输出不别名、深度/预算/DF/RSP；预检回调栈；保存并恢复外层执行边界 | 完整外层 ABI |
| `callback_v1.inc:wnd_save/wnd_restore` | 各复制完整 State、Context.snapshot、全部 ReturnFrame 和 current/pending/import/COM 边界字段 | 大块复制、元数据恢复；不是只保存 ABI 非易失寄存器 |
| `callback_v1.inc` 返回检查 | 校验 marker、RSP、活跃帧前缀、RBX/RBP/RSI/RDI/R12–15、XMM6–15 低 128 bit 和 DF | 返回契约与错误路径 |
| `user32_v1.inc:wui_defproc` | 按白名单实现消息语义；合法 KEYUP 的默认分支返回 0，未知消息设 `AOT_UNSUPPORTED` | 真正的默认处理 API，不能用 stub 返回值替代 |

源文件：[`callback_v1.inc`](../window_bridge/callback_v1.inc)、[`callback_v1.h`](../window_bridge/callback_v1.h)、[`runtime.c`](../window_bridge/window_runtime/runtime.c)、[`user32_v1.inc`](../window_bridge/user32_v1.inc)、[`window_host.c`](../window_bridge/window_host.c)、[`benchmark.c`](../window_callback_single_v1/benchmark.c)、[`switch_tile.cpp`](../switch_window_fixture_v1/switch_tile.cpp)。

需要保留的细节：

- callback TLS 保存数字 owner、复制的不可变 root 表和统计；live State/Context 沿真实参数传递，不另存可解引用的 TLS 指针。这与 Remill 生成参数的 alias 契约有关。
- 正常回调以 `outer_rsp - 48` 为 entry RSP；先完整预检五个独立 8-byte RW operand，再写一个返回 marker 和四个 shadow word，共 40 bytes。剩余 padding 不写。
- 正常返回恢复外层 State/快照/帧/边界字段，但**不撤销 guest 内存写入，也不回滚累计 steps**。不能把 benchmark 为重复执行做的输入重置误写成运行时行为。
- fault 或 ExitProcess 时，只展开 native 栈，不执行 `wnd_restore`；保留故障处 State、guest frames、已经提交的内存和 exit latch，也不执行外层 synthetic RET。
- State 当前固定为 3504 bytes；边界内有两个 State 和全部 frames。实际 `sizeof(WindowCallbackBoundary)`、alignment/offset 须由新编译探针输出，不根据手算声明具体复制总字节数。编译器可能消除或合并复制；机器码实际内存流量也不能由结构大小直接推出。
- XMM 检查属于 ABI 保留规则，不表示当前整数 profile 已支持执行 SIMD 指令。
- `window_host.c` 已有 `--base` 和 `--test-sequence`，后者包括 `right-up`、`left-up`；重定位仍受实际 `kCanRebase` 和映射条件约束，两个基址须实际跑过才算证据。

## 3. 实现范围：完整运行时中的诊断回放

建议新建 `window_outer_abi_v1`，旧模块和已验收产物保持冻结。依赖现有真实 PE、提升对象、运行时与实际 Cocoa/D3D 后端；不得把完整 runtime 换成 `TestOwner`、手填 `session.running=1`，或把 import 改成成功 stub。

### 3.1 入口和 source overlay

1. 核验 `examples/window-switch/switch_tile.exe` 的 SHA-256 为 `39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`，回调注册根来自已审核 profile；当前根为 RVA `0x1000`。同时冻结 decoder/lifter、输入 profile、完整 provider 和实际编译依赖。
2. 真实 host 创建会话，执行真实 PE main，完成类注册、窗口创建等准备。由已有受控消息入口投递 RIGHT 或 KEYUP，让真实 guest 到达 DispatchMessageA 的 import CALL。
3. 从这个真实已提交边界进入诊断回放。首选生成严格的 source overlay：只把完整 runtime 中的 `__remill_function_call` 定义重命名为内部实现，再新增同签名 wrapper。wrapper 在唯一选定的真实 DispatchMessageA callsite 捕获边界；回放调用原实现，嵌套调用通过递归保护直接进入原实现。实际 callback body、User32 分支、owner 检查、RET shim 保持原样。
4. wrapper 要验证唯一 callsite、signature 214、真实 owner/线程、MSG 参数、回调注册根和 profile 身份。不能靠“任何 API 调用”触发；不能将成功标志代替实际 call/return 计数。
5. 生成器要求固定模板 SHA、每个替换锚点恰好一次，输出完整 diff 和内容 SHA；reference/candidate 使用相同 hook，只有原有 instruction lookup 策略不同。不要通过运行时 selector 切换策略。

这是诊断构建。结果名称须写成“完整 DispatchMessage/WndProc import 往返回放”，不能写成无插桩正式 App 的耗时。wrapper 还有 dispatch/递归保护开销；两构建相同不等于此开销为零。

LLVM 层必须检查实际 helper 声明和优化后的 IR：回调链不可带错误的 `nocallback` / 只读 / 仅参数内存副作用假设；保持正确函数签名、地址空间、calling convention 和 State/Context 参数传递方式。禁止不同类型函数指针强转来“接上”入口。先 O0/O3 等价，再计时。

### 3.2 重复执行与恢复范围

同一完整 owner session 不能重复调用顶层 `aot_execute`；它是一次性入口。回放必须发生在该次真实执行内部，当前线程仍拥有活跃 session。

每次输入重置应有显式契约：捕获 live State、完整 Context、选定可写 guest 映像与栈及其权限，恢复到已提交 import CALL 边界，再调用原 dispatcher。必须写回同一 live State/Context 地址，不能拿副本地址调用 dispatcher，否则数字 owner 身份不同。Context 的宿主指针只能在它们仍指向同一已验证对象时恢复；live 指针仍从实际 helper 参数派生，不能从 TLS 重取可解引用指针。重置预算/steps 是诊断输入准备，不能暗改 production fault 语义。

**不允许 memcpy 回滚整个 D3D/User32/file/host session。** 其中存在对象所有权、宿主句柄、allocation 和异步状态；浅拷贝可能造成资源泄漏或 double-free。选择的回放路径不得创建/释放 GPU 对象、分配映射、执行文件 I/O、改变窗口生命周期或 process exit。出现未声明的这些行为就终止该实验。

Context 内的 `result.steps`、`switch_commits` 会随完整 Context 重置，必须与真实执行总账分开：每轮保存 before/after delta，累加到 Context 之外的诊断账本，记录 reset 次数和值。RIGHT 每轮的 switch commit 增量必须计入总账，不能只从最终 Context 的一次结果声称执行了 N 次。诊断结束后，Context 恢复原真实边界并执行一次 continuation，因此最终 production Context 只包含原流程和这一次正常调用；额外执行量完整保存在独立诊断总账。

Context 外的原有 TLS 业务计数保持真实累计，不为便于匹配旧报告而抹零。每次回放经过原 `wui_dispatch` 和 `wui_callback`，所以 DispatchMessage API 次数、posted_dispatches、User32 callbacks、callback calls/returns 应按账本同步递增；KEYUP 额外递增 DefWindowProc API 次数。完整 D3D/file owner 状态、LastError、对象/map 状态和业务计数在所选成功计时路径内不得改变。

回放结束后恢复一次边界并执行一次真实 import，继续原 PE 主循环，最终由受控 escape/close 正常结束。单独记录 warmup、正确性、timed、最终 continuation 的实际次数。新的 reader 不能套用“固定实际消息数”的旧正常 App 计数模板；需要有物理消息与诊断重复两本可对账的计数。

窗口 main thread 仍可能 pump 原生事件；线程 CPU 与这段 guest worker 工作负载相对应。即使计时区间没有 guest 图形调用，也不能声称整个进程或桌面没有执行任何 GPU/窗口工作。

### 3.3 最小场景

| 场景 | 真实 PE 路径 | 必须观测的差异 |
| --- | --- | --- |
| RIGHT，position 0…7 | `WM_KEYDOWN/VK_RIGHT → switch8 → RET` | 实际位置结果、moves、keydowns、dirty；position 7 边界行为；无嵌套 API |
| LEFT，position 0/1/7 | `WM_KEYDOWN/VK_LEFT → RET` | 下界与移动行为；无嵌套 API |
| RIGHT repeat | bit30 已置位的 `WM_KEYDOWN` | ignored_repeats 增量，无位置变化 |
| RIGHT-UP、LEFT-UP | `WM_KEYUP → PE default → DefWindowProcA → RET → callback RET` | signature 212 每轮恰好一次、返回 0、无 fault；不得用拒绝 API dispatcher 或 stub |

先以一个真实到达的 KEYUP 边界和一个 RIGHT 边界完成纵向切片，再扩展全部场景。位置输入可来自正常消息准备，或来自诊断重置；后者必须报告为“受控 guest 输入”，不能伪称这些输入都由真实用户事件自然产生。映像写入位置要来自 profile/符号映射的精确白名单，不能搜索字节碰巧命中。

默认 API 必须另做负例：未知消息/不支持 key、失效 HWND、错误参数，分别证明正确层级的失败。`wui_posted_message` 会先拒绝未知 posted 消息，因此“消息被分发前拒绝”不能算作已测试 `wui_defproc` 未知分支。后者需要新版本的自制 PE 负例或明确标记的诊断参数注入，在真实、合法的 callback/import 边界上触发；保留原消息白名单。只修改外层 MSG 的 HWND 会被 `wui_dispatch` 当 stale message 丢弃，并未到达 DefWindowProc；需在真实嵌套 signature 212 边界注入才能覆盖该分支。此时返回 0 + LastError 属于 API 失败，ABI callback 仍可正常返回 `AOT_OK`，必须分别记录这两个结果。

## 4. 正确性门禁先于计时

正常路径矩阵：reference/candidate × callback 提升对象 O0/O3 × 两个合法基址 × 上述场景。运行时和诊断 harness 统一 O3、无 LTO。相同基址使用 reference/O0 为差分锚；每个场景还须用独立语义 oracle 检查结果，不能仅凭“两份实现犯同样的错”放行。

首先冻结诊断输入，而非事后清理输出差异。`cocoa_host.mm:input_metadata` 对 test-post 也写入实时 system uptime 和鼠标坐标，随后 GetMessage 将它们写进 guest MSG.time/pt；真实窗口初始化也可能受异步消息影响。因此“只规范化宿主指针”不足以保证跨进程完整 State/Context/映像/栈可比。保留原始捕获边界和环境记录；允许在执行前对明确 MSG 字段以及经审核的诊断输入白名单设定固定值，输出原值、新值、偏移、理由及输入 SHA。A2 必须证明各策略拿到同一诊断输入；剩余异步差异没有逐项解释时阻止全字节差分验收，不能宽泛清零、mask 或忽略。原始边界另留给最终 continuation，不用固定诊断输入污染正常 App 的继续执行。

导出并严格复核：完整 State、完整 Context、guest 映像/栈/权限、回调 return value、统计增量、import/COM binding、退出信息。在已证明输入一致的前提下，跨进程只规范化明确列出的宿主指针槽；保留其他字节，包括未激活槽和 padding。private struct 的 sizeof/offsetof 来自实际编译探针，并与固定 Remill State 布局校验绑定。不能清空整个指针附近区域来获得相等结果。

正常成功需要同时满足：

- 原 dispatcher 实际完成；callback calls = returns，当前深度回到进入值，无 rejection/fault；外层 import RET 实际执行。
- 真实 PE 结果符合 oracle；外层边界恢复符合源码契约；guest 栈 marker/shadow 和回调内存副作用按预期保留，不能要求运行时把它们清回初值。
- KEYUP 每轮 signature 214 与 212 各一次，对应两个 import RET 和一个 callback RET；其他计时场景不得出现额外 API/COM 调用。
- 在相同规范化规则下 O0/O3、两查表策略一致。两个基址各自比较，涉及 guest VA 的字段不得直接跨基址逐字节比较。
- 定时关闭和定时开启两种诊断构建/模式均符合语义；计时额外读时钟不能成为某个 API 的成功条件。

终止和拒绝路径不计入成功吞吐量，单独测试：

| 组别 | 用例及证据 |
| --- | --- |
| 逐预算切点 | 以完整往返的实际 steps 定义切点，包含外层 import、callback、KEYUP 的嵌套 import/RET；旧内核 41/45 steps 不可直接沿用。记录首次 fault 的精确 State/frames/memory，完成全部实际切点后才宣称全覆盖 |
| 入场/栈 | owner/thread/State/Context 不匹配、pending/in_instruction、未注册 target、RSP 对齐/溢出、DF、深度上限、marker 冲突、输出别名；五个 stack operand 跨区域/权限失败，检查预检全通过之前零写入及 bounds-before-permission |
| 返回 | 错误 marker/RSP/帧、非易失 GPR/XMM 破坏；XMM 测试注入须标记为 ABI 负例，不能当作支持 guest SIMD 的证据 |
| 嵌套 API | 支持的 KEYUP default 真执行；unsupported default 真失败；invalid HWND 的 LastError 与返回语义；不能把默认 0 一律认成成功 |
| 进程终止 | 新自制 PE/版本化负例在回调内调用 ExitProcess，验证 exit latch、原始 guest frames/State 和外层 RET 未执行。原 switch fixture 没有此回调行为，不得声称现成覆盖 |

fault 之后必须使用全新 session/进程，不在已经终止的生产 session 上清 fault/exit latch 再继续。过去 `window_bridge/callback_test.c` 的 TestOwner 负例可作为用例来源，不能代替新完整运行时证据。

## 5. 计时规则与实验成本

第一次只做一个基址、RIGHT position 3 和 RIGHT-UP 的开发 smoke；不用于推广性能。全部正确性门禁通过后，冻结正式规则再开始正式运行。

- 主时间源 `CLOCK_MONOTONIC_RAW`；线程 CPU 只作诊断。每批两端读时钟，不在每个 callback 内加系统时钟采样。
- 主报告包含完整输入重置、原 dispatcher 往返、轻量校验及 checksum。另做同输入的 reset-only 控制并单列；**不相减来制造“纯 ABI”时间**。全状态比较、分配、文件输出与进程初始化放在计时外。
- 若将来另测无重置的连续 KEYUP 批次，应是新 workload ID，记录不断增长的 steps/计数器和预算，不能与 reset workload 混合汇总。
- 先固定 pilot 流程选择使每批约 20–100 ms 的迭代数，并设置有限上限；pilot 原始记录保留。正式 N、warmup 数、场景轮转、进程顺序在正式采样前冻结。不能看到结果后追加直到 candidate 获胜。
- 每基址 12 个进程组，偶数组 ABBA、奇数组 BAAB；每进程轮转场景。每组两份 candidate wall 总和 / 两份 reference wall 总和，保留所有原始值、ratio、快/慢/相同次数；不跨场景掩盖退步。
- 同时记录 OS/硬件、编译器/SDK、Rosetta 标志、构建选项、产物与依赖 SHA、PID、实际线程标识、命令、退出码、stdout/stderr、信号/超时、timed/untimed 调用数。
- 时钟误差、调度、温度和频率可能影响结果；CPU/wall 逆差原样保留。短区间顺序采样不保证 CPU ≤ wall，禁止 clamp/任意剔除，若来源解释不清则不下性能结论。
- 限制同时只运行一个实验 App；进程串行、每个独立 data-dir 和全新输出。预算切点二进制记录采用带精确 header/总长/EOF 校验的压缩流，避免大规模重复展开占用磁盘。

完整 host 初始化可能有图形开销；正式测量前要估计全矩阵的进程数和时长，并设合理 timeout。这份草案未运行 pilot，不给出编造的分钟数或性能百分点。

## 6. Go / No-Go 与自审

**Go：开发完整 ABI 诊断基准。** 当前源码具有真实 callback root、实际 DispatchMessageA 和 KEYUP 默认处理路径，能形成明确的纵向切片。尚未证明诊断回放实现可用，先完成下列 A 阶段才允许计时。

**No-Go：现在优化 save/restore 或宣称 App 收益。** 旧 CPU 内核数值不覆盖外层；完整边界复制、TLS、import 验证和真实 API 的成本比例仍未知。特别是 full State 的保存与恢复不能仅凭 Win64 callee-save 规则裁剪：当前运行时还依赖外层快照、事务元数据、终止行为和精确差分证据。

| 风险 | 推敲结论与门禁 |
| --- | --- |
| 用 TestOwner/手填 TLS 得到快结果 | 只能算组件模拟；新验收必须看到真实主程序与原 dispatcher 到达的边界、实际 owner、真实 PE root 和 import/RET 账本 |
| 两个产物同错 | 差分之外保留独立 guest 语义 oracle、源代码不变区域审计和负例；KEYUP 必须证明 signature 212 真调用 |
| 回放恢复 host 对象导致 UAF/重复释放 | 不回滚完整 session，只恢复明确 guest 输入/Context；禁止选用会改变 host/GPU/file 生命周期的计时路径 |
| 重放把 fault 擦除 | 正常回放与负例分离，terminal case 新进程；保留故障现场，不恢复外层正常 State |
| benchmark 编译器属性使回调失真 | 固定正确签名，检查调用副作用/别名属性，O0/O3 差分及反汇编；必要改动独立版本化，不能静默改旧产品 |
| reset 或 wrapper 掩盖/制造收益 | 报告区间实含内容和控制组，固定两份同 hook；不减时间、不等同正式 App |
| 在 default 返回值上偷换成功定义 | 同时看 admitted API、真实调用计数、fault、LastError、状态；unknown 仍失败，不能 return 0 充数 |
| 看见 noisy 胜负才改门槛 | pilot 仅用于定 N 与估计 A/A 波动；正式前冻结效应阈值和分析规则；不够分辨率即“无结论” |

基准自身的 Go 条件是上述正确性、来源和账本门禁全部通过，独立 reader 在 Python 普通和 `-O` 模式都能拒绝篡改/缺失/不完整记录。它不要求 candidate 一定更快。

只有提出后续生产优化时才设性能收益门槛：先用 A/A 重复实验估计本机波动，再在看 A/B 正式结果前冻结最小有意义收益；每个主要场景保留 12 组分布，不允许明显退步被总体均值掩盖。统计不确定性过大时保留方案，不把“多数批次略快”当作性能证明。优化进入正式 App 后还需原正常/失败回归和独立 App 工作负载；此报告仍不覆盖 Steam 商业游戏、Wine/Rosetta 或帧率对照。

## 7. 以 AI 开发阶段标记的下一步

| 阶段 | 交付 | 完成门槛 |
| --- | --- | --- |
| A0：设计冻结 | 本草案复审、真实调用链/可重置字段清单、默认 API 正负场景 | 明确不支持项；reviewer 能逐项对应源码 |
| A1：只生成不运行 | 新 source overlay 生成器、closure/编译依赖清单、计数 schema、源码负例测试 | 固定模板、唯一锚点、无 stub，无原代码修改；普通/-O 单测通过 |
| A2：纵向正确性 | 真实 PE main 到达的一次 RIGHT 与一次 KEYUP，实际 callback/DefWindowProc/RET、正常退出 | 无计时；全 State/Context/内存和实际 API 账本可复核 |
| A3：完整矩阵 | 两 lookup、O0/O3、两基址、所有正常场景、逐预算和 ABI/默认 API 负例 | 独立 reader 验收；没有把 TestOwner、stub 或注入用例误标为真实产品运行 |
| A4：计时合同冻结 | A/A pilot、迭代数、顺序、区间、效应阈值、资源限额 | 开跑正式 A/B 前冻结；保留 pilot，控制组不相减 |
| A5：正式计时与自审 | 全部原始记录、独立分析、完整性负例、结果报告 | 无遗漏样本或错误归因；明确完整 ABI 与 App 性能区别 |
| A6：有证据才选优化 | 根据完整 ABI 占比选择查表、复制或 metadata 优化；另开版本 | 先论证语义，再复用完整门禁；没有收益则保持当前实现 |

预期最小源码闭包：新 generator/harness/reader/tests + 固定 `window_lookup_v1`/`window_switch_v1` 提升生成链 + 完整 `window_bridge` runtime/transaction/callback/User32/file/host/includes + profile/PE/实际提升 IR 与 RET shim + 编译器探测的头文件闭包 + 实际 Cocoa/图形后端 provider/链接依赖。最终闭包以实际编译 depfile、链接记录与来源锁为准；只枚举 Python 文件或只扫存在文件不能证明固定非 Python 资源完整。

当前只完成本文件的只读设计、自审和一次独立方案复审。复审指出的实时 MSG 输入、Context 计数重置、live owner 地址和 API/ABI 结果区分已补入上述门禁；具体字段清单与确定性输入实现仍待验证，因此 A0 尚未闭合。A1–A6 均未实现或实测；没有可以立即复制运行的 `window_outer_abi_v1` 命令。实现后再填写可复现实验命令，避免用示意命令冒充现成入口。
