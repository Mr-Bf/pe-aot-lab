# 完整外层 ABI：无计时 single-pass 诊断 v1

**本轮无计时single-pass完整外层ABI纵切通过。** 修正后的24条诊断构建命令、四配置实际执行、3980个文件身份的独立读验均完成；普通／`-O`验收报告逐字节一致。33项模块测试和每模式128项实际trace内存副本篡改拒绝通过。首次两轮因观察器调用点定位错误而退出65，失败原样保留。本轮从真实 PE main 进入 DispatchMessageA，验证完整 WndProc ABI、KEYUP的真实 DefWindowProcA和import RET；没有重复回放、输入重置或性能采样结论。

## 本轮范围与来源

新模块为 `window_outer_abi_v1`，正式运行时和旧产物保持不变。输入仍是自制固定 Windows x86-64 PE，SHA256 `39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`；profile 为 schema2／`win32-d3d11-tile-switch-v1`。未新增一般 PE、Windows API、SIMD、线程、TLS、SEH、图形或 Steamworks 兼容能力。

本轮显式复用本机私有项目 `build/window-lookup-v1/app-01` 的已验产物，其 `result.json` SHA256 为 `cd28493d3f7f3afd3851af9586cbb7d79a44250801c40df73f73f2815924419a`。构建开始先调用冻结的 `window_lookup_v1.review`，检查产品、来源、实际命令和lookup provenance；这份既有产品属于前批v7生产接入，**不是前一批 install v3 的外部源码目录产品**。

| 本轮新生成 | 本轮显式复用 |
|---|---|
| 两套严格source overlay、两个观察版runtime对象、一个接收参数的host对象、四个ARM64诊断可执行文件 | 既有提升main／WndProc对象及其O0/O3版本、RET shim对象、native-backend／window-backend／Cocoa三个对象、原CPU与图形provider及对应dylib |

没有重建Remill／XED／LLVM／DXMT依赖，没有重新提升原PE，也没有打包或替换无参数生产App。host从原 `window_host.c` 重新编译，移除生产App专用的 `-Dmain=aot_window_main`，省略no-argument entry对象。实际运行使用显式data-dir和test-sequence的诊断host；不能称为新的无参数App、Finder／LaunchServices或真实键盘验证。

## 代码与证据链

`generate.py`逐项核验固定runtime、transaction、callback、User32、file及相关头文件。它在唯一锚点重命名原import helper与callback函数，为真实import RET增加观察调用，附加同一份诊断代码。reference保留原bsearch查找，inline只使用前批已验的指令查找实现。生成 `overlay.diff` 和来源摘要；原业务分支、owner检查、callback保存恢复及未知语义拒绝保持不变，不提供成功stub。

`build.py`只接受已验固定PE产品，使用其真实编译器、SDK、编译参数和链接依赖。host/runtime统一O3、无LTO；guest main、WndProc和RET分别选择原O0／O3对象，形成 `reference-O0`、`inline-O0`、`reference-O3`、`inline-O3` 四配置。编译器依赖查询、实际编译、IR输出、链接、ad-hoc签名和签名验证均保留命令、退出码和stdout/stderr。

已观察输入的摘要不能被后续同一路径的新摘要覆盖；已生成对象、IR及签名后可执行文件也进入不变清单，结束前重验。两次依赖列表必须一致。这些检查用于发现前后持续变化，不是恶意主机或“改后复原”瞬态修改的执行字节认证。

`run.py`按上述顺序串行启动四个诊断host：每个进程使用全新 `data`、`diagnostic`、`cache` 目录；禁止覆盖旧结果，使用模块运行锁并检查其他项目App／诊断进程。它只结束自己持有的 `Popen` 子进程；timeout和证据写入／等待被中断的错误均保留。实际输入固定为 `right,right-up,escape`，类型明确为 `TEST_QUEUE_NOT_OS_KEYBOARD`。每进程只观察一次RIGHT、一次RIGHT-UP，最后由原PE正常保存、释放资源和退出。

`review.py`是独立只读文件reader，不导入producer或运行builder/native/UI。它检查实际源码变换、编译依赖和命令、对象及加载库、原始布局／快照／事件、保存结果与正常退出；不从runner的成功标志直接推断ABI成立。普通与 `-O` 结果及篡改负例另列，不把reader运行当成新的native执行。

## 真实调用与状态门禁

详细字段合同见 [WINDOW_OUTER_ABI_CONTRACT_V1.md](WINDOW_OUTER_ABI_CONTRACT_V1.md)。本次严格选正常主循环的 register CALL **RVA5839／`0x16cf`／R12**，对应signature214、目标 `base+0xf00d6000`，真实返回地址为 `base+5842`（`0x16d2`）。KEYUP中的DefWindowProcA为直接CALL RVA4248／`0x1098`、signature212、目标 `base+0xf00d4000`。退出清理循环的6051／RDI不属于观察范围。

每条受选消息记录 `outer-before → callback-before → callback-after → outer-after` 的完整快照，并记录实际RET及KEYUP嵌套API事件。快照包含完整State、Context、指令表、所有guest region backing与权限，以及D3D／User32／callback会话原始字节；独立reader对长度、EOF、字段布局和来源逐项检查。

同一回调入口／出口的完整State必须相等；Context只允许精确的 `result.steps` 和 `switch_commits` 字段变化，不能忽略整个result、附近padding或其他字段。guest内存写入不应回滚：callback栈marker、shadow和提升函数栈写仍可见，RIGHT也真实改变样例状态。所有region的backing和权限均被捕获，但捕获不等于每个字节的副作用都有独立oracle：本轮精确检查映像允许的变化、其他非stack区域与权限不变、outer RSP及以上栈字节不变，以及callback frame的40B marker／shadow。对8个实际区间，固定PE的prologue／写入类型门禁与原始快照共同确认这40B为 `base+0xe0000010` 和四个零值shadow word；该结论只适用于本次固定样例，不能推广为任意Win64 callee都必须保留shadow为零。outer RSP以下其余真实栈写仍保留，**尚无该部分全部字节的独立语义oracle**。不能把这项验收写成全栈或完整guest内存零差分。

外层import退出已经执行真实RET，RIP、RSP、RAX和相关Context字段合法变化，不能套用callback恢复规则。reader依据真实ReturnFrame及栈返回槽核对RET返回地址、RSP、call_depth和一步计数；KEYUP必须有一次212 RET和一次214 RET。

| 受选场景 | 独立样例语义与事件要求 |
|---|---|
| RIGHT | 实际MSG为0x100／VK_RIGHT，非重复键；position3→4、moves0→1、keydowns增1、dirty=1；switch_commits增1，无嵌套API，LRESULT=0 |
| RIGHT-UP | 实际MSG为0x101／VK_RIGHT；该次回调内样例与观察区不变，真实DefWindowProcA调用一次并返回0，switch_commits不变，两个import RET |

两场景必须沿同一真实live State／Context与线程owner执行。API、callback、深度、steps、file／LastError和D3D生命周期账本交叉检查，不从“返回0”推断默认API实现正确。最后退出与保存是整个诊断进程的收口验证，未纳入任意计时区间。

本轮不修改MSG.time／pt，保留真实uptime和鼠标坐标；初始化还可能有focus／paint等异步差异。两个策略分别满足同一独立oracle及同进程完整边界关系，**不宣称跨进程State／Context／映像／栈全字节相等**。两个策略都通过也不代表错误不可能相同；固定源变换、真实原PE身份及独立结果规则分别提供约束。

## 已保留的首次失败与修正

初次静态定位把清理drain loop中的DispatchMessageA误认成正常唯一位点，observer固定为6051／RDI。实际PE含两个读取同一IAT的位点：正常循环在RVA5457装入R12并于5839调用；退出清理在RVA6022装入RDI并于6051调用。共享signature和目标不能推出共享callsite。

| 失败目录 | 实际进程结果 | 证据及处理 |
|---|---|---|
| `run-01/reference-O0` | PID38991，退出65，非timeout | `OUTER_ABI_DIAGNOSTIC_FAILURE: selected dispatch boundary differs from fixed PE`；保留第一份构建、源快照和原始输出 |
| `run-02/reference-O0` | PID39593，退出65，非timeout | 只补结构化stderr，未放宽selector；记录真实current_rva5839、kind4、合法import214及零pending/in_instruction/fault/returned，证实调用点选择错误 |

第二轮记录的PC为9396117504、module_base为5368709120、RCX为5368721808，分别对应正确的214目标和 `window_message` VA；错误不在guest内存或已提交CALL边界。诊断在受选callback观察区间开始前拒绝；不能记为生产runtime错误或callback执行失败。

修正仅把观察点收敛到正常 **5839／R12** 与真实返回地址5842，仍拒绝清理循环6051；不能改成“任何signature214均成功”。新构建／运行使用 `build-03`／`run-03`，旧 `build-01/02`、`run-01/02` 和 `failed-source-01/02` 原样保留。旧 [NEXT设计](WINDOW_OUTER_ABI_NEXT_V1.md)继续作为历史提案，修正后的明确合同与失败证据见本报告和CONTRACT。

## 最终验收状态

| 层次 | 实际结果 | 验证边界 |
|---|---|---|
| 代码／源码审查 | generator、观察代码、build/run、独立reader及测试已完成；来源摘要覆盖与owned-child异常清理已复审 | 12个generator、6个工具门禁、15个reader测试，普通／`-O`各33项通过；不代表完整native负例矩阵 |
| 新诊断构建 | `build-03`完成24条命令；源码、对象、命令与依赖经独立复核 | 只新编host/runtime，提升与后端对象显式复用；不是第三方重建或新生产App |
| 新四配置执行 | `run-03`四进程均退出0，每个实际投递3条TEST_QUEUE事件，8个受选callback区间通过 | 首选基址的RIGHT与RIGHT-UP正常路径，不是物理键盘、完整预算或全部API负例 |
| 独立验收 | 3980个唯一文件身份；普通／`-O`报告逐字节一致，状态PASS | 同进程完整State／Context恢复、独立guest副作用及实际API／RET账本；跨进程全字节等价仍为false |
| reader篡改拒绝 | 8个实际正常区间的内存副本共128项变异，普通／`-O`均全部拒绝 | 原始文件未改，native执行数0；不是128次运行时ABI负例 |
| 性能／重放 | 未实施 | 无时钟采样、无reset、无MSG改写、无重复回放，不填写加速比 |

本轮统计来自本轮记录，未沿用前批5514／805文件或1488内核次数。

### 已取得的原始执行记录

`build-03/build.json` SHA256为 `337334fe1115d18c7605da6d335a86444458987f7282c0f2a4658480b7bf1f82`；`run-03/run.json` SHA256为 `aa8980fbfdd35b3e6f39dac662decf8e87e9da53636b202042e4a0a57d2d0545`。runner状态按原设计保留 `OUTER_ABI_SINGLE_PASS_RUNS_OBSERVED_NOT_INDEPENDENTLY_ACCEPTED`，由后续独立reader给予接受结论，不能回写旧runner回执。以下数字来自本次stdout、事件、快照和独立复核。

| 配置 | PID／退出码 | 主程序总steps／switch commits | 事件记录／完整快照 | 保存position／moves／draws |
|---|---|---|---|---|
| reference-O0 | 39990／0 | 809／1 | 16／8 | 4／1／3 |
| inline-O0 | 39993／0 | 809／1 | 16／8 | 4／1／3 |
| reference-O3 | 39996／0 | 809／1 | 16／8 | 4／1／3 |
| inline-O3 | 39999／0 | 809／1 | 16／8 | 4／1／3 |

成功轮合计4个进程、8个受选外层调用区间、64条事件、32份完整快照。本轮native运行总账为4次成功＋2次observer主动拒绝；reader、单测和内存变异的重复执行均不算新增native运行。每个进程的RIGHT区间记录6条事件／46 guest steps（callback内45），KEYUP区间记录10条事件／18 guest steps（callback内17）；前者1个import RET，后者2个import RET及1个嵌套212调用。这是指令与事件计数，不是耗时。每个进程的20B存档SHA相同：`dbfd6f46801dc7186f3ab2b70e777e74feb62110b1c33fb478c9b40fce3661cf`。

各进程stdout记录 `proc_translated=0`、`proc_translated_errno=0`、`outcome=PROCESS_EXITED`，test_queue请求／实际投递均为3；系统退出码0与host内部 `aot_status=11`（进程退出路径）分开记录，不能把内部枚举当系统错误码。每进程完整生命周期共9次callback且全部正常返回、3次Present；其中2次是本报告详细捕获的RIGHT／RIGHT-UP，不能把8个受选callback写成整个App的全部callback次数。实际布局记录为State3504B、Context5792B、callback boundary8256B；结构大小不等于编译后实际复制流量或开销。

### 独立reader、反例及源码身份

最终 `review-ordinary-03.json` 与 `review-optimized-03.json` 均位于 `build/window-outer-abi-v1/`，各自命令、stdout、stderr及结果记录同目录保存；退出码均为0，stderr为空。两份报告SHA256相同：

```text
b43e48726eb4e59064f3cc5cbc016f873c8c1019d7e87c6867ed6655d9dfae54
```

状态为 `PASS_UNTIMED_SINGLE_PASS_OUTER_ABI_INDEPENDENTLY_REVIEWED`，3980个唯一文件身份；明确 `timing_verified=false`、`replay_verified=false`、`cross_process_full_byte_equivalence=false`、`stack_below_outer_rsp_exact_oracle=false`。原始MSG的time／pt在不同进程之间保留实际差异，没有输出清洗或掩码使其相等。首次reader报告01也通过，随后自审明确了RSP以下栈写尚无精确oracle的范围，新增显式false字段并以全新02报告重新读验；最终03又增加40B marker／shadow精确检查及reader输出位置不得污染冻结输入的门禁。01／02不删除，后续reader重验不增加native执行次数。

最终 `actual-mutations-ordinary-03.json` 与 `actual-mutations-optimized-03.json` 的每次128项拒绝来自16类变异乘8个实际区间。覆盖错误清理位点、State／Context快照修改、steps不推进、未声明映像／outer RSP以上栈／proxy／权限变化、RET栈错误、漏事件、错误marker／非零shadow、API账本、owner、callback返回及伪造计数字段offset；原始8组先分别通过。变异仅作用于reader输入的内存副本，`raw_inputs_modified=false`、`native_executions=0`，不冒充fault／ExitProcess等真实运行时负例。两模式报告含各自mode字段，不要求它们逐字节相同；完整正常验收报告才是逐字节一致。旧01／02的112项变异记录另存；03新增两类marker／shadow变异，不能把重复读验次数计成native或新增场景覆盖。

修正后的构建冻结实现摘要为：

| 文件 | SHA256 |
|---|---|
| `build.py` | `a166cb801b7dd2318f179fee1a77ae579c4d791804ea88e5301a621f12e9fd6a` |
| `generate.py` | `fe3c24d5ba38cfb664f618a528313b3a69f501dca30e06cc710f85d69996582c` |
| `instrumentation.inc` | `60dfa9d9b012c87cc93c9fbcbbd7348e6c5b65dff03dfb67e33aa4c01937fad2` |
| 最终独立 `review.py` | `89d117570453413f90d2769e986c09cd56a8d7ddaf5cae23de4b5ff0a9522219` |

完整输入及生成文件身份见build回执，不能把这四个摘要当作全部源码闭包。旧失败的源快照和回执分别保留其实际代码，后续修正不覆盖旧失败。

## 可复现实验入口

以下命令从仓库根目录执行；Apple Silicon、原产品及其原绝对路径依赖须仍可用。使用新目录名，不能覆盖本文已经存在的 `build-03/run-03`。公开源码发行不附带这份私有native产品，应先按对应正式入口取得自己的合法样例产物；不得用缺失的历史产物补造通过回执。

```sh
python3.13 -B -m window_outer_abi_v1 build \
  --product "$PWD/build/window-lookup-v1/app-01" \
  --out "$PWD/build/window-outer-abi-v1/build-new"

python3.13 -B -m window_outer_abi_v1 run \
  --build "$PWD/build/window-outer-abi-v1/build-new" \
  --out "$PWD/build/window-outer-abi-v1/run-new" --timeout 60

python3.13 -B -m window_outer_abi_v1.review \
  --build "$PWD/build/window-outer-abi-v1/build-new" \
  --run "$PWD/build/window-outer-abi-v1/run-new" \
  --out "$PWD/build/window-outer-abi-v1/review-new-ordinary.json"

python3.13 -B -O -m window_outer_abi_v1.review \
  --build "$PWD/build/window-outer-abi-v1/build-new" \
  --run "$PWD/build/window-outer-abi-v1/run-new" \
  --out "$PWD/build/window-outer-abi-v1/review-new-optimized.json"

python3.13 -B -m unittest \
  window_outer_abi_v1.test_generate window_outer_abi_v1.test_tools \
  window_outer_abi_v1.test_review -v
```

运行器上限60秒只是本示例监督参数，不是性能目标；原host另有更短的内部timeout。窗口／GPU会实际初始化，始终串行；不需要再次通过桌面工具选中App，也不需要Steam。代码中的诊断输出目录由runner设置，不能把文件输出开销解释成纯ABI成本。

## Go／No-Go与下一步

**Go接受本轮single-pass完整外层调用纵切。** 新source overlay、诊断构建、四配置实际执行和独立reader均已通过本轮范围；首次调用点定位错误的两轮失败单列保留。下一步可扩大正确性范围或设计明确的重复回放，但本轮不等于完整ABI优化或完整迁移工具完成。

**No-Go把本轮称为性能实验或完整矩阵。** 本次只覆盖首选基址、两个正常消息及两个guest优化级别；没有重跑前批32正常＋1456预算、共1488次回调内核矩阵，没有新的原始x86差分。完整重复回放的A0仍有same-address恢复、确定性输入和双账本工作；A3的预算／默认API／ABI破坏／ExitProcess负例，A4及之后的pilot、计时合同和正式采样均待做。

本轮通过后先补其证据暴露的缺口，再选择下一切片：更多正常场景与严格终止负例，或明确输入重置和累计账本的回放生成器。必须在完整正确性和实验合同通过后才计时；不能削减State、snapshot或frames来提前制造更快结果。代表性App负载、Wine／Rosetta同场景基线、真实合法单机游戏、干净机器和发行仍另设验收。
