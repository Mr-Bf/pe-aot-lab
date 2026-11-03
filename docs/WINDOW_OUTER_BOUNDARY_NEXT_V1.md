# 外层 ABI 预算与终止边界：下一纵切设计 v1

状态：`DESIGN_SOURCE_REVIEW_NOT_IMPLEMENTED_NOT_EXECUTED_NOT_MEASURED`。日期：2026-11-03。

本文件只读核对现有源码和已有 `window_outer_replay_v1/run-01` 事件；没有运行 native、UI、reader、构建或测试。这里给出下一批 A3 的最小实现合同，不修改已经冻结的[正常重放合同](WINDOW_OUTER_REPLAY_CONTRACT_V1.md)、[实际报告](WINDOW_OUTER_REPLAY_V1.md)或历史 [NEXT](WINDOW_OUTER_ABI_NEXT_V1.md)。文中的“期望”均是下一批验收条件，不是新实验结果。

## 1. 本次应实现什么

**建议先实现真实主程序中的一次预算耗尽，再让原执行入口返回和宿主正常清理；不对失败路径做重放或恢复。** 已完成的同地址两次正常诊断加一次 continuation，只证明两种准入消息的正常路径；它明确拒绝 fault/Exit 后的恢复。下一批若为了得到可比结果清除 fault、重设 session 或恢复原始边界，会破坏正在验证的生产终止语义。

每个负例使用独立 native 进程。原 host 创建真实 Cocoa/D3D/User32/file/callback 会话，原提升 main 到达唯一选定的真实 signature214 边界。此时只把当前 `Context.budget` 改为 `B + delta`，其中 `B` 是该真实边界捕获的 `result.steps`。调用原 dispatcher 一次，记录预算耗尽和 native 栈展开，交还原 main/`aot_execute`，让原 host 清理。不可再运行第二个顶层 `aot_execute`，也不可在故障后继续消息处理。

本纵切回答的是：预算拒绝发生在正确指令/边界；故障与已提交 guest 写入不丢失；正常 callback 恢复与终止 callback 不恢复的分界正确；原 owner 会话完成真实资源清理。它不完成整个 A3，不证明 ExitProcess-in-callback、任意异常、跨进程全字节等价或性能。

## 2. 固定来源及真实入口

输入仍为合法自制 `examples/window-switch/switch_tile.exe`，SHA256 为 `39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`。复用已冻结 `build/window-lookup-v1/app-01` 的提升对象和真实图形后端，建立新版本诊断 overlay；不修改旧生产 App、旧 replay 模块或既有失败证据。具体新模块名、CLI 和实际输出目录须由实现后报告给出，本文不提供尚不存在的“可运行命令”。

真实选定位点继续使用：

| 项目 | 合同 |
|---|---|
| 正常消息循环外层 CALL | RVA5839／`0x16cf`，kind4，R12，signature214，target=`base+0xf00d6000` |
| 外层正常返回位置 | RVA5842／`0x16d2` |
| KEYUP 内层 CALL | RVA4248／`0x1098`，signature212，target=`base+0xf00d4000` |
| WndProc | RVA4096／`0x1000` |
| RIGHT switch leaf | RVA7216／`0x1c30` |
| MSG | 原真实48B，RCX=`base+0x3190`；本纵切不改 time/pt 或其他 MSG 字节 |
| 未准入的同目标 CALL | cleanup drain RVA6051／`0x17a3`／RDI；仍拒绝 |

在改预算前核验原 State/Context 参数地址、owner thread、`session.running/used`、User32/Callback owner、完整 import binding、当前 CALL metadata、RIP、frame/return slot、DF、RSP、pending/in_instruction、零 fault/returned/exit latch，及完整 region/table/permission 身份。只识别 signature214 不足以开始诊断。原预算必须足够到达边界；`B + delta` 需要显式检查 uint64 溢出，且不重置 `steps`。

保存 `original-before` 与 `prepared-before` 两份完整快照；二者只有预算那个精确8B字段可以不同。其余 State/Context、所有 guest backing、权限表、instruction table、host TLS 字节必须不变。若预算已经等于拟注入值，可记录零字节差，但仍明确这是预算输入。诊断缓冲区只保存副本和数字身份；所有 live 访问沿真实 helper 参数传递，不从 TLS 中另取可解引用的 live 指针。

## 3. 已有路径长度与预算点

只读已有 `build/window-outer-replay-v1/run-01/reference-O0/diagnostic/events.jsonl` 中正常 `diag0`，得到以下相对步数。RIGHT 的当次 B=438，KEYUP 的当次 B=566；这些绝对值只是既有运行事实，**新实现不得硬编码它们**，启动 sent notification 可改变前缀计数。

| 正常事件 | RIGHT 相对 B | KEYUP 相对 B |
|---|---:|---:|
| 外层214 / callback进入 | 0 | 0 |
| 真实212 helper进入 | 无 | 12 |
| 内层212 RET完成 | 无 | 13 |
| callback正常返回 | 45 | 17 |
| 外层214 RET完成 | 46 | 18 |

这些长度仅对当前固定字节、路径和语义有效。新构建先运行对应正常 control 并检查同样的相对事件/指令事实；若不同，应阻止负例验收并保留证据，不能调整 expected 值来迁就候选输出。

建议第一片取 reference lookup 与 inline lookup 的 guest O3，各执行以下四个负例，以及一个完整正常 control；计划合计10个新 native 进程。O0、第二合法基址、全部预算点和其余消息留给扩展矩阵。每个目录必须新建，串行运行并取得旧/新 observer 共用锁；四个负例不能在同一个已经 terminal 的 session 内拼接。

| case | 真实消息队列前缀 | 注入余量 delta | 期望 terminal 位置与意义 |
|---|---|---:|---|
| `keyup-outer-budget-0` | `right,right-up` | 0 | 原214 helper预算检查拒绝，尚未增加214 API/posted/callback计数，没有进入 WndProc |
| `keyup-nested-budget-12` | `right,right-up` | 12 | WndProc已执行至真实212 CALL并提交；212 helper预算检查拒绝，212 API与其 RET 尚未执行 |
| `keyup-outer-ret-budget-17` | `right,right-up` | 17 | callback已正常返回并恢复外层边界；原214 helper设置返回结果后进入真实 RET，RET在 `aot_begin` 预算检查拒绝，没有提交 |
| `right-outer-ret-budget-45` | `right` | 45 | RIGHT callback与switch已正常完成，实际 guest 更新保留；外层真实 RET进入后预算拒绝，没有提交 |
| `normal-control` | `right,right-up,escape` | 不注入 | 正常真实 main 继续绘图、保存、释放并退出；观测两个选定消息各一次，不重放 |

KEYUP 的前置 RIGHT 是原程序自然执行一次，不算诊断重放；保存其真实发生与完成的证据。队列只投递到需要的消息，负例不再请求 escape，以免拿“未投递的第三个事件”当成故障或误把后续保存写成预期。输入来自 `TEST_QUEUE`，不是操作系统键盘。正常 control 也不是 noarg App。

`delta=18`（KEYUP）或46（RIGHT）可让所选外层 RET完成，但随后下一条 main 指令会耗尽预算；不能自动把原预算改回来制造正常 continuation。这类“边界已完成、下一主程序指令失败”应作为后续独立 case，写清期望 PC。同理，预算必须覆盖实际 `aot_begin` 次数，不能按 C函数调用数或“消息一个单位”解释。

## 4. 预算拒绝的精确语义

源码依据：[`transaction_v1.c`](../window_bridge/window_runtime/transaction_v1.c):`aot_begin/aot_commit/fault`，[`runtime.c`](../window_bridge/window_runtime/runtime.c):`__remill_function_call/aot_execute`，[`callback_v1.inc`](../window_bridge/callback_v1.inc):`aot_wndproc_invoke/wnd_restore`，[`user32_v1.inc`](../window_bridge/user32_v1.inc):`wui_invoke/wui_dispatch/wui_callback`。

原 import helper先验证 owner和signature，写 `current_pc=pc`，检查RSP/DF，再检查预算，随后才检查 thunk/return/shadow并调用 API。signature9 的预算相等行为特殊，本片没有覆盖它。`aot_begin` 则先检查既有terminal，再设置 `current_pc` 和 State.RIP，再检查预算；预算失败在更新 `current`、snapshot、binding、`in_instruction`和递增steps之前。因此“拒绝不改变任何 Context 字节”是错误 oracle，应精确重建这些按顺序发生的字段变化。

所有负例期望首个 fault 为 `AOT_BUDGET=4`，宽度和access为0；故障PC/address由真实拒绝边界决定，不能只验status。首fault不可被外层传播覆盖。

| 相对 prepared-before 的区间账本 | KEYUP余量0 | KEYUP余量12 | KEYUP余量17 | RIGHT余量45 |
|---|---:|---:|---:|---:|
| guest steps增量 | 0 | 12 | 17 | 45 |
| switch提交增量 | 0 | 0 | 0 | 1 |
| User32 signature214增量 | 0 | 1 | 1 | 1 |
| User32 signature212增量 | 0 | 0 | 1 | 0 |
| posted_dispatches / User32 callbacks增量 | 各0 | 各1 | 各1 | 各1 |
| Callback calls / returns增量 | 0 / 0 | 1 / 0 | 1 / 1 | 1 / 1 |
| Callback rejections增量 | 0 | 0 | 0 | 0 |
| 内层import RET完成数 | 0 | 0 | 1 | 0 |
| 外层import RET进入数 / 完成数 | 0 / 0 | 0 / 0 | 1 / 0 | 1 / 0 |
| terminal guest call_depth | 1 | 3 | 1 | 1 |
| native callback TLS depth收口 | 0 | 0 | 0 | 0 |

“Callback rejections=0”不意味着没有故障：本片故障发生在import/engine，callback只传播它。余量12时保留真实嵌套 CALL 帧、当前回调State和已提交栈；只减少native callback TLS depth，不执行 `wnd_restore`。余量17/45时 callback正常返回已经执行 `wnd_restore`并增加returns，但外RET不能pop frame、不能增加steps，也不能被误记为正常返回到main。

RIGHT余量45必须保留 position3→4、moves与keydowns各加1、dirty=1、switch提交1及对应guest内存写入；不能恢复为原position3来伪装原子失败。KEYUP余量12/17的image除原输入外无回调业务修改，但真实callback/内部调用栈写入仍保留。不同阶段的栈必须按固定PE实际写入和RET/marker规则推导，不能大范围mask RSP以下内容以取得差分。

## 5. terminal传播、宿主清理和副作用

一旦原 dispatcher返回，observer只记录当前结果，不改fault、budget、State、Context或guest内存，不调用回放reset，不继续另一轮。fault传播期间 `aot_should_exit` 阻止新的guest指令；原 `aot_execute` 返回，真实session.running收口。保留 `session.used`，不伪造owner，不调用 `TestOwner`。

新observer需要明确允许**预期的 terminal 返回**。旧replay observer对非正常回调/RET调用 `_Exit(65)` 是诊断失败策略，不能不经改造就用来“证明预算退出”。新负例应执行到原host最终JSON，期望 `outcome=FAULT`、`aot_status=4`、`host_exit_code=3`、OS退出码3，setup/join/清理错误为0、无timeout、native ARM64。exit64/65、signal、超时或无最终回执均不是预期通过。正常control则保留其正常ProcessExit门禁。

真实清理仍由 [`window_host.c`](../window_bridge/window_host.c):`worker/main` 执行：D3D清理释放对象和view/map；User32/Callback session收口；file session关闭实际句柄；主线程 `wb_host_finish` 完成原生窗口清理。原源码明确不在清理中调用guest WndProc、合成QUIT或写save。因此负例的新独立Data目录不应产生游戏保存；清理的真实资源计数必须保留。宿主stdout的清理后结果与observer的terminal-before-cleanup是两个阶段，不能要求TLS在清理前后完全相等。

所选边界内部仍只允许既定214及KEYUP一次真实212；在执行未知nested API前拒绝，避免意外文件/GPU/窗口生命周期副作用。完整D3D/FileTLS在选定区间内应不变；User32/Callback只允许上表与精确phase转换。Cocoa主线程可继续pump异步事件，不承诺整个Cocoa内部状态不变，也不增加每phase的宿主查询来污染计数。全量FileSession、next_handle和files_ready若仍仅在C guard中比较，报告必须继续区分“runtime完整核验”和“reader独立核验已导出的LastError/API/读写计数”。

此片没有恢复、没有隐含额外执行量，`reset_count=0`、`diagnostic_replays=0`、选定负例调用次数1。最终Context.steps保留实际到故障为止的累计值，不把observer外账替代它。host实际API/callback计数不回滚；对前置RIGHT和初始化消息的总账从真实事件链求和，不能硬编码上批正常进程的809步/9次callback。

## 6. 独立读验不能只比较两份结果

沿用完整3504B State、5792B Context及所有guest backing/table/permission捕获，布局须再次与编译产物一致；数值不是可替代布局验收的硬编码借口。每个phase都校验静态身份、预算、指针/region长度、inactive frames、reserved/padding和完整三宿主session转换，不能只要求三个快照相互一致。

前批reader01曾误接受12个自洽伪造反例，reader02增加了每phase完整entry/RET和host转换oracle。本片要继承这些门禁，并新增terminal相位规则；不能因为没有正常RET就跳过整个Context验证。预算注入前后须有唯一精确变换；失败点后各外层捕获的guestState/Context/内存不得被恢复成成功边界；native TLS depth下降是必须单列的真实变化。

事件至少区分：外层调用前原始捕获、注入后捕获、callback进入、真实nested212进入/返回、各RET进入/提交、callback正常/terminal返回、外层terminal返回、最终host退出。不存在的事件不能由placeholder充数。逐项核验顺序、数量、case身份、消息来源、完整快照引用、单调seq、文件闭包和EOF。必须观察真实事件，不能只信observer写的 `terminal_preserved=true`。

独立oracle至少覆盖：预算守卫先后顺序；fault PC/address；全部Context身份与帧；实际允许的State变化；image完整业务变化；非image/stack backing与权限不变；callback marker/shadow与该终止点已执行的栈写入；三host session phase变化；最终清理和Data目录。其余栈字节若尚无独立语义oracle，应明确 `full_below_rsp_independent_oracle=false`，不得以reference/candidate相等替代正确性证明。

跨进程保留原MSG time/pt和真实host地址。只进行各进程独立oracle及声明过的语义对照；不新增宽泛pointer/stack mask，不宣称全字节跨进程等价。各策略独立正确后，才谈同一case的语义一致。

建议纯文件反例至少包含：预算+1/−1；保留正确status但错fault PC；移除真实212/伪造212 API增加；把未提交RET伪造为完成；fault后RSP/frames被复原；RIGHT写入被回滚；bindings/current/snapshot的错误phase；Context静态地址/unused frame变更；不准确TLS深度/returns；cleanup前后混淆；篡改退出码、缺失最终JSON、额外save。其数目必须按实际测试单列，不能算作native ABI负例，也不能拿reader重复运行次数扩大native样本数。

## 7. LLVM、构建和运行门禁

对实际提升IR及最终声明检查同签名helper和callback effect，禁止错误的 `nocallback`、readonly/readnone、纯参数内存或错误calling convention。State/Context仍从当前真实参数访问；不得通过保存副本中的指针“重新找到”live入口。预算改写发生在真实helper边界，不能给编译器仍可缓存预算不变的契约。O3负例若与reference不符，先保留失败IR/机器码/快照，不下调检查或用全局volatile掩盖问题。

冻结原生产host、runtime、transaction、callback、User32、文件API、generator、layout、profile、PE、提升对象、backend、编译器及实际依赖SHA。新overlay只增加诊断捕获与唯一预算输入，不替换生产budget/RET/fault实现。每条生成命令和各obj/IR/exe的SHA采用单调ledger，构建与运行前后核验输入/产物，失败目录不覆盖。该核验不构成恶意主机瞬态改动的attestation。

运行工具需区分正常control和预期fault的receipt；旧成功runner的exit0、posted3、save存在规则不得直接套用。旧/新observer用同一稳定顺序获取非阻塞共锁，Popen后立刻拥有child并在任何异常时清理和wait，只终止本工具启动的进程。保存退出码3不是放宽任意异常；必须同时通过精确fault、terminal快照和宿主清理规则。所有native逐个串行，证据导出和reader不进入性能计时范围。

## 8. 后续扩展与停止条件

第一片通过后再扩展O0/O3、两个合法基址、callback内部预算点、KEYUP0…18/RIGHT0…46的完整区间、call-depth/返回槽/DF/RSP/权限/未知API分层负例及更多真实消息。原32/1456矩阵若没有在完整外层路径重跑，仍只是原范围的历史证据。

**ExitProcess-in-callback必须另建自制PE。** 当前Escape先走消息/主循环退出，不能代表WndProc中实际调用signature9。新fixture应在真实WndProc内发出真实ExitProcess，验证exit latch/code/PC/RSP/depth、停止后State/frames/已提交内存不恢复、无内外RET和真实host清理；不得在observer里直接调用Exit、改signature或拿宿主exit充数。signature9对预算相等的特殊规则也需独立精确case。

出现任何source身份不符、未声明nested API、异常region身份/权限变化、owner变更、原终止状态被改写、清理失败或reader无法解释的字节，停止该case验收并保留证据。不得把fault修成继续运行以完成矩阵。

设计结论是 **Go：正常消息路径的最小预算terminal纵切**；**No-Go：宣称完整A0/A3关闭、一般terminal重放、任意Win64应用迁移或性能收益**。真实第三方程序转换成功数仍为0。固定真实目标的PE/依赖盘点可以并行降低迁移范围的不确定性，但不能用本诊断通过替代真实应用集成。

## 附录 A：供真实目标盘点使用的 v7 能力描述

这里只列只读源码事实，供独立inventory/gap适配层复用，不改变其实现。不能按函数名、DLL名、API标签或Remill自身指令库推断本项目支持。可用入口与证据层必须分开：

| 入口/阶段 | 可复用能力 | 不能推导的结论 |
|---|---|---|
| `migration_v1.analyze.read_input` | regular file，最多64MiB的有界读取 | 不是loader/admission；直接调用inventory(bytes)时仍需外部大小上限 |
| `migration_v1.analyze.inventory` | PE32+元数据、sections、directories、named/ordinal imports盘点 | 其import.binding源于旧process-v1六项表，不能作为v7支持结论；不要复用console-v1的analyze verdict |
| `window_switch_v1.profile.analyze(data,profile)` | 真正v7使用的显式schema2/profile与strict loader入口 | `ELIGIBLE_FOR_BUILD_NOT_DECODED`未执行decoder或runtime；失败只返回首个错误 |
| `window_switch_v1.lift.Compiler.roots` | decode-only→独立原字节admission/root证明→lifting→ARM retarget | 需要真实依赖与显式根；metadata盘点不能声称已经完成这些阶段 |

建议输出结构把事实、当前阻断与未知项分开，例如：

```json
{
  "schema": 1,
  "capability_contract": "migration-v7-win32-d3d11-tile-switch-v1",
  "evidence_scope": "source-reviewed",
  "guest_executions": 0,
  "gates": [
    {
      "id": "profile.explicit_callbacks_and_switch_leaf",
      "stage": "profile",
      "status": "requires_explicit_profile",
      "source": {
        "path": "window_switch_v1/profile.py",
        "symbol": "validate"
      }
    }
  ],
  "imports": [
    {
      "dll": "kernel32.dll",
      "name": "GetModuleHandleA",
      "label_known": true,
      "signature_id": 201,
      "argument_contract": "lpModuleName must be NULL",
      "target_arguments_verified": false,
      "runtime_status": "runtime_arguments_unproven"
    }
  ],
  "decoder_executed": false,
  "build_verified": false,
  "target_runtime_verified": false
}
```

上例为schema建议，不代表已经在某真实目标中发现该导入。`status`宜用 `blocked_by_current_gate`、`requires_explicit_profile`、`admitted_not_decoded`、`runtime_arguments_unproven`、`not_examined`，而不是不分层的supported布尔值。每条gate附source路径/符号/固定SHA及target事实位置；未知不能写成支持，单个loader首错不能覆盖后续全部能力。资源/debug目录被当前policy拒绝，不等于输入PE损坏或从原理上不可AOT。

当前代表性阻断如下：

| 建议稳定gate ID | 当前准确合同与根因 | 源码 |
|---|---|---|
| `pe.amd64_gui_exe` | AMD64 PE32+、EXECUTABLE_IMAGE、非DLL；profile额外要求GUI subsystem2。依赖DLL可盘点但当前不加载多模块 | `memory_stage2/image_loader.py:load_image`；`window_profile_v1/profile.py:validate` |
| `pe.header_alignment_size` | optional header恰240B，16目录，section/file alignment4096/512，image≤64MiB且4KiB倍数，base64KiB对齐，拒绝W+X | `memory_stage2/image_loader.py:load_image` |
| `pe.directories_1_5_12_only` | 非空目录仅import1、reloc5、IAT12；resource2、exception3、certificate4、debug6、TLS9、load-config10、delay-import13等均被当前loader拒绝 | `callback_bridge/imports_v1.py:load_imported_image`清1/12后进入plain loader |
| `pe.reloc_dir64` | reloc只认ABSOLUTE padding0与DIR64 10；拒绝重叠patch、修改reloc元数据；改变base需要实际可用reloc | `memory_stage2/image_loader.py:load_image` |
| `imports.named_split_tables` | 命名导入、独立非零8B对齐ILT/IAT、原IAT==ILT、stamp/forward=0、完整终止与元数据边界；拒绝ordinal、绑定/延迟导入及重叠 | `callback_bridge/imports_v1.py:load_imported_image` |
| `imports.v7_known_labels` | 精确21项标签来自window_inc表；命中仅表示可以绑定到受限signature，不保证目标参数/行为 | `window_inc_v1/loader.py:SIGNATURES` |
| `profile.explicit_roots` | schema2精确字段、PE SHA、1…8显式callback根、精确排序imports、受限observations、一个不同于main/callback的RX switch leaf | `window_switch_v1/profile.py:validate`；`window_profile_v1/profile.py:validate` |
| `decode.one_exec_32k` | 恰一个可执行section，file-backed代码1…32768B，全部根位于其中，DIR64不得重叠代码 | `portable_app_v1/lift.py:executable_bytes` |
| `switch.one_ro_64k` | 恰一个非.reloc只读section、1…65536B；一个7指令形状的scalar signed-rel32 leaf，2…32项，目标在代码内且独立byte/CFG证明 | `window_switch_v1/lift.py:Compiler.roots`；`SwitchProfile.h`；`admission.py` |
| `decode.integer_operands` | class白名单之外拒绝；即使class命中仍有前缀/寄存器/width/operand/flags证明限制。拒绝SIMD/x87、LOCK/REP、FS/GS、address-size override、RET imm和syscall | `window_bridge/aot-profile-v1.patch`及window/inc/switch补丁；`window_inc_v1/lift.py` |
| `cfg.restricted_indirect` | 只准入已证明direct流、指定COM槽形状、运行时精确绑定IAT register call和单个有限switch；非一般间接函数调用/JMP。IAT_REG64与VTABLE_MEM64 base均排除RSP | `window_inc_v1/lift.py:validate_register_instruction/validate_virtual_instruction`；switch admission；runtime binding checks |
| `abi.single_worker_fixed_runtime` | Win64寄存器/栈调用约定和受限callback，不提供通用Windows线程/TLS/CRT/SEH/JIT/多DLL系统；XMM非易失保存不表示SIMD decoder支持 | callback/User32/runtime；profile LIMITS |
| `runtime.fixed_api_arguments` | API参数与生命周期逐项约束；见下列例子，不能从签名名推导完整Win32行为 | `window_bridge/file_api.inc`；`user32_v1.inc`；`window_runtime/runtime.c` |
| `graphics.fixed_shader_pipeline` | 640×360 swapchain，固定triangle DXBC逐字节匹配、固定绘图/pipeline/viewport子集；不是任意D3D11或任意shader支持 | `window_bridge/window_runtime/runtime.c` |

指令class只是一层过滤：例如SETZ仅AL/SIL/DIL，SETNZ仅CL/DL/SIL，CMOVNB仅32bit reg-reg，AND8仅特定AL←CL/DL形式，TEST16仅AX/AX；memory RMW仅获准的INC m32 RIP+disp或无index/零disp的非RSP GPR64形式。未知operand即使mnemonic相同仍拒绝。retarget还拒绝未处理的x86 intrinsics、x86_fp80和inttoptr，不能把“LLVM存在ARM后端”当跨ISA转换完成。

API代表性参数合同：GetModuleHandleA201只接受NULL；GetMessageA216的hwnd/min/max全0；CreateWindowExA211只接受style0x00c80000、exstyle0、双CW_USEDEFAULT坐标、无parent/menu/param、单640×360窗口；ShowWindow220仅0/5。CreateFileA4只处理安全ASCII basename≤120、share0/securityNULL/templateNULL/attrs0x80，write+CREATE_ALWAYS或read+OPEN_EXISTING；Read/Write≤1MiB、非overlapped且输出count/buffer不重叠。D3D11CreateDeviceAndSwapChain200只接受hardware/nulladapter、FL11_0单项、SDK7及特定RGBA8双buffer flip-discard描述符；shader只匹配固定字节，Draw只接受(3,0)和既定pipeline。参数不满足可能返回Win32错误，也可能触发明确AOT fault，必须按源码分开记录。

`resources='embedded-pe-only'`只是profile禁止外部资源staging，不代表实现了PE资源目录。runtime内部signature100有代码，也不代表v7导入表允许该API。对尚未选定或未读取的真实目标，不提前断言它含哪种API、指令或目录；先绑定实际发布包/PE/依赖的来源与SHA，再报告已发现事实及当前gate。
