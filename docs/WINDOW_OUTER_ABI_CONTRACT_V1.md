# 完整外层 ABI 首段纵切：观测合同 v1

状态：`REVIEWED_SOURCE_CONTRACT_NOT_EXECUTION_EVIDENCE`。日期：2026-11-02。本文件由只读源码、前批真实提升 IR 和 profile 核对形成；编写本文件没有运行 native、App、GPU 或计时，也没有改动旧运行时。新实现及其实际结果须另留回执。

## 1. 本次收窄与未关闭项

[完整设计](WINDOW_OUTER_ABI_NEXT_V1.md)仍是后续重复回放、全矩阵和性能实验的路线。本次首段建议先做 **single-pass、无输入修改、无回放、无计时的完整边界观测**：真实 PE main 初始化真实宿主会话，以已有 `--test-sequence` 投递 RIGHT、RIGHT-UP 和退出事件，经过原 DispatchMessageA、原 WndProc ABI、真实提升回调与 RET。两个查找策略使用相同观察代码、各自独立进程和空的新数据目录。

该范围可以验证 A1 生成器与 A2 的首段真实调用链，不能记为完整重放 A0 闭合、A3 全矩阵完成或跨进程全部字节相等。现阶段不清零 MSG 时间/坐标、不还原 Context、不回滚任何宿主状态；完整导出原始字节，以同一次实际调用前后关系和独立语义 oracle 验收。这样无需先解决所有异步初始差异，也不会把未解释差异隐藏在规范化规则中。

如果新实现仅观察 import 前后而未观察 callback 自身，则只能证明完整 import 的前后状态及真实调用链，不能直接声称已独立验证 `wnd_restore` 的完整字节恢复。下节分开这两层门禁。

## 2. 真实身份与观察点

固定自制 PE SHA256：`39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`。profile 为 schema2、`win32-d3d11-tile-switch-v1`，callback RVA `0x1000`，switch leaf RVA `0x1c30`。

前批新产品 `app-build-0002/native/native_imports.h` 和 decoder metadata 给出的定位如下。构建与独立 reader 必须共同从此次真实产物及原 PE 字节重验，不能只把常量写进 observer 即认为绑定成立；单独的 source overlay 生成不等于 PE 准入。

| 边界 | 当前固定样例身份 | 必须共同匹配 |
|---|---|---|
| 正常主循环外层 DispatchMessageA | signature 214、register CALL RVA `0x16cf`（5839）、R12、目标 RVA `0xf00d6000` | current kind4／rva、import binding valid／pc／target／signature、真实 State.RIP、owner、MSG VA |
| KEYUP 嵌套 DefWindowProcA | signature 212、直接 CALL RVA `0x1098`（4248）、目标 RVA `0xf00d4000` | current kind1／rva与真实 import metadata，不能把任意212算作本次嵌套调用 |
| 消息 | `window_message` RVA `0x3190`、48B | RCX 等于 base+RVA，完整字节中的 HWND／msg／WPARAM／LPARAM符合场景 |
| 状态及观察区 | `window_state` RVA `0x3000`／20B；`window_result` RVA `0x30c0`／60B | 输入 profile 原始身份、映像映射边界和实际 PE 数据；不能通过搜索输出字节猜偏移 |

**样例存在两个 DispatchMessageA 位点，不能把 signature 214 或同一IAT当作唯一调用点。** 正常主循环在RVA5457以RIP相对MOV装入R12，下一PC+4696指向IAT RVA10160，随后在5839以字节 `41ffd4` 调用R12。退出后的drain loop在RVA6022以RIP相对MOV装入RDI，也读取同一IAT，随后在RVA6051（`0x17a3`，字节 `ffd7`）调用RDI。本次只接受正常主循环5839／R12，清理循环6051／RDI继续拒绝；不扩为两个位点的白名单。

首次只读定位把清理循环6051／RDI误记为唯一位点，初observer因此拒绝合法的正常主循环输入。root实际执行的 `build/window-outer-abi-v1/run-01` 保留首次guard失败，`run-02/reference-O0/stderr` 补充的原始字段为：`current_rva=5839, kind=4, pc=9396117504, module_base=5368709120, rcx=5368721808, pending_size=0, in_instruction=0, fault=0, returned=0, import_binding_valid=1, import_binding_pc=5368714959, import_binding_target=9396117504, import_signature=214`。目标和MSG地址以及已提交边界均合法；错误在观察器选择了错误调用点。诊断在进入被选中的callback观察区间之前主动拒绝，不是生产runtime或guest的执行错误。本合同据此修正定位；两份失败不覆盖，不计入正确性成功。修正后的实际运行与读验结果必须另取新目录回执，不能由这次定位推断通过。

观察点建议为：

1. `import-enter`：真实已提交的外层214 CALL进入原 helper 前；不消耗任何额外 guest 指令。
2. `callback-enter`：原 `aot_wndproc_invoke` 已由真实 `wui_callback` 调用、尚未改写 callback State/栈前。
3. KEYUP时的嵌套 `import-enter/leave` 212；RIGHT不应出现该事件。
4. `callback-leave`：原 `aot_wndproc_invoke` 已经返回，检查实际状态码及输出值；正常返回时原函数已经执行 `wnd_restore`。
5. `import-leave`：原214 helper完整返回，此时外层真实 `aot_import_ret` 已执行。

每个事件使用单调序号、父事件编号、实际线程身份、数字 owner 身份、调用深度和原始输入；事件流长度与 EOF 必须严格校验。只记录被选中214区间及其真正嵌套调用，并记录越界／溢出／文件写失败为整次诊断失败，不能丢记录后报成功。observer 不得手写 `session.running`、`session.used` 或调用 `TestOwner`。

## 3. 捕获字段与单次边界关系

完整记录包含 3504B State、完整 `sizeof(AotContext)` 原始字节、每个 guest region 的完整 backing bytes 与权限，以及实际字段布局表。以下是 Context 源字段清单，具体 offset／size／alignment 只能来自新构建使用的实际 C 编译探针，不能硬编码另一个 ABI 的布局。

| 类别 | 字段 |
|---|---|
| 会话输入／地址 | `module_base, budget, exit_pc, initial_rsp, instructions, instruction_count, region_count` |
| guest 映射 | `regions[]` 每项 `base,size,bytes,permissions,page_count`；包括未激活槽的原始字节 |
| 状态／事务 | `result`全部、`current_pc,current,in_instruction,pending_size,pending,pending_value` |
| guest 返回／快照 | 全部 `frames[]` 和 `snapshot`，包括未激活frame，不只读取当前深度 |
| COM绑定 | `d3d_binding_valid,d3d_object_index,d3d_signature,d3d_binding_pc,d3d_binding_target` |
| import绑定 | `import_binding_valid,import_signature,import_binding_pc,import_binding_target` |
| 映射权限所有权 | `d3d_map_permissions`及其对应实际权限字节 |
| switch扩展 | `switch_pc,switch_targets[],switch_count,switch_bound,switch_binding_attempted,switch_commits` |

捕获 buffers 与 live State／Context／guest backing不重叠。live读取只从当前函数真实参数派生，捕获后留存字节，不从保存下来的地址重新访问live对象。保存原始Context内的指针字节用于身份对账，不代表这些指针可以在另一个进程解引用。

**callback层强门禁（正常RIGHT／RIGHT-UP）：**

- `callback-enter/leave` 的完整 State 应逐字节相等，因为 `wnd_restore`恢复全部 State；真实 LRESULT另由输出参数传回。
- Context除 `result.steps` 与 `switch_commits` 两个精确字段外，应逐字节相等。steps必须实际增加；RIGHT switch增量为1，KEYUP为0。差分规则须使用布局探针得到的精确字节槽，先核对字段数值，再逐字节核对剩余全部Context。不得扩大到整个result或相邻padding。
- call_depth回到原值；callback stats.calls/returns各增加1，rejections不变，depth回原值。`max_depth`是高水位，不要求每次加1。
- guest内存不回滚：marker/shadow和提升代码的栈写会保留；RIGHT修改实际状态。需要记录完整stack和映像，不能错误要求它们逐字节相等。
- callback成功结果不能从RAX单独推断，必须检查原函数实际返回 `AOT_OK`、返回值、fault／exit latch和真实callback账本。

**import层门禁：** 外层214的真实RET已经改变 RIP、RSP、snapshot、current、steps和call_depth，因此import前后不能套用callback层的“完整State恢复”规则。需要从进入时顶层ReturnFrame、原栈返回槽和实际RET事件，核对离开时 RIP=旧frame.pc、RSP=旧frame.rsp、call_depth减少1、returned仍为0、fault为0、binding valid清除，RAX为实际LRESULT。RET本身应增加一个guest step；KEYUP嵌套212还有独立的一次import RET。完整原始导出用于解释其余合法变化；未实现精确转换核对的字段必须写明未验，不能宽泛mask后宣称整Context相等。

**宿主账本：** 214外层区间的 `user32.stats.api_calls[5]`、posted_dispatches、callbacks和callback calls/returns各增加1；KEYUP额外 `api_calls[3]`（212）增加1，RIGHT该项不变。所选区间内D3D stats、文件API计数、LastError、对象／映射／窗口生命周期状态不得有未声明变化。计数取该区间增量，不假设整个App在启动期间没有其他真实callback或异步sent通知。

## 4. 独立场景 oracle

`switch_tile.cpp`、固定PE和profile共同提供样例语义；源码帮助解释，真实执行仍是提升后的PE字节。

| 场景 | 进入条件 | 必须观测的结果 |
|---|---|---|
| RIGHT | MSG=0x100，WPARAM=0x27，LPARAM bit30=0，position=3 | position=4，moves增1，keydowns增1，dirty=1；switch_commits增1；无嵌套API；实际LRESULT=0 |
| RIGHT-UP | MSG=0x101，WPARAM=0x27 | sample／Observations在本次回调内不变；真实DefWindowProcA调用一次且返回0；switch_commits不变；LRESULT=0 |

RIGHT与KEYUP之间主循环可能绘图，故不能用两个区间之间的状态差直接当作KEYUP副作用；必须比较该次callback或该次214的进入／离开。最后退出事件只用于正常收口与资源释放，不作为这两个受限区间的性能样本。test-sequence属于明确受控测试输入，不能称为物理键盘或无测试队列App运行。

正常后必须让原PE继续运行并真实保存／释放资源／退出；owner会话只使用一次。凡fault、预算终止、ExitProcess都单独留失败证据，不清除fault或exit latch再继续。广泛负例仍属于后续A3。

## 5. MSG确定性与后续重放清单

当前 `cocoa_host.mm:input_metadata` 即使处理test-post也读取系统uptime与鼠标位置。GetMessage生成48B的MSG：HWND偏移0／8B，message偏移8／4B，WPARAM偏移16／8B，LPARAM偏移24／8B，time偏移32／4B，pt.x偏移36／4B，pt.y偏移40／4B；偏移12…15与44…47由原实现置零。

`wui_dispatch`只使用HWND/message/WPARAM/LPARAM，未读取time/pt。本轮single-pass观察因此保留全部原值，完全不做输入规范化。可比较两个策略的独立语义与恢复关系，**不据此宣称跨进程完整State／Context／映像／栈字节相等**。

后续重复回放至少还需要：

1. 原始真实边界与独立诊断输入分开留存；如果固定MSG，白名单仅先允许32…43这12B，每个字段记录旧值、新值、理由及输入SHA。不能修改HWND、语义参数或padding来制造相等结果。
2. 逐项调查初始化期间的sent通知、focus、paint、frame metrics及guest残留栈状态。上述12B固定不保证其余输入相同。无法解释的差异阻止全字节差分验收。
3. 恢复live State与完整Context须使用同一地址；Context的指针、region和权限所有权先逐项验证仍指向原有效对象。禁止从另一个进程拷贝Context或把副本地址交给原dispatcher。
4. 只恢复已声明的guest bytes／权限，绝不memcpy恢复整个D3D、User32、file或Cocoa session。它们含native对象、allocation、异步状态和资源所有权。
5. Context的steps与switch_commits将被reset，必须另有每轮delta和外部累计总账；TLS中的原业务计数真实累加，禁止清零。最后恢复原始真实边界并只执行一次continuation，其他诊断执行量单列。
6. 跨进程比较若确有需要，精确宿主指针槽包括 `instructions,current,pending.byte[16],regions[].bytes,regions[].permissions,d3d_map_permissions`；它们须按区域／偏移身份建立可验证映射，而不是清零邻近区域。所有未激活槽、padding和guest VA保留；两个基址各自比较。

因此本文件只闭合single-pass观察合同，**完整回放A0尚未闭合**。

## 6. LLVM别名、副作用与生成器门禁

前批真实 `native/compiler/window-proc-1000/arm64.ll` 中，根函数及switch helper的State／memory参数带 `noalias`；`__remill_function_call` 的实际声明关联组为 `memory(readwrite)`，含 `noduplicate noinline nounwind optnone`，没有 `nocallback`。这只是前批IR事实，新诊断产物必须重新检查。

- 同签名保留 `void *(void *, uint64_t, void *)`，不通过不同类型函数指针转换接入。wrapper只能从真实State／Context参数派生live指针；TLS可存数字身份、计数和捕获字节，不能存可在回调中重新取回解引用的独立live指针。
- callback/import/RET observer有读取和写入自身记录的副作用，helper不得带 `nocallback`、`readonly`、`readnone`、`writeonly`、`argmemonly`、`inaccessiblememonly`、`inaccessiblemem_or_argmemonly`、`speculatable` 或过窄的 `memory(...)`。实际优化IR的相关声明和调用点都要检查，不能因同文件中无关纯helper带nocallback而错误拒绝整个模块。
- 原 `window_bridge/lift.py:validate_helper_effects`已经拒绝错误helper契约；新wrapper／hook实际IR与引用路径还需要自己的门禁。保留无LTO、固定编译器、编译依赖清单、符号和链接来源，不靠源码推断优化后调用仍存在。
- 首段source overlay只做固定模板、唯一锚点的命名／观察点增量；原User32分支、callback保存恢复、RET shim与未知语义拒绝不变。发布diff并校验未触及的源区域。
- 对实际回调执行成功的证明需要source绑定、事件流、RET计数和完整边界联合验证；把诊断布尔值写成true、只有包装函数被调用或只见最终图形画面都不足以替代。

## 7. 本次只读核对的源摘要

| 文件 | SHA256 |
|---|---|
| `window_bridge/window_runtime/runtime.c` | `9051c121f680988bc4f13a072dacbf213e8612fd3d095acc5704b388f87defd8` |
| `window_bridge/window_runtime/transaction_v1.c` | `0b0baf46ea802e3984065dad3be3f36a10a6fcc6d4f0d102e52a5913becaf8ed` |
| `window_bridge/callback_v1.inc` | `fa0c8108f08e10feaed87936a9440503b30ef1eaf2cce4eefb79470781f0ada2` |
| `window_bridge/user32_v1.inc` | `14a319668cd5e8856b017f9a7d54782556d461295033755f875fafadc14d20cf` |
| `window_bridge/lift.py` | `d43e6251be8893647e82d78428b36d7f624b6898f7911e08533fe76dcbfac978` |
| `window_switch_v1/runtime_fields.inc` | `76914960267b0a9f61909c85e366fbf8c66472f9cc686d3efa6c83c1257c4d2a` |
| `examples/window-switch/profile.json` | `c3974063866c3c80c4e1cb9af46748cc8c2f6039ae286bc6c8afb12c1dd74d76` |
| `switch_window_fixture_v1/switch_tile.cpp` | `6ccbe7814414503972db7de8b9b60a40ac297ffe10611ae4f995a80a1ce87577` |
| `window_bridge/cocoa_host.mm` | `6a50c36b492869ed55849dc435b54fd928c64ac344827ab695a62d26efe019d3` |

源检查给出实现约束，不提供新的运行通过、性能收益、一般Windows兼容或Steam游戏结论。
