# 外层 ABI 同地址确定性重放合同 v1

状态：`REVIEWED_SOURCE_CONTRACT_NOT_EXECUTION_EVIDENCE`。日期：2026-11-02。本文件给出当前固定自制 PE 的实施合同；编写时只读核对源码，没有运行 native、UI、reader 或性能实验。本轮实际结果必须由独立构建、运行和文件读验回执给出。本文件不修改历史 [NEXT 设计](WINDOW_OUTER_ABI_NEXT_V1.md)、[single-pass 合同](WINDOW_OUTER_ABI_CONTRACT_V1.md)及其[实际报告](WINDOW_OUTER_ABI_V1.md)。

## 1. 可实施结论与边界

**有条件 Go：在一次真实 `aot_execute` 会话中的正常 DispatchMessageA 边界，以原 State、Context 和全部原 guest backing 地址执行两轮诊断，再恢复原始真实边界并执行一次 continuation。** 只接受 RIGHT 与 KEYUP 两个已准入的正常场景；KEYUP 必须真实进入 DefWindowProcA 并执行其提升 RET，RIGHT 必须真实进入 switch leaf。诊断不计时，不替换 API，不启动第二个 `aot_execute`，不重建或者回滚宿主会话。

该结论依赖固定生产 host 的实际分配方式、固定 PE 的调用图和逐轮检查，不是任意 Windows 程序的可回滚事务。生产 ABI 没有普遍的“撤销文件/GPU/窗口调用”能力。若任何一轮出现 fault、ExitProcess、未声明的 nested import、宿主生命周期变化、region/permission 身份变化或输出证据写失败，整次诊断失败；**不得抹掉 terminal state 后再执行 continuation**。

两个 lookup 策略与 O0/O3 共四个进程可分别验证本进程同地址重放。固定 MSG 的12B不能消除 ASLR、宿主指针、初始化 sent notification 和残留栈差异，因此不承诺跨进程完整 State／Context／内存逐字节相等。原始32／1456矩阵、广泛负例、一般异常重放和性能阶段仍未关闭。

## 2. 固定准入身份

PE SHA256：`39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`。profile：schema2、`win32-d3d11-tile-switch-v1`；callback RVA `0x1000`；switch leaf RVA `0x1c30`。位置常量必须与冻结的原 PE、decoder metadata、实际链接产物共同复核。

| 项目 | 本轮唯一允许值 |
|---|---|
| 外层 CALL | signature214，正常主循环 RVA5839／`0x16cf`，kind4，R12，目标 `base+0xf00d6000` |
| 外层真实 RET | 返回 RVA5842／`0x16d2`；进入时顶层 frame 与 guest return slot 必须一致 |
| KEYUP 嵌套 CALL | signature212，RVA4248／`0x1098`，目标 `base+0xf00d4000`，每轮恰一次 |
| MSG | RCX=`base+0x3190`，48B，HWND 为当前 live 数字句柄，WPARAM=0x27 |
| RIGHT | message=0x100，LPARAM=`0x014d0001`，原始 position=3，非重复 keydown |
| KEYUP | message=0x101，LPARAM=`0xc14d0001` |

退出清理 drain loop 的6051／`0x17a3`／RDI虽然指向同一214 IAT，仍不在准入范围。以前 single-pass 首两次失败正是观察器误选此位点，不能重新把“唯一214目标”解释为“唯一调用点”。

必须同时验证真实 owner thread、`session.running/used`、State/Context 数字身份、Callback/User32 owner、已配置且唯一 callback root、原 helper参数 PC、真实 State.RIP、完整 import binding、`pending_size=0`、`in_instruction=0`、fault=0、returned=0、exit latch=0、callback depth=0以及有效顶层 frame。只匹配 signature 不足以开始重放。

## 3. 原始输入与诊断输入

在原214 helper执行前捕获 `original`，保留完整 State、完整 Context、全部 instruction table 原始字节、全部 guest region descriptor/backing/permission 字节、宿主 TLS 对照副本、数字 owner 和线程身份。State/Context当前大小3504B／5792B仅为本源版本事实；最终 reader 以实际编译布局且与固定合同一致为准。Context包括所有未激活 frames、pending 指针槽、snapshot、binding、region槽和padding，不能只摘取活动字段。

诊断输入由该原始捕获唯一派生。唯一规范化白名单为 MSG偏移32…43：`time=0x12345678, pt.x=100, pt.y=200`，little-endian字节 `7856341264000000c8000000`。HWND、message、WPARAM、LPARAM以及两段padding均保留原值。记录原始48B、诊断48B、修改的精确12B、输入摘要以及规范化理由；不得借白名单修改callback参数、sample状态或padding。

生产 `wui_dispatch`只解码 HWND/message/WPARAM/LPARAM；time/pt不传给guest callback。固定值用于诊断可比性，绝不宣称来自操作系统。最后 continuation 必须重新恢复原始48B，使用实际 GetMessage产生的time/pt。实际输入仍为 `TEST_QUEUE right,right-up,escape`，不是OS键盘，也不是生产 noarg App。

## 4. 保存与恢复对象的所有权

| 对象 | 操作及准入条件 |
|---|---|
| live State | 从当前真实helper参数读取，完整字节拷回原地址；不换成snapshot地址 |
| live Context | 全字节保存和恢复，包括steps与switch_commits；恢复前独立验证映射、table、permission身份，不能先覆盖再声称身份正确 |
| instruction table | 地址、count和全部字节必须不变；只校验，不改写 |
| guest backing | 按已核验的每个原始区域完整恢复，包括image、stack、proxy/vtable、Map shadow、scratch、RET thunk；不更换分配，不把相邻region合成跨分配写入 |
| permission表 | 地址、长度和全部字节必须不变；验证后保持原位，恢复为no-op。禁止去掉const再写入 |
| D3D/File/User32/Callback/Cocoa session | 仅捕获和核验允许的变化，不把副本写回，不重置统计或资源所有权 |
| 诊断 buffers／输出文件 | 自有宿主存储，不能与live State/Context、table、region bytes/permissions或TLS重叠；不属于guest可恢复内存 |

`window_host.c:worker`中image使用malloc，stack、proxy、Map、scratch、thunk使用calloc；guest的RO/RX权限是GuestMemory元数据，不是这些宿主分配的只读保护。因而固定host的全部backing可写回原字节。此事实不能推广到mmap只读PE、原生共享内存或别的loader。

特别核对了Map：`runtime.c:map_texture`先取得native映射，再将每行从`mapped.data`同步memcpy至独立的calloc arena。MapSlot保存object/context索引及offset/size，没有把native mapped.data安装成guest backing，也没有把arena指针交给native后端。当前六个guest backing不由Metal线程共享读写；D3D对象/映射状态本身仍在TLS，不可回滚。诊断期间必须禁止任何Map/Unmap、Present、Copy、Draw或资源调用，且检查D3D session没有变化。

权限表与backing所有权不同：image的`kImagePermissions`是生成的const对象；Map权限在session_begin被替换为`ctx->d3d_map_permissions`的独立calloc表，与`session.cleanup_permissions`别名。必须验证这组指针关系和逐字节不变，不能恢复旧host初始map_permissions指针，也不能统一memcpy所有权限表。这里“恢复权限”严格指**验证它从未改变并保持原地址原值**；若权限有变化，失败而非尝试修复。

恢复前先验证所有descriptor、table、指针/长度溢出和不重叠条件，再写任何live字节。目的地址始终从真实当前Context的已核验字段派生；保存副本中的指针字节仅用于身份比较和最终Context原址恢复，不能作为另一个可解引用live入口。恢复全部backing后拷回State/Context，逐字节再次验证恢复结果；初始化诊断输入时才额外写入获准MSG12B。

## 5. 每个消息的执行顺序

1. 真实外层CALL已提交，capture `original`，完成身份与重放资格检查。observer尚未调用原214。
2. 首轮开始时live对象已经是刚捕获的original，不必额外自拷贝；只固定MSG12B，capture `diag0-before`，原helper完整执行。记录callback前后、全部nested import与真实RET，capture `diag0-after`；验证正常返回与宿主副作用白名单。
3. 完成首次原地址恢复及相同规范化，capture `diag1-before`，原helper完整执行，capture `diag1-after`。先验证本轮语义，再验证两轮输入和输出的完整同进程字节关系。
4. 第二次恢复original，保留MSG原值，capture `continuation-before`；必须与original完整State/Context/guest bytes/permissions逐字节相等。宿主TLS计数保留前两轮真实增量。每个消息因此有两次真正reset，两个消息共四次。
5. 原helper执行**一次**，capture `continuation-after`；验证真实返回后解除观察状态，把原返回值交还原提升main。main继续真实绘图、保存、释放和退出。

每轮都调用同签名原helper `void *(void *, uint64_t, void *)`，原参数`s/pc/ctx`不变；返回值必须等于传入opaque Context。内部recursion guard只允许KEYUP的一次既定位212，且其返回值也应核对。RIGHT不允许nested import；未知签名、额外212或不同CALL位点必须**在调用原helper之前拒绝**。这比事后检查计数更关键：完成的POSIX、GPU或Cocoa副作用不能靠恢复guest memory撤销。

两轮诊断后的任何验证失败均保留当前失败状态和事件证据并终止，不reset成成功的原始状态。最终真实退出事件不重放，不清除session.used、running或exit latch。限次执行只重放当前import区间，不调用第二个顶层`aot_execute`。

## 6. 宿主副作用与统计双账

在准入RIGHT路径中，guest仅改sample/Observations、内部栈和switch计数；没有嵌套API。KEYUP的真实DefWindowProcA对准入键返回0，不修改窗口或LastError。`wui_dispatch`、`wui_callback`和callback引擎本身会增加TLS统计，这些真实执行次数必须保留。

| 每轮外层214增量 | RIGHT | KEYUP |
|---|---:|---:|
| User32 api_calls[5]（214） | 1 | 1 |
| User32 api_calls[3]（212） | 0 | 1 |
| User32 callbacks / posted_dispatches | 各1 | 各1 |
| Callback calls / returns | 各1 | 各1 |
| Callback rejections | 0 | 0 |
| callback depth | 回到0 | 回到0 |
| max_depth | max(原高水位,1) | max(原高水位,1) |
| guest steps（冻结路径预期，须实测） | 46：callback45+外RET1 | 18：callback17+外RET1，含内RET |
| guest switch_commits | 1 | 0 |

User32其余全部原始字节必须不变，包括HWND/window_state、focus、procedure、frame metrics、config.host、class_name及inactive字段/padding。Callback除上述精确统计字段外全部字节不变，root entry pointer不变。D3D session、FileSession、`wfile_next_handle`、`window_files_ready`必须完整不变，包括D3D native对象表、pipeline、map记录、arena_next、cleanup权限所有权、exit状态和全部统计，以及文件fd/token/rights、LastError、API计数、读写字节和清理计数。它们均只读核验，绝不回写。

本轮保留AOTABI1快照格式，完整导出D3D、User32和Callback三个TLS session。FileSession、next_handle和files_ready完整副本在C runtime中逐字节／逐值检查，没有单独导出原始FileTLS字节；reader对文件部分只能独立核验已导出的API计数、读写字节和LastError。**完整FileTLS不变属于runtime guard，不能宣称独立reader已核对其全部字节。**

**账本一是production continuation状态**：每次恢复包含Context.steps/switch_commits，原main最终只保留一次真正continuation的guest增量与sample效果。**账本二是实际执行总量**：observer在Context之外单调累计每轮steps/switch delta、diagnostic_calls、continuation_calls和reset_count；TLS的API/callback计数也真实累加。必须分别报告诊断与continuation，不能用恢复后的Context掩盖诊断执行量。

对两个消息全部完成，预期diagnostic_calls=4、continuation_calls=2；两个RIGHT诊断多执行92步、两个KEYUP诊断多执行36步，共128诊断步。所选六轮总计192步、3次switch；其中continuation64步、1次switch。每消息三次214、KEYUP三次212。若最终真实main与前批相同为809步，则实际总guest执行应为937步；若前批全过程callback为9，则新真实callback总数应为13。这是派生期望，不能作为新运行的既成事实，实际全进程异步启动事件仍需从回执解释。

Cocoa宿主不能做全字节快照恢复：主线程在worker诊断期间仍泵事件，queue、focus和event_pumps可能异步变化。`wb_host_stats()`本身通过on_main增加main_dispatches，调用它就有观察副作用。本轮宜不在三轮中新增Cocoa查询，使用API前置白名单与完整TLS核验约束guest发起的行为，正常收口再核对host输出。若记录host stats，应单列observer引入的main_dispatches和异步字段；不能宣称完整Cocoa/Metal内部状态不变或完整进程确定性。

## 7. 独立 reader 的验收关系

同一进程同一事件的diag0与diag1输入：完整State、Context、instruction table、所有backing和permissions逐字节相同；TLS计数应按每轮delta核验，不能把绝对值不同算失败或清零制造相等。diag0/diag1输出同样逐字节相同，包括此前没有完整语义oracle的整个RSP以下stack。该关系证明**重复执行一致**；不能自动升级为“整个stack的独立正确性oracle”。

callback-before/after仍使用原强门禁：State全字节恢复；Context仅两个精确8B字段steps/switch_commits可变，其他全部字节恢复；guest memory写入保留。外层import完整RET的RIP/RSP/depth/current/snapshot变化按原独立RET规则校验，不能错误套用callback恢复关系。

语义oracle分别检查RIGHT position3→4、moves+1、keydowns+1、dirty=1、switch+1、LRESULT0；KEYUP image语义无修改、真实212恰一次、switch0、LRESULT0。guest image的其余字节精确不变；非image/stack区域和全部权限不变；marker/shadow40B与固定PE栈写类型门禁继续保留。重复结果与oracle都通过才接受。

continuation-before必须是original完整原字节，不能只检查12B MSG或几个寄存器。其后状态与diag输出的可比范围应显式定义：State/Context/table及其他backing相同，image仅MSG32…43换回original值。比较前应先证实两轮都没有修改MSG，而不是直接mask12B遗漏坏写。此精确可逆变换仅服务当前固定路径；若实现未检查该关系，报告需写明没有验证，不能写全面等价。

reader应读取原始snapshots独立计算，不能只相信observer输出的`restored=true`或计数总数。事件必须带单调seq、事件index、attempt、role、全状态与地址身份、完整snapshot引用和外部账本；校验顺序、数量、唯一性、EOF及文件闭包。所有失败证据保留原目录，新运行使用新目录。纯文件mutation拒绝测试不计作native ABI负例；多次reader也不计作多次native执行。

## 8. LLVM alias 与 effect 审查

固定Remill guest root和内部switch函数的State/memory参数带noalias。允许原址恢复的必要条件是所有live State/Context访问都从**当前真实helper参数**派生；TLS可记录数字身份、字节副本和累加器，不能保存并重新解引用独立live指针。Context.snapshot是独立内嵌字节存储；将真实Context换成另一个副本地址、通过TLS找回原State或把callback输出buffer放进guest backing均不允许。

恢复时使用完整字节memcpy，避免C结构赋值对padding的未规定处理破坏全字节合同；保存副本不能与目的区间重叠。预检之后仍保持原table/region/permission所有权，Context里的别名指针只恢复同一对象的原值。实际root/RET仍用冻结对象，新的runtime wrapper保持相同C签名，无函数指针类型转换，不使用restrict给额外指针作错误承诺，不启用LTO来改变已审查的边界。

真实helper声明及调用点必须保持保守memory(readwrite)效果或等价未收窄默认，禁止nocallback、readonly/readnone、writeonly、argmemonly/inaccessible范围、speculatable/noreturn等错误属性。`window_bridge/lift.py:validate_helper_effects`已有检查；新runtime wrapper及实际生成IR仍应独立复核。源码上调用了原函数不等于优化后没有误编译，需保留编译命令、IR、依赖、符号和最终链接来源证据。

## 9. 本轮阻断条件与未覆盖风险

- 新host改用只读mmap或native共享region，或者任一保存对象被释放/重分配：本合同失效，不能继续完整backing恢复。
- permission内容或指针变化、instruction table变化、descriptor别名关系变化：不能写回掩盖变化，应保留失败。
- 除既定214/212以外的API、错误位点、callback重入、fault/Exit、非零DF、返回值或frame不符：进入原有terminal路径，不试图使失败“可重放”。
- 文件调用/资源创建释放/Map/Unmap/Present/窗口destroy/focus/queue消费都不具备本轮回滚合同；不得将这两条无宿主业务副作用路径扩写成通用API重放能力。
- Cocoa异步队列及nativeGPU对象内部没有原始快照oracle；本轮只有guest区间确定性与限定副作用账本，不是全进程checkpoint。
- 两轮诊断包括完整拷贝和文件I/O，不构成性能基准。no-Rosetta执行身份、实际退出和图形结果仍要以本轮native回执为证，不由源码合同推断。

## 10. 核对源摘要

| 文件 | SHA256 |
|---|---|
| `window_bridge/window_host.c` | `9b79aa34c0cfc6302f34d354b39d6bae9678b6b7efe6fe805ddbd7d072e04919` |
| `window_bridge/window_runtime/runtime.c` | `9051c121f680988bc4f13a072dacbf213e8612fd3d095acc5704b388f87defd8` |
| `window_bridge/window_runtime/transaction_v1.c` | `0b0baf46ea802e3984065dad3be3f36a10a6fcc6d4f0d102e52a5913becaf8ed` |
| `window_bridge/callback_v1.inc` | `fa0c8108f08e10feaed87936a9440503b30ef1eaf2cce4eefb79470781f0ada2` |
| `window_bridge/user32_v1.inc` | `14a319668cd5e8856b017f9a7d54782556d461295033755f875fafadc14d20cf` |
| `window_bridge/file_api.inc` | `66c2b474dc296fd198d510252c5b52240f3c3a2b1333b5b50089443a62076b31` |
| `window_bridge/cocoa_host.mm` | `6a50c36b492869ed55849dc435b54fd928c64ac344827ab695a62d26efe019d3` |
| `window_bridge/lift.py` | `d43e6251be8893647e82d78428b36d7f624b6898f7911e08533fe76dcbfac978` |
| `switch_window_fixture_v1/switch_tile.cpp` | `6ccbe7814414503972db7de8b9b60a40ac297ffe10611ae4f995a80a1ce87577` |
| `window_outer_abi_v1/instrumentation.inc` | `60dfa9d9b012c87cc93c9fbcbbd7348e6c5b65dff03dfb67e33aa4c01937fad2` |

以上摘要冻结的是此次设计依据。正在实现的replay overlay、构建器和reader不在本表中，实际版本及通过/失败只能由其新回执绑定。
