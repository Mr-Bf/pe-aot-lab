# 真实 PE 的 CFG 库存合同 v1

日期：2026-11-03。状态：`SOURCE_REVIEWED_DESIGN_NOT_CFG_OR_AOT_ACCEPTANCE`。

目标是为固定 Chocolate Doom Windows PE 建立可追溯的指令和控制流**需求库存**，用于选择下一处实现缺口。它不运行目标，不替代 Windows loader，不证明完整可达性、函数发现或 AOT 兼容。此合同只读审查了现有 lifting 前端、已冻结 PE 库存，并用本机 objdump 静态核对少量原始入口字节；尚未产生或验收完整 CFG。

## 1. 固定输入与根

主文件为 `chocolate-doom.exe`，SHA256 `15e81c194df270fbd71450222e71846247926fabfb889e72e7d855903454d752`，preferred base `0x140000000`。首批根为 PE entry RVA `0x13e0`，以及文件 TLS 表中的两个 callback：按表顺序为 `0x1570`、`0x1550`。输出保留每个根的来源、原始目录/槽偏移及 VA/RVA，不能只留下排序后的地址列表而丢失 TLS 声明顺序。

这些是独立的静态根，不在它们之间合成“Windows已执行TLS→entry”的边。DLL初始化、TLS通知原因、CRT构造器、`.CRT`指针、导出函数、运行时注册callback和异常handler都可能增加实际入口；本片未闭合这些根。`.pdata`的RUNTIME_FUNCTION范围只作为候选元数据，既不是全部函数清单，也不是“每个begin均由entry可达”的证据。若另作候选根扫描，必须与entry/TLS图分开统计。

每次从同一份有界原PE字节重新解析metadata并绑定摘要；不信任外来JSON中的roots、instructions或import名。读取与输出沿用新文件、输入树外、路径/大小/身份检查。decoder及其库、构建工具、源码、调用参数和原始输出也要绑定身份。图形、游戏数据、Steam均不是本静态阶段前置。

## 2. 图的准确含义

用有界worklist从显式根展开，记录原字节、RVA、长度、decoder类别、操作数摘要和每条边的来源。图表示**语法上可能到达的路径**；默认不做路径可行性、常量传播或非返回函数证明。不得把 `discovered`、`decoded`、`may_reachable`写成“实际执行”或“必定可达”。

| 指令类别 | 图中应记录 |
|---|---|
| 已识别的普通指令 | 后继 `sequential`，只表示指令正常完成后的控制流；异常边仍未知 |
| direct JMP | 目标边；没有普通fallthrough |
| 条件分支 | taken与not-taken两边；未证明条件结果时不得剪掉其中一边 |
| direct CALL | direct-callee边，加独立的 `may_return_continuation` 指向下一指令；不能声称callee已返回 |
| indirect CALL | 未解析目标边，加 `may_return_continuation`；即使寄存器看似来自IAT，也不能无数据流证明补造目标 |
| indirect JMP | 未解析目标边，无普通fallthrough；IAT尾跳也不合成“调用后继续” |
| RET | 终止当前展开路径，记录动态return目标；不连接到所有CALL后继，也不证明整个函数一定返回 |
| trap/system/未知控制类别 | 显式终止并记语义缺口；不能把未分类指令默认当普通fallthrough |

callee可能不返回；CALL后的字节也可能是数据。`may_return_continuation`是有意识的保守假设，会带入不可行路径。API名叫ExitProcess、abort等本身不足以删除后继，除非另有版本化语义证明。未知间接边、unresolved return和未枚举异常边必须在报告中保留；queue空不等于完整CFG。不得从“未发现动态代码”推出没有JIT。

在多个可执行section上可以做库存，但每条指令必须完整落在唯一已声明、file-backed、可执行范围内，不跨section缝隙、虚拟零填充或权限边界拼接。库存范围比现有v7单section/32KiB门禁宽，不代表已经放宽生产准入。越界/无可执行存储的目标记录为未解析终点，不能填零继续解码。

维护整个扫描的逐字节instruction-owner。root/branch进入一条已解码指令的内部，或两个新解码区间部分交叠，均记冲突并停止相应展开；不能覆盖先前记录，也不能因处理顺序不同隐藏重叠。未知/非法字节不做逐字节跳过再同步。若达到instruction、edge、queue、byte或输出上限，保留未处理frontier和 `truncated=true`；不得输出complete。

## 3. IAT关联与前端能力不能混为一谈

仅对精确的64bit RIP-relative memory CALL/JMP，在确认没有改变寻址含义的前缀/segment、计算了真实next-PC+signed displacement、且有效地址等于已解析IAT槽时，可记录 `iat_metadata_association`。这只是文件声明的DLL/name/ordinal关联，不证明Windows已绑定、符号存在、ABI已实现或调用参数正确。delay-import和未解析描述符保留其原状态；普通IAT与delay IAT不得无条件混用。

`CALL RAX`、从普通内存读出的pointer、jump table和callback表必须保留未知目标，除非实现了独立的原字节/数据流证明。不能把原IAT槽里指向hint/name结构的值误当可执行函数地址，也不能把本项目synthetic thunk值写回原PE后声称盘点的是发布包。

现有v7实际入口为 [`window_switch_v1/lift.py`](../window_switch_v1/lift.py):`Compiler.roots`，依次执行strict loader、[`portable_app_v1/lift.py`](../portable_app_v1/lift.py):`executable_bytes`、XED/Remill decode-only、原字节switch/root证明、lifting及ARM retarget。主目标的392,224B file-backed executable范围已经超过32,768B门禁，且当前loader更早拒绝其resource目录；因此本CFG工具不能称“v7已成功decode目标”。

当前 `AotPreflight` 的最终class集合为40项：MOV/MOVZX/MOVSX/MOVSXD/LEA/ADD/SUB/XOR/AND/OR/TEST/CMP/ROL/INC/DEC/NOP/PUSH/POP/CALL_NEAR/RET_NEAR/SETZ/SETNZ/CMOVNB，以及JMP与16种Jcc。来源是 `window_bridge/aot-profile-v1.patch` 加import/vtable/window、INC及switch补丁链；必须核验最终组合，不只读最早patch。

class命中之后还有独立门禁：LOCK/REP、FS/GS和address-size前缀拒绝；只有三种固定CS-prefixed NOP例外；GPR/IP/FLAGS之外寄存器拒绝；RET imm、absolute memory和超出1/2/4/8B的普通memory operand拒绝；memory RMW只准入有限INC m32形状。SETZ、SETNZ、CMOVNB、AND8、TEST16、ROL有更窄操作数/计数限制。IAT-reg调用要求运行时精确thunk绑定，COM调用要求精确接口/槽/对象，普通indirect JMP仅允许单个已证明的switch形状。flags definedness、helper ABI/effect及 `x86_fp80`/`llvm.x86.*`/`inttoptr` 的retarget拒绝仍在后面。

建议每条库存指令使用以下分层字段，禁止 `supported=true` 或“支持率”：

```json
{
  "decode_status": "decoded",
  "decoder_iclass": "MOV",
  "v7_class_gate": "class_name_in_filter_only",
  "v7_operand_prefix_gate": "not_evaluated",
  "v7_flags_cfg_proof": "not_evaluated",
  "v7_runtime_target_binding": "not_evaluated",
  "v7_lifting_attempted": false,
  "guest_executed": false
}
```

若decoder本身是XED，可直接对照其iclass；若采用另一decoder，别名/前缀/伪指令需显式映射和原字节复核，否则记 `class_mapping_unknown`。class不在集合是当前class门禁的潜在阻断，class在集合仅表示尚未在该层排除；统计名称分布和具体缺口PC，不用总byte、instruction或class比例估算迁移完成度。

## 4. 真实入口的短路径检查点

以下是本机静态objdump和原PE字节提供的检查点，不是运行轨迹，也不是最终XED CFG验收：

| 位置 | 原字节或关系 | 需要保留的结论 |
|---|---|---|
| entry CALL RVA `0x13f1` | `e8 1a fc ff ff` → RVA `0x1010`；下一指令 `0x13f6` | direct边与may-return后继分开 |
| RVA `0x1025` | `65 67 48 8b 00`，GS + address-size override MOV | MOV名称虽在class集合，当前prefix契约明确不接纳；不能报告“MOV已支持” |
| RVA `0x1052` | `f0 48 0f b1 33`，LOCK CMPXCHG | LOCK语义与CMPXCHG均超出当前合同；Apple objdump把LOCK单独显示一行，不能按文本行当指令边界 |
| TLS root `0x1550` | 条件边经 `0x1560` direct JMP至 `0x2010` | 根来源是TLS表，不是entry已执行它 |
| TLS root `0x1570` | 一条条件路径经 `0x15e6` direct JMP至 `0x2010` | 不假设TLS reason固定，未实现loader通知语义 |
| RVA `0x15c8` | `ff d0`，CALL RAX | 记录未知目标与may-return；不能自动称IAT调用 |

`0x15c8`之前两个LEA分别把RBX、RSI设为同一个 `base+0xbd7a8`，随后条件比较会影响该路径。首批若没有常量/路径证明，仍可以保留语法展开，但必须标注未证明实际可达；不能写“TLS实际调用了未知函数”。同样，线性窗口在TLS例程RET后显示的SIMD字节不自动属于该根的图，只有真实静态边发现后才能计入对应根的需求。

短窗口解码不是完整函数识别。输出不得根据被strip的文件和熟悉的启动形状，未经符号/源码映射证明就命名为某个CRT函数或认定某段业务逻辑。

## 5. 独立复审与验收

最小反例应针对真实风险：direct CALL与may-return区别；unknown indirect CALL/JMP不同后继；RET停止；条件跳转进入指令内部及反向处理顺序的重叠；LOCK/GS/addr-size仍按单条真实XED指令边界；RIP-IAT与addr-size/segment变体不可误关联；非法/截断/跨section指令；空或零长度`.pdata`不变成可信函数根；budget达到后的frontier不得丢失。合成字节只验证工具，不计作目标native运行。

对固定目标，分别核对entry/TLS roots、首条direct CALL的相对位移、代表性完整指令字节与长度、IAT槽计算和未知边。正常与Python `-O`结果要一致；核对实际源/decoder身份以及输入未变。可用独立decoder辅助，但其文本行、别名或skip-padding策略不能成为图定义。差异必须保留并解释，不能用删行获得一致。

报告给出每根 discovered instructions/blocks、边种类、未知目标、decode失败、重叠和frontier，以及明确的 `exception_edges_enumerated=false`、`path_feasibility_proved=false`、`complete_cfg=false`、`aot_builds=0`、`guest_executions=0`。命中一个重要启动缺口即可驱动下一开发批次；不要求为增加计数扫描全部DLL或把所有`.pdata`范围强行解码。下一步应选择具体启动/ABI合同并实施，不把库存规模当性能或迁移成功。
