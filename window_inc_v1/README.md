# 原始 save/load PE 所需的有限指令扩展

这是独立于已冻结 `window_bridge` 的新工具/profile。它解决自然 O2 Windows PE 在 `INC DWORD PTR [RAX]` 上的真实拒绝，不改写游戏源码、不替换 PE 字节、不重编业务为 ARM 源码，也不修改冻结 runtime。

本目录目前覆盖指令准入、真实 Remill 提升及无窗口的标量验证；**不代表完整 save/load、窗口或 GPU 验收通过**。

## 输入与变更

输入 `build/window-bridge/prepared-save-load-v1/integer-tile.exe` SHA256：
`0e1bcf809cb2aa56f23526f3bbd80e9ee233488a1a5b215f1f810b4bb67aa976`。

最初旧 profile 拒绝 `ff00`（RVA `0x11b3`），编译器把两个计数地址经 LEA/选择放入 RAX 后执行同一条内存递增。新增支持后，继续真实控制流遍历又拒绝 `40 0f 95 c6`（RVA `0x1a1e`，SETNZ SIL）；首个新工具的拒绝日志保存在 `build/window-inc-v1/save-load-first-main`。没有为了绕过这些拒绝修改 PE。

新 patch 依次应用在固定 Remill SHA `56918a8c2554088e93389e97d292f4035286506c`、固定原 archive、六份冻结 window patches 之后：

- 保持原 `INC m32 [RIP+disp32]`；显式 `--aot_inc_base32` 才准入 `INC m32 [GPR64+0]`。只含一个内存操作数、无 index、位宽 32、排除 RSP。RBP/R13 的编码零位移及 R12 的无 index SIB 可以接受；非零位移、index、16/64/8 位、LOCK/REP/segment/address-size override、DEC/ADD 等其他 RMW 继续拒绝。
- 只新增 `SETNZ SIL`，与原 CL/DL 一起使用同一真实 Remill SETNZ 语义。CFG 门禁要求 ZF 已定义；不扩大到任意 SETcc。
- 每条指令多记录 `rmw_base_reg/rmw_displacement/rmw_width`。Python 二次核对 INC memory kind、位宽、base/位移以及 CF 不能成为新定义或未定义；非 RMW 必须是空元数据。实际 flags 定义传播仍走原 CFG 门禁。
- 新 loader 仅在原 window import 集合上增加 `kernel32.dll/ReadFile` → signature 6；这只是地址注册标签，真实受限文件运行时没有在这里改动或重复实现。

`BASELINE.json` 记录旧工具、旧 Python 和六个 patch 的来源哈希；`build/window-inc-v1/frozen-source-comparison.json` 记录其当前仍逐字节相同。新工具源码树在 `work/window-inc-v1`，构建在 `build/window-inc-v1/lifter`。原工具/产物保留。生成代码仍适用项目现有 Remill Apache-2.0 LICENSE/NOTICE；工具链不是无需依赖许可的 App 运行产物。

## 已完成的真实构建

`build/window-inc-v1/save-load-roots-r2/roots.json`：原 PE main 568 条、WndProc 75 条，共 643 条；主根和回调根分别生成原始 IR、ARM64 IR、O3/O0 对象并通过实际 LLVM verifier、四 triple State 布局及导出符号门禁。ReadFile 的 IAT RVA 为 `0x2728`，signature 6。两个新增形状之外没有继续放宽其他指令；常量 MOVABS `0x131574f43` 没有被当成 guest 地址指针。

这仍是 `BUILD_STATIC_NOT_EXECUTED`。生成时执行的 State 布局探针是编译器布局检查，不算原 PE 窗口执行。

## 有限标量实验及证据口径

四种实际寻址编码 RAX、RBP、R12、R15，各 64 组；SETNZ SIL 另 64 组，共 **320 个唯一输入**。每组原始 x86 PE 字节在独立 x86-64 测试进程执行，真实 Remill ARM64 在 O3/O0 分别执行，共 640 次正常 ARM 执行。RAX/RBP/R12/R15 覆盖普通 ModRM、编码零位移、SIB 和 REX；其他 11 个准入 base 目前只有 decoder 静态覆盖，不能声称都做过独立运行测试。

输入保留随机高位 GPR、递增溢出/零/符号/辅助进位/奇偶边界，CF=0/1 每形状各 32 次。INC 之前的真实 CMP 定义 CF；实际 raw x86、ARM 和独立整数模型核对全部六个定义算术 flags，确保 INC 保留 CF。SETNZ 真假与 RSI 高 56 位保留分别验证。全部 GPR、RET 后 RIP/RSP、完整 8192-byte 数据与 raw 对照；3504-byte State 只在 ARM O3/O0 和故障前缀之间完整比较，**不称 raw x86 与 Remill 私有 State 全字节相等**。

raw oracle 的 base GPR 被明确归一：输入 logical guest VA 对应测试 image offset `0x2ffe`，进入原字节前改为映射的真实 host 地址；退出时必须仍等于该真实地址，再还原为 logical VA。RSP/RET 也按测试捕获协议归一。地址计算本身没有被替换成业务算法；INC 原字节照常读写两个相邻数据页。

每种 INC × 两种优化另执行 5 个边界（共 40 次）：实际预算前缀、跨不同 backing 的成功访问、第二页只读、第二页不可读、第二映射缺失。后三种都必须完整恢复到预算前缀 State/PC，保留此前已经提交的 MOV 哨兵写入，不允许半个 INC 写入；精确 fault access/width/address/PC 均核对。故障模型是本项目显式 GuestMemory 契约，未宣称 Windows 原生硬件异常/SEH 对照。

静态准入普通及 Python `-O`：各 17 准入、22 拒绝、10 元数据拒绝；包括关闭开关拒绝新 INC、INC 不会定义未知 CF、SETNZ 拒绝未知 ZF。这些是门禁检查，不计 guest 执行。

初次 `scalars` 被环境禁止读取 `sysctl.proc_translated`，oracle 在运行 PE 前退出，ARM 0 次；保留 `first-failure.json`。`scalars-r2` 实际 320/640/40 全通过，但独立复审发现只读 verifier 未逐项核对 `boundaries.json`。已保留该轮和当时测试源码快照 `scalars-r2-source`，新 verifier 增加完整边界集合/精确 fault/前缀状态与 split-RW 实际结果绑定后，使用新目录 `scalars-r3` 重放。重复运行不累计成更多唯一输入。

Rosetta 只用于这个 x86 对照测试进程；实际被检对象、事务运行时和测试宿主是 ARM64。这不意味着转译后的 guest 运行需要 Rosetta，也不证明当前性能有优势。

## 复现与后续

从仓库根目录：

```sh
/opt/homebrew/bin/python3.13 -m window_inc_v1.build_lifter --jobs 2
/opt/homebrew/bin/python3.13 -m window_inc_v1.test_admission --verify-only
/opt/homebrew/bin/python3.13 -O -m window_inc_v1.test_admission \
  --out build/window-inc-v1/admission-optimized --verify-only
/opt/homebrew/bin/python3.13 -m window_inc_v1.test_scalars --verify-only
/opt/homebrew/bin/python3.13 -O -m window_inc_v1.test_scalars --verify-only
# 真正重新执行必须使用新目录，保留旧证据。
/opt/homebrew/bin/python3.13 -m window_inc_v1.test_scalars \
  --out build/window-inc-v1/scalars-new-run
```

对当前 save/load PE 可用 `window_inc_v1.lift.lift_roots(pe,out,[0x1000])`；API 与原版本相同。完整前端必须显式选择此新 profile，并重新绑定所有源、PE、对象、metadata 和运行库身份，不能沿用旧 manifest 的身份声明。

下一步是独立前端接入新 roots/ReadFile 注册，在相同 PE 上验证缺文件→保存→下一进程恢复与坏存档错误分支，并继续像素/窗口/预算清理验收。这里没有运行这些流程，也没有通用游戏、任意 RMW、原子指令或多线程支持声明。
