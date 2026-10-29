# S3 事务型真实 Remill lifter

本目录的 `lift.py` 提供 `lift_pe(pe_path, out_dir) -> manifest`。输入必须满足受限 PE image loader 和闭合标量指令 profile。输出包括保持完整 State 的 `arm64.o`、`arm64-o0.o`、`arm64.ll`、原始 `lifted.ll`、首次优化前 IR、逐指令 XED manifest 与布局验证证据。入口符号固定为 `aot_entry`，ABI 为 `void *aot_entry(void *state, uint64_t runtime_entry_pc, void *ctx)`。

这与 stage2 的叶函数实验不同：不使用 `--signature`、不创建 null token、没有 host 指针身份映射或 dummy return slot。它依赖单独链接的 `runtime.c`，执行结果由整体集成测试验证；lifter manifest 的 PASS 只表示批准和生成通过。

## 事务边界

`transactions.patch` 在 TraceLifter 的每条 `LiftIntoBlock` 前调用：

```c
uint32_t aot_begin(void *state, uint64_t current_runtime_pc, void *ctx);
```

指令语义后、CFG 控制转移前调用：

```c
uint32_t aot_commit(void *state, uint64_t next_runtime_pc, void *ctx);
```

两个 PC 都读取 Remill 的运行时 NEXT_PC，而非把构建期绝对地址写入运行时。hook 非零即从 trace 返回 ctx。直接 CALL 的子 trace 返回后还调用 `aot_should_exit(ctx)`；非零立即返回，父 trace 不进入下一条指令，不覆盖子调用错误。

边界在**第一次 OptimizeModule 之前**插入。hook 和 memory helper 保持读写副作用；C++补丁同时清理 helper 声明与 call-site 的错误 pure/readonly/alias 属性。live State、Context 及其 backing/snapshot 必须互不重叠；保留的 raw trace noalias 参数依赖此运行时契约。

## 准入与拒绝

XED 与 Remill 同时解码并核对长度，从入口递归发现直接分支、CALL 目标及 fallthrough；拒绝重叠指令、范围外目标和不可解码路径。原 CLI 把非入口 trace 当外部声明的行为已修改，实际提升全部可达 direct callee，允许有预算/深度限制的递归。

当前标量集合包括 MOV/MOVZX/MOVSX/MOVSXD、LEA、ADD/SUB/XOR/AND/OR/TEST/CMP、立即数 ROL、INC/DEC、NOP、PUSH/POP、直接 CALL/JMP、普通 Jcc 和无 immediate 的 near RET。这个清单还受具体 operand/category 约束，不能仅凭同名 iclass 放行所有形式。

明确拒绝：

- LOCK、REP、segment override、address-size override；segment/control/debug/vector/x87 等非 GPR 架构寄存器。XED 的 STACKPUSH/STACKPOP 栈效果伪寄存器是明确例外。
- 内存 RMW、DIV/IDIV、浮点/SIMD/原子、间接 CALL/JMP、syscall、未知 control/helper。
- CALL-to-next 获取 PC 特例、RET immediate 栈清理、变量 rotate count、闭合 profile 不支持的整宽 rotate count。
- 代码重定位、绝对 memory addressing、指向当前映像范围的绝对 64-bit immediate；数据节 DIR64 可以交给 image loader。
- 未定义 flags 用于分支。静态数据流在 CALL 入口及返回边界保守清空 flags 已定义集合；不声称完整跨函数 flags 分析。

每条 manifest 包含实际字节、RVA、长度、XED iclass/category、Remill semantics 名、flags 读写/未定义集合及 `kind`：NORMAL=0、CALL=1、RET=2。CALL 的 target_rva 供 runtime 返回栈验证使用。生成 IR 中不允许 guest `inttoptr`、x86 intrinsic、fp80 执行或未知 ABI。

## 布局验证

每次提升对四种 triple 实际编译 Remill State 头：x86_64-none-elf、aarch64-none-elf、x86_64-pc-windows-msvc、arm64-apple-macos11。检查 sizeof/align、全部 17 个 GPR/RIP 和 7 个 flags，共 26 项。

额外从**本次 Remill 输出的真实 LLVM State 类型**构造 GEP 布局探针，retarget 后编译为 ARM64 并执行，检查 sizeof 与全部所用字段的 25 项值。避免只比较独立 C++ 编译结果，却忽视原始 LLVM 类型在改变 DataLayout 后的布局差异。当前两组检查均通过：State 3504 bytes、C++ align 16。

## 构建与证据

从仓库根目录：

```sh
/opt/homebrew/bin/python3.13 integration_stage3/build_lifter.py
/opt/homebrew/bin/python3.13 integration_stage3/lift.py INPUT.exe OUTPUT_DIR
/opt/homebrew/bin/python3.13 integration_stage3/lifter_checks.py
```

`build_lifter.py` 使用独立 `work/integration-stage3/` 源码及 `build/integration-stage3/lifter/` 构建目录，只读复用 stage2 工具链。失败构建先将状态设为 RUNNING，不能沿用旧 PASS。提升入口核对 lifter、semantics、补丁哈希；工具链错误使用 RuntimeError，只有明确 profile 拒绝使用 TranslationError，不让负测吞掉链接或构建错误。

本轮 `build/integration-stage3/lifter-checks/results.json` 的 22 项拒绝用例全部通过。包含一项自审发现并修复的问题：MOV iclass 同时包含 segment 寄存器操作，单靠 mnemonic 白名单不足，因此新增寄存器类别约束。原先接受的 decode-only 证据保存在 `build/integration-stage3/mov_ds-decoded.json` / `mov_from_ds-decoded.json`；未执行这些指令。收紧后对 XED STACKPUSH 过严的失败日志也保留为 `lifter/failed-stackpush-profile.log`，现已明确处理。

整体 guest memory、变基址、CALL/RET 与故障语义的结论，应以同目录其他集成测试的最终证据为准。此事务版本刻意保留 State 快照和逐指令边界，目标是可验证基线，尚未进行高性能路径优化。
