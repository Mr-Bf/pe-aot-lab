# 固定原 PE 的控制流和指令需求

Python 3.13+；构建解码器需要 Apple Silicon macOS、Clang/SDK，以及已安装的 XED `include/xed` 和 `lib/libxed.a`。只编一个 ARM64 解码辅助库，复用已有 XED，不重建 LLVM/Remill。该辅助库读取 x86 字节作为数据，没有执行 PE 或生成目标游戏 ARM64 代码。

从仓库根目录运行，目录及输出文件必须是新路径：

```sh
python3.13 -B -m real_pe_cfg_v1 build-decoder \
  --xed-prefix /absolute/path/to/installed-xed \
  --out /absolute/path/to/new-decoder
mkdir -p /tmp/new-pe-cfg
python3.13 -B -m real_pe_cfg_v1 analyze /absolute/path/to/game.exe \
  --decoder-receipt /absolute/path/to/new-decoder/decoder.json \
  --json-out /tmp/new-pe-cfg/graph.json \
  --markdown-out /tmp/new-pe-cfg/graph.md
```

`analyze` 产出有用的部分图时返回 **2**，状态为 `PARTIAL_STATIC_GRAPH_NOT_EXECUTED`。它不是成功迁移准入；捕获的输入/工具错误同为2，但 stderr 给出 `INPUT_OR_TOOL_REJECTED`，不会伪造图；参数语法错误则由argparse输出usage。`build-decoder` 返回0只表示辅助库构建成功。CLI默认最多100,000条指令，可用 `--max-instructions` 设更小限额，超出时保留未分析前沿。

从原 PE 的入口和声明的 TLS callbacks 递归发现；保留 TLS 数组次序，各根独立标识。普通条件分支两条边都是候选；CALL后继单独标 `may_return_continuation`，不证明callee返回。间接CALL/JMP保留未知目标，RET不猜调用栈，异常handler边未枚举。`.pdata` 的 RUNTIME_FUNCTION只保存候选记录，**不自动用作根**。代码区只读取 `min(VirtualSize, SizeOfRawData)` 内的可执行文件字节，原始对齐padding不自动解码。

JSON记录原始字节/文件偏移、XED类别、前缀、内存/寄存器操作数、边、基本块、逐根语法可达来源、冲突与未闭合项。名称/类别不等于生产lifter支持，flags、ABI、调用副作用和路径可行性仍未验证。IAT关联只表示控制指令静态引用某个槽，不证明槽运行时的值或系统实际提供该函数；FS/GS和32位地址不能错误绑定为普通64位IAT。

XED使用固定 `XED_CHIP_ALL` 识别模式以保存CET/MPX等特征依赖的opcode，不推断guest CPUID、动态启用状态或这些扩展可运行。CLI/STI、未建模system/事务/特殊控制操作形成前沿。`normal`只表示当前识别策略下的名义顺序后继，不说明不会fault，也不提供指令执行语义。

根上限64，来源对上限500,000；原始声明保留，超过限额明确标 `analysis_seeded=false` 或 `root_origin_enumeration_complete=false`。成功解码和此前失败的目标都参与字节重叠检查，不用后发现的指令静默覆盖旧目标。

```sh
export PE_AOT_CFG_DECODER_RECEIPT=/absolute/path/to/new-decoder/decoder.json
python3.13 -B -m unittest real_pe_cfg_v1.test_graph real_pe_cfg_v1.test_decoder real_pe_cfg_v1.test_cli -v
python3.13 -B -O -m unittest real_pe_cfg_v1.test_graph real_pe_cfg_v1.test_decoder real_pe_cfg_v1.test_cli -v
```

未设置receipt时，真实decoder测试会明确skip；不能将这种运行称为47项全量测试（含真实decoder、无skip）通过。fake-decoder算法测试不是x86指令oracle。receipt固定适配器、XED库/头文件、编译器、SDK信息及产物身份；它是本机受信构建记录，不能用来安全加载来源不明的第三方dylib。实际源码与许可来源见[本批报告](../docs/REAL_PE_CFG_V1.md)，图合同见[独立审查设计](../docs/REAL_PE_CFG_CONTRACT_V1.md)。
