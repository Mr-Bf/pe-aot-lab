# 有限只读跳转表 AOT 实验

本模块把两份自制 Windows x86-64 PE 函数中的真实 Clang 跳转表转换为 ARM64 Mach-O 代码，在 Apple Silicon 上用独立事务运行时执行。目标代码不需要 Rosetta。它是兼容性研究切片，尚未接入完整游戏迁移入口，也不生成可启动的 macOS App。

## 已实现的范围

- `clang-rel32-v1`：单一 unsigned `CMP/JA` 范围检查、32 位索引清高位、RIP-relative 表基址、signed rel32 加载、基址相加及 GPR 间接 JMP。表项数限定 2–32；当前实测两份输入均为 8 项。
- 驱动先输出候选闭包。`admission.py` 从原始 PE 字节独立重算受限指令、节权限、CFG、表内容、目标边界、调度入口与 flags 条件；候选 JSON 本身不构成准入。
- 通过证明后，Remill 将有限目标接入显式 LLVM `switch`，默认分支显式报错。每条指令保留 `aot_begin/aot_commit`，kind 5 跳转检查成员集且不增加调用深度。
- 运行前，`aot_bind_switch` 核对映射内整张表与证明字节相同、权限恰为只读、每项 signed rel32 与已配置目标逐项对应。失败后不可进入 guest。可信宿主必须在绑定后保持 backing 和权限稳定；本组件不防御恶意宿主或并发修改。

本地已实际完成两份 PE 的 144 组输入、O0/O3 共 288 次正常 ARM64 执行，完整 State、寄存器与内存一致；原 C 的独立 ARM64 编译版本提供返回值参考。另用原始 PE 指令与只读表共同映射的 x86 参考进程验证全部 GPR、已定义 flags 与内存；**只有该参考进程使用 Rosetta**。绑定拒绝、预算边界、无权限表读取、非法 JMP 目标及只读写事务也有实际记录。后者的写测试直接调用事务内存 helper，不表示已新增带写指令的 PE 覆盖。

这些是固定小样本正确性结果，没有游戏兼容率、性能提升或完整 Windows ABI 支持的结论。没有 DRM、反作弊、Win32、Steamworks、UI 或 GPU 执行。输入没有 imports、TLS、SEH 或重基址需求。

## 前置条件

需要原生 Apple Silicon macOS、所选 Xcode SDK、Python 3.13，以及已经由 `portable_lifter_v1` 构建并验证的 CPU provider。先按 CPU provider 文档准备公开缓存和离线构建；本模块不下载工具，不重编 LLVM 或图形依赖。

公开输入位于 `examples/switch/`：

| 文件 | 用途 |
|---|---|
| `switch8.exe`、`switch8_variant.exe` | 两份自制 PE 函数输入 |
| `supported.packet.json`、`variant.packet.json` | 真实候选解码记录；运行时会再次解码并核对 |

原 C 参考保留在 `switch_supported_fixture_v1/switch8.c` 与 `switch_variant_fixture_v1/switch8_variant.c`。构建时需要这些文件及 `memory_stage2`、`integration_stage3/bindings.py`、`portable_lifter_v1` 的纯工具/内存支持。项目原创代码与样本遵循仓库 `LICENSE`；Remill 源码与补丁涉及的 Apache-2.0 许可见 `integration_stage3/LICENSE.remill` 及 CPU provider 内原始许可。不要将外部依赖重新标成项目 MIT 许可。运行收据会保存原 C 和这两份许可的副本与摘要。

## 复现

从仓库根运行，输出目录和新 driver prefix 必须不存在。`CPU_PROVIDER` 指向已验 provider 的绝对路径；以下三个变量只是本次输出位置，可自行更换。

```sh
export CPU_PROVIDER="/absolute/path/to/cpu-provider"
export SWITCH_PREFIX="$PWD/.local/switch-driver-01"
export SWITCH_BUILD="$PWD/.evidence/switch-driver-01"
export SWITCH_RUN="$PWD/.evidence/switch-runtime-01"

python3.13 -B -m switch_aot_v1.build_driver \
  --provider "$CPU_PROVIDER" --prefix "$SWITCH_PREFIX" \
  --out "$SWITCH_BUILD" --jobs 2

python3.13 -B -m switch_aot_v1.harness \
  --build "$SWITCH_BUILD/result.json" --packets examples/switch \
  --supported-pe examples/switch/switch8.exe \
  --variant-pe examples/switch/switch8_variant.exe \
  --out "$SWITCH_RUN"
```

驱动只重编自己的 Remill 源副本与 driver，明确依赖原 CPU provider 的 LLVM、静态库和语义文件，不能将新 prefix 单独当作完整可搬移 provider。harness 在独立证明前不生成 IR，随后生成并执行 O0/O3 ARM64 动态库；这一步会实际运行受控 guest 函数，但不会启动 App。

正常结果状态为 `PASS_ARM64_O0_O3_AND_NATIVE_C_REFERENCE`，并明确 `raw_x86_oracle=false`。独立原始 x86 参考需要另行运行 `switch_aot_v1.oracle`，向其传入上述 ARM 结果及同一对 PE；应先查看该模块的 `--help`。若 Rosetta 或执行环境不允许参考进程运行，保留真实失败，不能以 C 返回值参考替代原 x86 验证。

仅检查公开输入参数与 Python 证明门禁，不构建或执行 native：

```sh
python3.13 -B -m unittest switch_aot_v1.harness_test
PE_AOT_SWITCH_INPUTS=examples/switch \
  python3.13 -B -m unittest switch_aot_v1.test_admission
```

新参数入口保留旧默认路径以兼容本地历史实验。公开复现应显式传递上面的两个 PE 参数。历史 native 收据绑定的是当时保存的源码副本；后续 CLI 参数化只做接口验证，不能把新文件摘要回填旧执行记录。失败输出不覆盖，取消后不自动重试。
