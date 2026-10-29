# PE AOT Lab

**将受限的 Windows x86-64 PE 在构建期转换为 Apple Silicon ARM64 代码，打包成 macOS App。**

这是一个以正确性与性能为目标的工程研究原型。当前已跑通自制窗口程序的原生 App 闭环；还不能转换一般 Windows／Steam 单机游戏。公开仓库包含源码、固定依赖配置、补丁和小型自产样例，完整本机实验日志与工具链缓存不在仓库中。

## 实现路线

```text
Windows x86-64 PE + 显式兼容配置
         │
         ▼
PE 校验／映像装载 → XED 控制流发现 → Remill 语义提升
         │                            │
         │                            ▼
         │                    LLVM IR → ARM64 Mach-O
         ▼                            │
受限 Windows ABI/API 运行时 ←─────────┘
         │
         ▼
D3D11 子集 → DXMT／Metal → Cocoa macOS App
```

这是一条跨 ISA 翻译路线。与 Switch ARM64 → Mac ARM64 的二进制重写相比，还必须重建 x86 指令、flags、寄存器和内存语义；不是修改 PE 文件头或重编译游戏源码。原生 App 的执行路径不使用 Rosetta。部分差分测试借助 Rosetta 执行原始 x86 字节，它不是 Windows 实机或 Wine 游戏性能基线。

## 已验证范围

| 能力 | 当前证据与边界 |
| --- | --- |
| 固定依赖获取和离线构建 | CPU、图形缓存校验与独立构建入口；一次完整 install 实际完成 139 条构建命令。CPU 使用固定 LLVM 17 预编译工具包；Remill／依赖及图形 LLVM／DXMT 另行编译。 |
| 自制 PE 到原生 App | 显式 PE/profile → 静态提升 → O0/O3 ARM64 对象 → App 打包和验证。较早样本产物已完成窗口输入、存档恢复、保存及正常退出，也验证了搬移路径。 |
| 较早完整 install-v1 产物 | 构建与独立静态复核通过；首次交互尝试因桌面操作延迟超时，尚未取得该产物的正常退出验收。不能借用旧 App 的成功替代。 |
| 有限 switch 正式 App | schema2 profile → 显式 window-rel32-v1 provider → 全根证明 → 完整 ARM64 App；真实 RIGHT 路径调用只读表并影响绘制/存档。两轮原路径/搬移 Cocoa 正常退出，790文件独立复核；32次真实 WndProc 两基址/O0/O3执行通过。单表叶函数范围，不代表一般间接跳转。 |
| 早期 switch 原 x86 对照 | 独立 scalar 切片的288次正常ARM与144次原PE字节对照保留；本轮窗口callback不是新的原x86差分。 |
| 标量／内存／ABI | 多项组件差分和拒绝测试已通过；它们各自的支持范围不同，不等于通用 Windows 运行时。 |
| 性能 | 已有局部微基准和资源记录；尚无代表性游戏性能、Wine＋Rosetta 同场景对比或整体提速结论。 |

当前窗口样例限制包括单 guest worker、显式回调入口、固定的 Win32／COM／D3D11 契约、640×360 画面及限定 shader／资源参数。未知指令、未证明的跳转、导入或运行机制会明确拒绝。

尚未支持通用 CRT/DLL 装载、TLS、SEH/unwind、多线程、一般 SIMD、JIT／自修改代码、任意着色器与图形资源、音频和 Steamworks。研究仅面向合法获取的自制／开源或单机游戏输入，不包含 DRM／反作弊绕过；仓库不分发商业游戏、Steam SDK、Apple SDK 或 D3DMetal。

## 开发入口

当前入口为 **`migration_v6`**，使用 `examples/window-switch` 的新profile。普通CPU provider先生成switch driver overlay，再与既有图形provider生成App。overlay保留对原CPU provider绝对路径的依赖，不能单独搬移，也不是完整provider；生成后的App已另验搬移运行。旧install-v1仍只构建原profile。下一项是把v6接入完整离线install，详见剩余清单。

- [正式窗口 switch 开发与复现](window_switch_v1/README.md)及[实际验收](docs/WINDOW_SWITCH_V1.md)。
- [真实运行监督与独立复核](migration_run_v3/README.md)：单进程、OS事件与同档恢复分别记录。
- [早期 scalar switch 复现入口](switch_aot_v1/README.md)：单表叶函数实验，独立于正式窗口构建链。
- [早期研究](docs/RESEARCH.md)与[反证审查](docs/REVIEW.md)：保留研究时点，不作为当前实现能力声明。
- [剩余任务与验收门槛](REMAINING.md)：按能力与证据推进，不按周数或估算百分比表示完成度。
- [第三方许可与修改归属](THIRD_PARTY.md)：根 MIT 许可不覆盖第三方衍生代码的单独许可。
- `migration_cache_v2`、`portable_graphics_v2`：准备固定版本依赖缓存。
- `migration_install_v1`：从两份缓存离线构建 CPU／图形后端与 App；不会自动启动 App。
- `migration_v5`：使用已有显式 CPU／图形 provider 的 analyze/build/verify。
- `examples/integer-tile`：小型自制 PE、配置与源码来源。现有历史样例生成脚本仍有旧工具路径依赖，不能声称从 C++ 到该 PE 已完全独立一键复现。

## 从样例开始

构建要求 Apple Silicon macOS、Python 3.13 或更高版本，以及已选择且包含 Metal 工具的 Xcode／SDK。已验环境为 M2、macOS 26.3.1、Xcode 16.2／SDK 15.2；尚未做另一台干净机器的完整复现。大依赖构建需要数 GiB 临时磁盘空间。以下从仓库根目录执行；所有输出目录均使用尚不存在的新路径。

先分析本轮窗口switch样例；完整构建参数见上述正式开发入口：

```sh
python3.13 -B -m migration_v6 analyze examples/window-switch/switch_tile.exe \
  --profile examples/window-switch/profile.json
```

以下是普通provider和旧profile的基础安装入口：

```sh
python3.13 -m migration_install_v1 --help
python3.13 -m migration_v5 analyze examples/integer-tile/integer_tile.exe \
  --profile examples/integer-tile/profile.json
```

联网准备依赖，然后离线安装：

```sh
python3.13 -m migration_cache_v2 prepare-cpu \
  --cache "$PWD/.local/cpu-cache" --out "$PWD/.local/cpu-fetch"
python3.13 -m portable_graphics_v2 prepare \
  --cache "$PWD/.local/graphics-cache" --out "$PWD/.local/graphics-fetch"

python3.13 -m migration_install_v1 plan \
  --cpu-cache "$PWD/.local/cpu-cache" \
  --graphics-cache "$PWD/.local/graphics-cache" \
  --pe "$PWD/examples/integer-tile/integer_tile.exe" \
  --profile "$PWD/examples/integer-tile/profile.json" \
  --identifier org.peaotlab.example.v1 \
  --work-root "$PWD/.local/install-work" --out "$PWD/.local/install" --jobs 2
```

预检通过后，以同样参数把 `plan` 改为 `install` 开始构建；预检不会替你完成 native 构建或启动验证。使用 `migration_v5 verify <产物目录>` 复核产物，实际运行、交互与性能需要分别验收。

当前源码发行的无工具链检查与完整 native 验收是不同层级。许多历史实验测试依赖私有保留的原始构建证据，不能在刚 clone 后运行全仓 `unittest discover` 并把缺文件当成兼容性失败。以本仓库明确列出的复现命令和前提为准。

## 许可

项目原创部分采用 [MIT](LICENSE)。Remill 衍生部分保留 Apache-2.0 及其声明，当前固定 DXMT 提交采用 LGPL-2.1-or-later；其他依赖以对应固定版本许可为准。此发布为研究源码发行，不提供第三方工具链或预构建 App 发行包。后续二进制分发仍需完成各依赖相应的源码、修改归属与重链接等义务。
