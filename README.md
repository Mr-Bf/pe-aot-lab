# PE AOT Lab

**将受限的 Windows x86-64 PE 在构建期转换为 Apple Silicon ARM64 代码，打包成 macOS App。**

这是一个以正确性与性能为目标的工程研究原型。当前已跑通自制窗口程序的原生 App 闭环；还不能转换一般 Windows／Steam 单机游戏。公开仓库包含源码、固定依赖配置、补丁和小型自产样例，完整本机实验日志与工具链缓存不在仓库中。

**2026-11-02：指令查找优化完成受控成对实测。** RAW时钟、64份完整正常输出、1456对预算前缀和约315万次测量阶段回调通过；16场景的配对中位比值对应7.1%–8.1%耗时下降，191/192组候选更快。960条原始记录独立复核，慢例全部保留；下一步验证无实验选择器的单策略产物。正式运行时尚未改动，不代表App/游戏提速。见 [本轮报告](docs/WINDOW_CALLBACK_PAIR_V1.md)；[上一批异常](docs/WINDOW_CALLBACK_BENCH_V1.md)原样保留。本轮追加11个模块文件与1份报告，公开源码共527文件。

**已验构建基线：** 公开提交 `99a271d` 的499文件从本地Git archive导出后，使用既有固定缓存新建全部provider和App，144条被接受命令和两轮Cocoa存取/搬移通过；见 [独立目录复现](docs/PUBLIC_REPRODUCTION_V1.md)。后续doctor与本轮基准单独验收，不把新增源码算成499文件整链重建证据，也不等同于网络clone、冷获取、另一台机器或二进制逐字节可重复构建。

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
| 固定依赖获取和离线构建 | CPU、图形缓存校验与独立构建入口；公开 `99a271d` 独立目录完整install接受144条命令。CPU使用固定LLVM17预编译工具包；Remill/XED等依赖及图形LLVM15/DXMT实际重新编译。较早install-v1的139条记录另保留。 |
| 自制 PE 到原生 App | 显式 PE/profile → 静态提升 → O0/O3 ARM64 对象 → App 打包和验证。较早样本产物已完成窗口输入、存档恢复、保存及正常退出，也验证了搬移路径。 |
| 公开源码独立目录复现 | 同机、本地archive、既有固定缓存；五阶段完整构建，新CPU/switch/graphics/App均未复用旧安装。正式reader实读5459文件，另审1700文件；新callback32次，新App原路径/搬移两轮正常，790文件运行复核。首次超时及额外实例清理单独保留。 |
| v6完整离线安装与恢复 | 从固定缓存实际完成CPU41、switch5、graphics29、App69条被接受命令；图形SIGTERM后保留失败，复用重验的CPU/switch并在新目录重建。5722文件独立读验；新App原路径/搬移两轮正常，32次callback两基址/O0/O3通过。 |
| v6安装前诊断 | 新doctor以11组PASS/FAIL/SKIPPED汇总前置条件，全部通过退出0，否则退出2；不创建work-root/out，不启动builder/App。14项实现测试及14项独立反例各普通/-O通过；它不是构建或源码闭包证明。 |
| 较早完整 install-v1 产物 | 构建与独立静态复核通过；首次交互尝试因桌面操作延迟超时，尚未取得该产物的正常退出验收。不能借用旧 App 的成功替代。 |
| 有限 switch 正式 App | schema2 profile → 显式 window-rel32-v1 provider → 全根证明 → 完整 ARM64 App；真实 RIGHT 路径调用只读表并影响绘制/存档。两轮原路径/搬移 Cocoa 正常退出，790文件独立复核；32次真实 WndProc 两基址/O0/O3执行通过。单表叶函数范围，不代表一般间接跳转。 |
| 早期 switch 原 x86 对照 | 独立 scalar 切片的288次正常ARM与144次原PE字节对照保留；本轮窗口callback不是新的原x86差分。 |
| 标量／内存／ABI | 多项组件差分和拒绝测试已通过；它们各自的支持范围不同，不等于通用 Windows 运行时。 |
| 性能 | 已有局部微基准和资源记录；尚无代表性游戏性能、Wine＋Rosetta 同场景对比或整体提速结论。 |

当前窗口样例限制包括单 guest worker、显式回调入口、固定的 Win32／COM／D3D11 契约、640×360 画面及限定 shader／资源参数。未知指令、未证明的跳转、导入或运行机制会明确拒绝。

尚未支持通用 CRT/DLL 装载、TLS、SEH/unwind、多线程、一般 SIMD、JIT／自修改代码、任意着色器与图形资源、音频和 Steamworks。研究仅面向合法获取的自制／开源或单机游戏输入，不包含 DRM／反作弊绕过；仓库不分发商业游戏、Steam SDK、Apple SDK 或 D3DMetal。

## 开发入口

当前完整入口为 **`migration_install_v2 plan/install/resume`**，从固定缓存构建CPU base、switch overlay、图形和v6 App。公开 `99a271d` 已完成[同机独立目录整链构建与新产品运行](docs/PUBLIC_REPRODUCTION_V1.md)；较早图形受控中断、重验复用与新attempt恢复见 [安装入口](migration_install_v2/README.md)及[恢复验收](docs/MIGRATION_INSTALL_V2.md)。新增 [doctor](migration_doctor_v1/README.md)只用于分项前置诊断。

低层已有provider构建入口为 **`migration_v6`**，使用 `examples/window-switch` 的新profile。普通CPU provider先生成switch driver overlay，再与既有图形provider生成App。overlay保留对原CPU provider绝对路径的依赖，不能单独搬移，也不是完整provider；生成后的App已另验搬移运行。旧install-v1仍只构建原profile。下一项固定CPU/ABI热点工作负载，测量实际命中与成本，再在差分门禁下优化；干净机器和性能仍另设验收，详见剩余清单。

- [正式窗口 switch 开发与复现](window_switch_v1/README.md)及[实际验收](docs/WINDOW_SWITCH_V1.md)。
- [真实运行监督与独立复核](migration_run_v3/README.md)：单进程、OS事件与同档恢复分别记录。
- [v6安装前诊断](migration_doctor_v1/README.md)及[诊断验收](docs/MIGRATION_DOCTOR_V1.md)：11组只读前置观测，不代替安装门禁。
- [早期 scalar switch 复现入口](switch_aot_v1/README.md)：单表叶函数实验，独立于正式窗口构建链。
- [早期研究](docs/RESEARCH.md)与[反证审查](docs/REVIEW.md)：保留研究时点，不作为当前实现能力声明。
- [剩余任务与验收门槛](REMAINING.md)：按能力与证据推进，不按周数或估算百分比表示完成度。
- [第三方许可与修改归属](THIRD_PARTY.md)：根 MIT 许可不覆盖第三方衍生代码的单独许可。
- `migration_cache_v2`、`portable_graphics_v2`：准备固定版本依赖缓存。
- `migration_install_v2`：从两份缓存离线构建CPU／switch／图形与v6 App，提供受控失败恢复；不自动启动App。旧 `migration_install_v1` 保留原profile。
- `migration_v5`：使用已有显式 CPU／图形 provider 的 analyze/build/verify。
- `examples/integer-tile`：小型自制 PE、配置与源码来源。现有历史样例生成脚本仍有旧工具路径依赖，不能声称从 C++ 到该 PE 已完全独立一键复现。

## 从样例开始

构建要求 Apple Silicon macOS、Python 3.13 或更高版本，以及已选择且包含 Metal 工具的 Xcode／SDK。已验环境为 M2、macOS 26.3.1、Xcode 16.2／SDK 15.2；尚未做另一台干净机器的完整复现。大依赖构建需要数 GiB 临时磁盘空间。以下从仓库根目录执行；所有输出目录均使用尚不存在的新路径。

先分析本轮窗口switch样例；完整构建参数见上述正式开发入口：

```sh
python3.13 -B -m migration_v6 analyze examples/window-switch/switch_tile.exe \
  --profile examples/window-switch/profile.json
```

以下准备固定缓存并计划完整v6安装：

```sh
python3.13 -m migration_install_v2 --help
python3.13 -m migration_v5 analyze examples/integer-tile/integer_tile.exe \
  --profile examples/integer-tile/profile.json
```

联网准备依赖，然后离线安装：

```sh
python3.13 -m migration_cache_v2 prepare-cpu \
  --cache "$PWD/.local/cpu-cache" --out "$PWD/.local/cpu-fetch"
python3.13 -m portable_graphics_v2 prepare \
  --cache "$PWD/.local/graphics-cache" --out "$PWD/.local/graphics-fetch"

python3.13 -B -m migration_doctor_v1 \
  --cpu-cache "$PWD/.local/cpu-cache" \
  --graphics-cache "$PWD/.local/graphics-cache" \
  --pe "$PWD/examples/window-switch/switch_tile.exe" \
  --profile "$PWD/examples/window-switch/profile.json" \
  --identifier org.peaotlab.install.switch.example.v1 \
  --work-root "$PWD/.local/install-work" --out "$PWD/.local/install" --jobs 2

python3.13 -m migration_install_v2 plan \
  --cpu-cache "$PWD/.local/cpu-cache" \
  --graphics-cache "$PWD/.local/graphics-cache" \
  --pe "$PWD/examples/window-switch/switch_tile.exe" \
  --profile "$PWD/examples/window-switch/profile.json" \
  --identifier org.peaotlab.install.switch.example.v1 \
  --work-root "$PWD/.local/install-work" --out "$PWD/.local/install" --jobs 2
```

doctor输出stdout JSON，`--out`是待安装目录，不是报告文件；使用 `-B` 防止Python字节码写入，Apple工具可能维护系统缓存。doctor只记录前置观测和磁盘源码快照，不证明运行中加载的代码身份或全部资源完整。

预检通过后，以同样参数把 `plan` 改为 `install` 开始构建；预检不会替你完成native构建或启动验证。使用 `migration_v6 verify <结果中的product目录>` 复核产物；正常首次安装的独立reader中，`--installation`和`--session`都指向本次安装目录，只有实际恢复才使用新resume目录。按[运行入口](migration_run_v3/README.md)使用本次返回的product和receipt SHA，替换旧 `app-04` 示例；实际运行、交互与性能分别验收。

当前源码发行的无工具链检查与完整 native 验收是不同层级。许多历史实验测试依赖私有保留的原始构建证据，不能在刚 clone 后运行全仓 `unittest discover` 并把缺文件当成兼容性失败。以本仓库明确列出的复现命令和前提为准。

## 许可

项目原创部分采用 [MIT](LICENSE)。Remill 衍生部分保留 Apache-2.0 及其声明，当前固定 DXMT 提交采用 LGPL-2.1-or-later；其他依赖以对应固定版本许可为准。此发布为研究源码发行，不提供第三方工具链或预构建 App 发行包。后续二进制分发仍需完成各依赖相应的源码、修改归属与重链接等义务。
