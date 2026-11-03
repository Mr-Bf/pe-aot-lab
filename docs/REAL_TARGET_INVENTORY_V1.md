# 首个真实 Windows PE：库存、当前阻断与下一开发入口

本批日期：2026-11-03。**主线已从自制样例回归推进到固定第三方 Windows 发布包。** 选定 Chocolate Doom 3.1.1 官方 Win64 ZIP，完成身份校验、静态库存与当前 v7 loader 的实际数据试读。新增两个可复用 Python 模块；没有执行第三方 EXE/DLL，没有构建其 ARM64 产物，没有迁移成功或游戏性能结论。

结论：**Go 继续真实目标的控制流和 ABI 缺口开发；No-Go 把当前 v7 当成该游戏的可用转换器。** 第三方完成迁移数仍为 0。目录门禁、DLL/CRT/TLS/异常、指令/控制流及 SDL/API 都有实质工作，不能把剩余工作解释为再加几个导入名或放大一个限制。A3 外层终止边界仅完成[辅助设计](WINDOW_OUTER_BOUNDARY_NEXT_V1.md)，本批没有实施新的 native A3 矩阵。

## 冻结输入与来源

| 项目 | 实际身份 |
|---|---|
| 上游 | [Chocolate Doom 官方 release](https://github.com/chocolate-doom/chocolate-doom/releases/tag/chocolate-doom-3.1.1) |
| tag 对应源码 commit | `410d96855b5df5410ff591a90efeafa889119224` |
| 官方资产 | `chocolate-doom-3.1.1-win64.zip`，release id 240385722，asset id 283165247 |
| ZIP 大小 / SHA-256 | 9,798,661 B / `58c34c61ae954493fce5ff01fd553898240a0de25658aa97b43ac9510c49581f` |
| 解包内容 | 37 个普通文件，20,984,174 B；其中 2 EXE + 32 DLL，均为 AMD64 PE32+ |
| 主程序 | `chocolate-doom.exe`，875,520 B |
| 主程序 SHA-256 | `15e81c194df270fbd71450222e71846247926fabfb889e72e7d855903454d752` |

GitHub 连接器读取官方 release/tag/源码与许可；连接器不提供二进制下载，ZIP 使用官方 HTTPS 链接下载，再核对官方公布的长度与 SHA。首次直连网络失败保留为 `acquire-01`；第二次使用机器已有的本地代理成功，未修改全局网络配置。解包前检查路径、重复成员、大小、类型及压缩方式，逐文件摘要保存于 `acquire-02/extraction.json`。所有提取文件为普通不可执行权限，没有运行安装器。

Release API 的 `immutable` 为 false；这里冻结的是已取得的字节身份，不能把上游 release 当成不可变发布。源码 tag 与资产同属 release 不证明源码到官方二进制可重复构建。上游引擎 GPL 许可、自由素材候选和 DLL 许可闭包边界见[选型报告](REAL_TARGET_SELECTION_V1.md)；本仓库不再分发该 ZIP、EXE、DLL 或游戏数据。Freedoom/IWAD 尚未下载，不需要 Steam 登录。

## 已开发和实际验证的能力

| 能力 | 代码 | 本机验证 | 未覆盖 |
|---|---|---|---|
| `real_pe_inventory_v1` | 独立 stdlib PE32+ 库存器 | 34 个真实 PE 的头、节、目录、导入、重定位、TLS、异常头等；普通与 `-O` 冻结结果比较 | 不是 Windows loader、CFG 或完整语义解释器 |
| `real_target_gap_v1` | 重新读取原字节，对照受审 v7；固定 11 个能力源码 SHA | 34 个原 PE 实际 data-image loader 试读，全部在当前门禁拒绝 | 不生成 profile、不调用 guest、不提升代码 |
| 独立核对 | Apple `/usr/bin/objdump --private-headers` 及独立字节读取 | main、SDL2、SDL3、libgomp 四文件的头/目录/导入等交叉核对 | 不是执行 oracle、Windows 实机或完整 PE 安全审计 |
| 外层 A3 | 预算拒绝和终止合同设计 | 只读前批正常轨迹与源码 | 未构建、未执行、未计时 |

库存的总体状态为 **INCOMPLETE**：所有 34 个文件都包含尚未完整解释的元数据，整文件头解析拒绝数为 0。正常目录读取成功与局部语义缺口同时存在，并不矛盾。CLI 的退出 2 保留这种不完整性；gap CLI 退出 0 则只表示缺口报告已生成，不能当成转换通过。

## 主程序的实测需求

| 静态事实 | 当前含义 |
|---|---|
| 入口 RVA `0x13e0`；映像 1,695,744 B；GUI subsystem | 已固定文件身份，未运行入口 |
| 一个 executable section；`min(VirtualSize, SizeOfRawData)` = **392,224 B** | 当前 `portable_app_v1.lift.executable_bytes` 上限 32,768 B；代码形态门禁已不满足。不是指令数、可达代码大小或覆盖率 |
| 26 个导入 DLL 描述符，**318 个静态导入符号** | v7 21 项标签表仅命中 3 次：CloseHandle、GetLastError、ReadFile；其余 315 次不在表内。命中 3 次也未验证参数和行为，不计算支持百分比 |
| resources 目录 2、exception 目录 3、TLS 目录 9 | 都在当前允许集合 1/5/12 之外；真实 loader 首个拒绝为 `unsupported directory 2`。这是实现限制，不是文件损坏结论 |
| TLS 原始模板 8 B；2 个 callback，RVA `0x1570`、`0x1550` | TEB/TLS、初始化顺序和回调执行尚未实现到该目标 |
| 1,554 个 RUNTIME_FUNCTION 记录 | 只盘点范围和 unwind 原始头/槽；不能据此宣称完整函数发现、SEH 或 C++ 异常支持 |
| CreateThread、同步 API、TlsGetValue、LoadLibraryW、GetProcAddress、VirtualProtect 等导入 | 表明这些 API 是静态需求候选；未证明某具体路径运行、线程实际创建或存在 JIT |
| 直接导入 SDL2 111 项、SDL2_mixer 20 项、SDL2_net 7 项，以及 FluidSynth/libpng/libsamplerate/UCRT 等 | 当前固定 D3D11 triangle runtime 不提供这组 ABI。SDL 源码使用 renderer/texture，实际选中的渲染后端仍未验证 |

整个发布包共 464 条导入描述符边、4,396 次静态符号出现。53 条边在包内有唯一 basename 候选，411 条未在包内找到；**这不是 411 个缺失 DLL**，其中包含 Windows/API-set 名称，真实系统解析尚未做。包内存在 SDL2 和 SDL3；实际库存显示 `libfluidsynth-3.dll → SDL3.dll`，没有据共存关系猜测 SDL2 就是 SDL3 兼容层。

34 次当前 loader 试读全部拒绝：26 次先遇到严格 import descriptor size 门禁、7 次先遇到只允许 EXE 的门禁、主程序先遇到目录 2。首个拒绝不等于所有阻断项已穷尽；其他目录/代码区/导入名及 profile 问题另列。DLL 仍可被库存器读取，不能把其库存成功解释为当前运行时支持多模块加载。

## 复审、失败与证据边界

独立复审修复了两类报告错误：

1. 库存器：delay-import 的 module-handle、bound-IAT、unload-IAT 越界仍被标完整；添加真实字节反例与范围门禁。另将 relocation 的计数上限前置，避免先把过大的表展开为 Python 对象再拒绝。
2. 缺口报告：有 DLL 名、但 bound-IAT 缺 ILT 或旧式 VA delay thunk 尚未解析的描述符，原先会因符号列表为空而被遗漏；现完整保留原始描述符和未解析计数。12 项 gap 测试普通与 `-O` 均通过，独立原始反例确认未解析描述符完整保留、计数正确。

真实 libgomp 的零基索引 817（第 818 条）RUNTIME_FUNCTION 为零长度范围，独立读取原始 12 B 确认不是目录尾零 padding；该项不是 objdump 条目核对结果。工具现保留其原始值并标 `empty_range_unparsed`，目录仍 PARTIAL；没有猜 Windows 是否接受，也未算成有效代码范围。反向范围仍拒绝。

初次库存 `inventory-01`、初次 gap `gap-01`、两个工具的 `review-01`、直连失败及 Python 3.8 环境不支持 API 的失败都保留。Python 环境错误不算 PE 失败；使用 Python 3.13 的最终复验单独记录。当前工具仅面向合法输入的工程盘点，不宣称完成恶意 PE 安全审计。

本机完整原始 JSON、命令、stdout/stderr、源码快照和独立复核位于 `build/real-target-inventory-v1/`。大体积第三方包位于仓库外 `work/real-target-v1/`。公开源码只包含本项目实现和报告，完整本机证据不会被冒充为公开 CI 或干净机器复现。

最终冻结结果：`inventory-02` 的31项库存测试和 `gap-02` 的两个模块合计43项测试均在普通／`-O`模式通过；两次报告分别逐字节一致，且独立 inventory 与 gap 内嵌库存内容完全相同。不是把31与43再相加为74项覆盖。库存 JSON SHA为 `d928de6d4694ccb4c93cad8f1c8a71f24a94076a780814853ef59d50cb814add`；缺口 JSON SHA为 `a3780e55c5a1a1dcdb64ba7a34829b59925daf113e9d2a0ff8abcd2e0ee2484b`。受审代码执行前后未变，guest/native程序执行数为0。

## 可复现实验入口

Python 要求 3.13+。输入应为合法获得并已校验身份的目录；本机使用 `/opt/homebrew/bin/python3.13`。这些命令只读 PE：

```sh
mkdir -p /tmp/chocolate-inventory-new
python3.13 -B -m real_pe_inventory_v1 /absolute/path/to/extracted \
  --json-out /tmp/chocolate-inventory-new/inventory.json \
  --markdown-out /tmp/chocolate-inventory-new/inventory.md
# 此目标预期退出 2，报告状态 INCOMPLETE，仍保留已读元数据。
python3.13 -B -m real_target_gap_v1 /absolute/path/to/extracted \
  --entry chocolate-doom.exe \
  --json-out /tmp/chocolate-inventory-new/gap.json \
  --markdown-out /tmp/chocolate-inventory-new/gap.md
python3.13 -B -m unittest real_pe_inventory_v1.test_inventory real_target_gap_v1.test_report -v
python3.13 -B -O -m unittest real_pe_inventory_v1.test_inventory real_target_gap_v1.test_report -v
```

输出路径必须不存在，不能在输入树内；重复实验换新目录。输入包可从上面的官方 release 下载；下载后必须按本报告固定 SHA/长度复核，再解包。无需编译上游源码或执行第三方 PE。更详细 schema 和边界见[库存器](../real_pe_inventory_v1/README.md)、[缺口工具](../real_target_gap_v1/README.md)。

## 后续 AI 开发批次与验收

| 优先级 | 下一工作 | 验收条件 |
|---|---|---|
| P0 主线 | 为固定主程序建立有来源的 CFG/指令需求库存 | 入口和 TLS callback 作为显式根；`.pdata` 仅作候选边界；记录已解码块、拒绝 PC/字节/操作数及未知间接边，不把线性反汇编当可达 CFG；不能只扩大 32 KiB 门禁 |
| P0 主线 | 选择明确的 ABI 分界并闭合依赖来源 | 审核 DLL 版本/源码/许可，评估以原生 SDL/音频/图片库桥接缩小 guest DLL 面；保留主游戏 Windows PE 为翻译输入。原生库桥接是候选架构，尚未实现，也不能计作源代码移植后的 AOT 成功 |
| P0 主线 | Windows 启动与 CRT/TLS/异常的第一条真实路径 | 以该固定 PE 的首个可证失败驱动实现，原字节、初始化顺序、栈/flags/回调证据对齐；需要的线程/同步语义单独验收 |
| P1 辅助 | A3 最小 terminal-budget 纵切 | 按新设计保留真实终止和清理，不回滚宿主；通过前不缩减 State 保护、不测外层 ABI 性能 |
| P1 集成 | 原目标原生启动到事件循环/画面 | 先完成上述前置；随后自由 IWAD、输入、音频、存档、退出、资源释放逐项验收；不能用替换为更简单自制程序计成功 |
| P2 性能 | 代表性负载与同场景基线 | 正确性冻结后区分 CPU、GPU、帧时、内存；与 Wine/Rosetta 对照必须实测，当前没有游戏优势结论 |

这次关闭的是“首个真实输入尚未固定、缺少实际 PE/API 清单”的缺口；游戏 AOT 构建、运行和性能都没有关闭。以实际能力和证据推进，不用测试数或目录大小换算项目完成百分比。
