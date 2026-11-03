# 首个真实 Windows x86-64 目标：静态盘点选型

日期：2026-11-03。状态：`SOURCE_SELECTION_FOR_STATIC_INVENTORY_NOT_AOT_ADMISSION`。

本轮选定 **Chocolate Doom 3.1.1 官方 Win64 发布包**作为首个真实第三方 PE 盘点目标，后续游戏数据候选为 Freedoom 0.13.0。选择依据是上游有明确许可证、约9.8 MB的现成Win64包、固定tag对应提交和官方资产SHA256，以及可直接核对的C源码和发布流程。这里选择的是需要迁移的原Windows二进制；已有macOS源码构建或上游ARM64发行包不作为本项目的迁移证据。

本报告完成在线主来源核对、范围选择，以及对已取得包的独立摘要／PE头部复核。本选型任务没有下载或执行第三方程序，也没有宣称解码、AOT、Windows兼容、游戏运行或性能通过。主任务的下载、解包和详细PE／依赖盘点另存记录；不能用本报告中的源码依赖列表代替二进制实测。

## 候选比较

| 候选 | 可核实的上游材料 | 本轮决定 |
|---|---|---|
| Chocolate Doom 3.1.1 | 官方Win64 ZIP；9,798,661 B；release资产有SHA256；GPLv2许可文件；主要C代码；Windows CI使用MSYS2 UCRT64 | 优先静态盘点。多DLL、SDL和CRT仍带来实质兼容工作，不是可立即转换的目标 |
| OpenTTD 15.3 | 官方Win64 ZIP；官网下载页列10.7 MiB及SHA256；GPLv2为主，附第三方许可；需另备基础图像包 | 保留后续候选。本轮不展开大型C++游戏、脚本与内容系统；尚未下载或比较实际PE复杂度，不能把上述推断写成已测成本 |

OpenTTD官网明确图像数据需单独提供，声音与音乐可选；其独立官网下载入口不要求Steam，社交平台插件另外安装。以上属于上游发布说明，不代表本项目验证过其全部运行路径。[OpenTTD下载页](https://www.openttd.org/downloads/openttd-releases/latest)、[固定版本README](https://github.com/OpenTTD/OpenTTD/blob/14ec60f248547d4d062a1160f0fc26d742319888/README.md)、[固定版本许可](https://github.com/OpenTTD/OpenTTD/blob/14ec60f248547d4d062a1160f0fc26d742319888/COPYING.md)。

另尝试读取Neverball的GitHub latest-release接口，得到404；仅说明该接口没有返回最新release，不能推出项目不存在或没有Windows发行包。本轮不继续扩展候选搜索，原始错误单独保留。

## Chocolate Doom 输入身份

| 项 | 固定值 |
|---|---|
| 仓库 | `chocolate-doom/chocolate-doom` |
| release/tag | `Chocolate Doom 3.1.1` / `chocolate-doom-3.1.1` |
| release ID | `240385722` |
| tag指向的commit | `410d96855b5df5410ff591a90efeafa889119224`（Git ref对象类型为commit，无需继续解tag） |
| release发布时间 | `2025-08-16T17:23:36Z` |
| Win64 asset ID | `283165247` |
| 文件名 | `chocolate-doom-3.1.1-win64.zip` |
| 官方API size | `9798661` B |
| 官方API digest | `sha256:58c34c61ae954493fce5ff01fd553898240a0de25658aa97b43ac9510c49581f` |

来源：[固定release](https://github.com/chocolate-doom/chocolate-doom/releases/tag/chocolate-doom-3.1.1)、[tag引用API](https://api.github.com/repos/chocolate-doom/chocolate-doom/git/ref/tags/chocolate-doom-3.1.1)、[官方Win64资产](https://github.com/chocolate-doom/chocolate-doom/releases/download/chocolate-doom-3.1.1/chocolate-doom-3.1.1-win64.zip)。官方网站的[下载页](https://www.chocolate-doom.org/wiki/index.php/Downloads)也链接该Windows发行版。

下载后必须由本机重新计算ZIP的字节数与SHA256，再逐文件记录EXE/DLL的PE Machine字段和摘要。不能仅凭文件名中的win64认定所有成员都是AMD64。GitHub release的`immutable`字段为false；版本、commit、asset ID和摘要共同固定本轮输入，不依赖未来`latest`内容。tag和官方发布关系不等于已经证明从对应源码可逐字节重建该ZIP。

主任务现已取得该ZIP并完成有边界的解包，记录位于`build/real-target-inventory-v1/acquire-02/`。选型复核独立重算ZIP摘要，与官方size／digest相符；37个文件总计20,984,174 B，其中2个EXE和32个DLL的PE头Machine均为0x8664。主程序`chocolate-doom.exe`为875,520 B，SHA256为`15e81c194df270fbd71450222e71846247926fabfb889e72e7d855903454d752`。这些是静态头部与文件身份事实，尚不是成功装载、提升或执行的证据。

实物同时带有`SDL2.dll`、`SDL2_mixer.dll`、`SDL2_net.dll`和`SDL3.dll`。仅凭这些名称还不能证明谁会加载谁、运行时选择哪个渲染驱动；详细依赖图应依据实际导入、转发和动态加载证据继续建立。包内非PE文件只有`CMDLINE.html`、`INSTALL.html`、`NOT-BUGS.html`三份，未附齐每个DLL的独立许可材料；本轮没有宣称32个DLL的版本、对应源码和分发许可闭包已全部审核。完整包不加入本项目公开仓库。

## 许可与实际技术路线

固定提交的[COPYING.md](https://github.com/chocolate-doom/chocolate-doom/blob/410d96855b5df5410ff591a90efeafa889119224/COPYING.md)是GNU GPL第2版文本；[i_video.c](https://github.com/chocolate-doom/chocolate-doom/blob/410d96855b5df5410ff591a90efeafa889119224/src/i_video.c)的文件头允许GPL第2版或之后版本。项目[CMake配置](https://github.com/chocolate-doom/chocolate-doom/blob/410d96855b5df5410ff591a90efeafa889119224/CMakeLists.txt)的包许可字段写为GPL版本2。报告保留这一层次区别，不把单个文件头外推为包内全部DLL统一许可，也不把本实验工具库的许可套到翻译后的游戏产物。

固定提交的[Windows CI](https://github.com/chocolate-doom/chocolate-doom/blob/410d96855b5df5410ff591a90efeafa889119224/.github/workflows/main.yml)使用MSYS2 UCRT64／GCC，安装SDL2、SDL2_mixer、SDL2_net、libpng、libsamplerate、FluidSynth等依赖。发布[打包规则](https://github.com/chocolate-doom/chocolate-doom/blob/410d96855b5df5410ff591a90efeafa889119224/pkg/win32/GNUmakefile)调用`cp-with-libs`收集程序依赖，并strip EXE/DLL。这给出需要检查整个包的理由，但不是本机已核实的最终DLL清单；CI解析的依赖版本也未全部由该源提交锁定。

图形源码通过SDL创建窗口和renderer、上传texture并呈现CPU生成的画面。`SDL_CreateRenderer`使用自动驱动选择；代码还包含OpenGL格式处理。因此本目标不能标为“固定D3D11游戏”，也不能靠既有自制D3D11样例的通过结果推断其图形路径已适配。后续应检查实际SDL DLL中的动态库加载和渲染驱动，并明确是保留Windows SDL路径还是建立另一个经过验证的窄API后端；两者都不能悄悄把游戏源码重编译成macOS程序冒充PE迁移。[固定图形源码](https://github.com/chocolate-doom/chocolate-doom/blob/410d96855b5df5410ff591a90efeafa889119224/src/i_video.c)。

单机范围不要求测试其网络游戏功能，但发行包中的网络DLL和导入仍应如实记录。未知导入不得假装成功，运行时是否加载或执行某项能力需要另外取得证据。当前不需要Steam账号或商业Doom数据。

## 后续自由游戏数据候选

Freedoom提供游戏数据，不包含运行引擎。固定候选为[0.13.0发行版](https://github.com/freedoom/freedoom/releases/tag/v0.13.0)：

| 项 | 值 |
|---|---|
| 仓库/tag | `freedoom/freedoom` / `v0.13.0` |
| annotated tag对象 | `8cecc3642861dfb71839984c886d5576fa120d49` |
| 解tag后的commit | `cfb8644b1a8dc7d7d2177e6a892ccaa2922bdaae` |
| 资源asset | `freedoom-0.13.0.zip` / asset `148625434` |
| API size | `24143781` B |
| API digest | `null`，不能补造SHA256 |

[COPYING.adoc](https://github.com/freedoom/freedoom/blob/cfb8644b1a8dc7d7d2177e6a892ccaa2922bdaae/COPYING.adoc)为BSD三条款形式，要求保留版权、许可和免责声明，并禁止未经许可的背书；[README](https://github.com/freedoom/freedoom/blob/cfb8644b1a8dc7d7d2177e6a892ccaa2922bdaae/README.adoc)说明Phase1／Phase2面向单人关卡，IWAD包含画面、音效和音乐等数据。本轮静态PE盘点不需要下载IWAD。进入运行阶段时再冻结资源包、上游CHECKSUM及本机摘要，优先选择明确的单关卡流程，不使用原版商业Doom的素材。

0.13.0发行说明记录了vanilla兼容性改进，也仍列有savegame buffer overflow问题；因此“可用自由数据”不等于本项目已证明Chocolate Doom与该版本所有关卡、存档都正常。tag签名在GitHub API中的验证状态为unknown_key，本轮未进行GPG验证，不写“签名已验证”。将来分发派生游戏产物时，需要另行保留GPL对应源码与许可义务、各DLL许可及Freedoom数据的归属；本轮公开工具库不加入第三方ZIP、PE或IWAD。

## 盘点完成后的开发决策

1. 将官方ZIP、EXE、全部DLL与可读许可材料按摘要冻结；数据文件另列，不执行任何目标代码完成静态清点。
2. 解析架构、entry、section／权限、导入与转发／延迟导入、重定位、TLS、exception/unwind、load-config等；区分有目录、已解析内容、已支持运行语义三个层次。
3. 对照当前迁移工具的真实合同，列出首个精确拒绝原因和目标所需能力。单凭导入表不能证明完整控制流、没有动态代码、没有额外DLL加载或全部导入都会执行。
4. 先选择可验收的启动里程碑，再补支持和独立差分；保留原PE字节。菜单、输入、音频、存取档、真实退出和性能分别验收。

Go：下载并静态盘点此官方Win64输入。No-Go：宣称已迁移、立即可运行、已经验证DirectX后端、全部游戏兼容或任何性能收益。

## 证据保存

本次GitHub连接器返回的metadata与UTF-8文本快照位于`build/real-target-inventory-v1/research/`；`index.json`记录来源。文本是连接器解码结果，末尾换行统一保留，不冒充原始HTTP字节或Git blob文件摘要。若读取旧式`COPYING`／`INSTALL`路径得到404，失败JSON保留，随后改读实际路径，不据此断言项目无许可。

OpenTTD备选的固定tag `15.3`指向commit `14ec60f248547d4d062a1160f0fc26d742319888`；官网Win64 ZIP链接为`https://cdn.openttd.org/openttd-releases/15.3/openttd-15.3-windows-win64.zip`，官网列SHA256 `61c0a6a43d81008c7ff4330fb56351bbf66a980cdad041f1d0e08b51f2eeb34c`。它只作为可追溯备选，本轮没有下载该文件或基础图像包。
