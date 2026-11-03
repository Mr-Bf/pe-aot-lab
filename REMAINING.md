# 剩余工作与 AI 开发入口

**固定已支持输入的受限迁移脚本MVP已完成同机静态交付闭环。** 入口统一为[`migration_workflow_v1`](migration_workflow_v1/README.md)，覆盖一份配置的检查、构建、失败恢复与验证。既有provider和固定缓存offline两条路线均有实际产品及独立复核；未知PE不会自动补profile或直接转换。

本轮从本地公开`7db91d2`的639文件完整导出到同机新源码目录，完成新CPU／switch／graphics／App，接受41／5／29／69条命令。首次App构建受控中断后恢复成功，103个原失败文件before／after／current一致；verify及成功产物reuse退出0、workflow attempts仍2。独立安装reader两模式各5510文件／650产品文件、原始报告相同；外层恢复关联两模式均通过。详见[离线整链与恢复](docs/MIGRATION_WORKFLOW_OFFLINE_V1.md)。

本轮生产源码无改，App／guest／GPU执行均为0，无新增性能结论。本地交付、不推送；这是已有缓存与SDK条件下的同机公开源码复现，不是网络冷获取、第二机器或逐字节可重复构建。

## 已验收的脚本范围

| 工作 | 实际边界 |
|---|---|
| 单配置入口／门禁 | init/check/plan/build/status/resume/verify；配置内路径按config.parent解析；未知PE、缺profile及已有输出保持拒绝 |
| providers构建／恢复 | 上批fresh及中断恢复后产品两模式各3806唯一文件／650产品文件；135旧失败文件保持；36项双模式测试通过 |
| offline整链／恢复 | 本轮新三provider与新App，真实App-stage中断后恢复；5510文件reader两模式相同；103旧失败文件保持 |
| 公开源码同机复现 | 固定本地公开提交639文件，完整manifest校验，新源码目录发起native；不借用旧provider或私有源码 |
| 成功产物复用 | verify及resume重验通过；已有成功产物不重复构建，本轮attempt仍2 |

上批providers证据独立见[工作流报告](docs/MIGRATION_WORKFLOW_V1.md)，与本轮offline数字分开。check／plan需要拟建且不存在的workspace，只输出stdout；已有工作区用status／verify／resume。所有工作流命令都不自动启动App。

## 下一主任务：真实原PE的startup／TLS切片

首个目标已固定为Chocolate Doom 3.1.1官方Win64包，34个PE完成静态库存；主程序318个导入中只有3个名称命中现有表，参数未验。原入口／TLS根的45,456节点、11,286块及53,288边已独立核对，478项控制前沿仍未闭合。**真实第三方迁移成功数为0。**

下一批以固定原PE的startup／TLS reason、state和ABI为入口：明确reason条件、状态读写、调用签名及返回约束，保留未知边；根据实际缺口实现最小切片，再推进原PE切片AOT与真实启动。不能把线性解码当完整控制流，也不能把静态边当必经或用源码macOS重编译计迁移成功。

随后按真实失败扩CRT／DLL／SEH／线程／API，逐项验证主循环、图形／音频／输入、存取档与退出；素材和DLL对应源码／许可另核对。更广SIMD、间接控制与复杂图形仍有缺口。性能需同场景实测，不能从指令数、测试数或微基准推断游戏FPS／支持率。

## W9交付余项

- **有限诊断：** 活动工作区已拒绝重复resume并避免重复builder，但现状是通用`CHECK_FAILED`、`next_action=null`；BUSY专用诊断与下一步提示仍待完善。
- **版本与发行：** 本批报告／清单／版本状态的本地收尾；本地导出、测试、提交、线上推送分别记录。自动依赖准备、签名公证与升级仍未完成。
- **独立环境：** 网络冷获取和第二台干净机器的依赖／SDK／构建验收尚未进行，不能继承本机结果。
- **运行产品：** 真实目标长时稳定性、代表性性能及Wine＋Rosetta对照另立可复核实验。

这些余项继续开放，不再统一阻塞下一批真实原PE切片；不为完善UX或扩大harness无限延后兼容开发。进度按实际能力和证据记录，不按周数、测试数量或估算百分比。

## 历史验收导航

- [v7离线构建／恢复](docs/MIGRATION_INSTALL_V3.md)、[公开源码同机复现](docs/PUBLIC_REPRODUCTION_V1.md)。
- [正式lookup与App回归](docs/WINDOW_LOOKUP_V1.md)、[同地址ABI重放](docs/WINDOW_OUTER_REPLAY_V1.md)。
- [真实PE库存](docs/REAL_TARGET_INVENTORY_V1.md)、[原PE控制流需求图](docs/REAL_PE_CFG_V1.md)。

以下数字保留原冻结范围，不是本轮重新执行的结果，不参与新入口完成度计算。

<details>
<summary>历史已通过子项与原证据数字</summary>

| 类别 | 历史子项 | 冻结范围 | 原证据 |
|---|---|---|---|
| 已通过子项 | 有限switch正式窗口集成 | 该历史批次代码/构建/正确性/整链通过，性能未验 | schema2与capability隔离；全根证明；86项普通/优化门禁；32次真实callback两基址/O0/O3；两轮真实Cocoa存取和搬移运行、790文件复核。原scalar 288 ARM/144 x86证据另保留 |
| 已通过子项 | v6完整离线install与恢复 | 该历史批次实现/构建/正确性/整链通过，性能未验 | 新installer与reader40项边界；真实图形SIGTERM失败保留，CPU/switch重验复用、新图形attempt；五阶段144条被接受命令、5722文件独立读验及新App两轮真实Cocoa/790文件复核 |
| 已通过子项 | 公开源码同机独立目录整链native复现 | 构建/正确性/整链通过，性能未验 | 公开99a271d的499文件从本地archive导出；既有固定缓存→全部新provider/App，144命令、5459正式reader/1700额外审查、新callback32及新App两轮Cocoa/790运行复核；首次超时和额外实例单列。不是网络clone/冷获取或bit-repro证明 |
| 已通过子项 | v6安装前分项诊断 | 实现/边界/本机正负诊断通过，无native构建 | 11组PASS/FAIL/SKIPPED；实现14项、独立14项普通/-O；实际11PASS退出0，负例7PASS/3FAIL/1SKIPPED退出2；源快照/完整性边界明确 |
| 已通过子项 | 正式switch回调CPU测量工具/原始采样 | 构建/32例完整状态/独立读验通过；稳定性能未验 | 两基址约79万次回调、384原始批次、16计时末态，4047文件普通/-O独立复核一致；7条时钟逆差及调度扰动原样保留，未执行完整ABI/App/GPU或启用旧快路径 |
| 已通过子项 | RAW时间源观察与lookup成对优化实验 | 组件正确性/原始采样/独立复核通过；非部署收益 | 64正常fullresponses、1456预算对、约315万次测量阶段回调、960样本；16场景配对中位比0.9191–0.9289，191/192更快；新RAW零逆差但调度慢例保留，旧异常不改写 |
| 已通过子项 | 无选择器独立产物 | 组件构建/完整状态/实测/独立复核通过 | 64normal、2912完整budget、96process/1536样本，16场景配对中位比约0.9141–0.9411，189/192更快；无App性能结论 |
| 已通过子项 | v7正式lookup及新App回归 | 代码/构建/正确性/受限集成已验，App性能未验 | 69构建命令、86测试、1488内核执行含1456完整预算；两轮Cocoa原路径/搬移存取正常退出；产品3806/回调5148/运行805文件身份独立复核（产品内650文件） |
| 已通过子项 | v7的install/resume/doctor接线 | 实现／版本边界／本机整链通过，性能未验 | schema3计划／session2、固定lookup身份；旧v2拒绝；App真实SIGTERM后前三provider重验复用，新attempt生成App；80项普通／-O、12组doctor正负例、144条接受命令、5514／805文件独立复核。首次桌面绑定超时及额外实例清理保留，见[该历史批次报告](docs/MIGRATION_INSTALL_V3.md) |
| 已通过子项 | 完整外层ABI单次观察 | A1／A2观察切片已构建、执行和独立复核 | 四配置、64事件／32快照／8选定调用链；State／Context恢复、映像oracle和40B marker已验，3980文件两模式复核；33单测与128轨迹变异拒绝／每模式。保留两次selector错误；非系统键盘、重放或性能 |
| 已通过子项 | 同地址正常ABI重放 | 四配置执行与独立复核通过；性能未验 | 200事件／104快照／24选定调用；51单测、396轨迹变异拒绝／每模式，4060文件复核；12项共同篡改漏洞已复现并修复。原输入恢复、完整guest重放一致、每阶段转换及宿主累计账本已验，见[报告](docs/WINDOW_OUTER_REPLAY_V1.md) |
| 已通过子项 | 首个真实目标PE/依赖库存 | 官方Win64固定身份、34PE库存及该时点loader拒绝已验 | 仅静态事实，第三方转换0；素材未下载、DLL许可/源码闭包仍待审核 |
| 已通过子项 | 固定原PE的入口驱动CFG/指令需求 | 新XED适配器、47测试、45,456节点全量LLVM字节/边界交叉已验 | may-return/未知间接/异常/路径可行性未闭合，不是完整CFG或执行支持 |

| 能力 | 冻结证据与边界 |
| --- | --- |
| 固定依赖获取和离线构建 | CPU、图形缓存校验与独立构建入口；公开 `99a271d` 独立目录完整install接受144条命令。CPU使用固定LLVM17预编译工具包；Remill/XED等依赖及图形LLVM15/DXMT实际重新编译。较早install-v1的139条记录另保留。 |
| 自制 PE 到原生 App | 显式 PE/profile → 静态提升 → O0/O3 ARM64 对象 → App 打包和验证。较早样本产物已完成窗口输入、存档恢复、保存及正常退出，也验证了搬移路径。 |
| 公开源码独立目录复现 | 同机、本地archive、既有固定缓存；五阶段完整构建，新CPU/switch/graphics/App均未复用旧安装。正式reader实读5459文件，另审1700文件；新callback32次，新App原路径/搬移两轮正常，790文件运行复核。首次超时及额外实例清理单独保留。 |
| v6完整离线安装与恢复 | 从固定缓存实际完成CPU41、switch5、graphics29、App69条被接受命令；图形SIGTERM后保留失败，复用重验的CPU/switch并在新目录重建。5722文件独立读验；新App原路径/搬移两轮正常，32次callback两基址/O0/O3通过。 |
| v6安装前诊断 | 新doctor以11组PASS/FAIL/SKIPPED汇总前置条件，全部通过退出0，否则退出2；不创建work-root/out，不启动builder/App。14项实现测试及14项独立反例各普通/-O通过；它不是构建或源码闭包证明。 |
| v7完整离线安装与诊断 | 新install v3／doctor v2：41／5／29／69条被接受构建命令；App阶段真实SIGTERM后重验复用前三provider，新App attempt及静态验证通过。5514文件安装读验、新App两轮Cocoa同档恢复与805文件运行读验通过；12组诊断、80项普通／-O测试。 |
| 较早完整 install-v1 产物 | 构建与独立静态复核通过；首次交互尝试因桌面操作延迟超时，尚未取得该产物的正常退出验收。不能借用旧 App 的成功替代。 |
| 有限 switch 正式 App | schema2 profile → 显式 window-rel32-v1 provider → 全根证明 → 完整 ARM64 App；真实 RIGHT 路径调用只读表并影响绘制/存档。两轮原路径/搬移 Cocoa 正常退出，790文件独立复核；32次真实 WndProc 两基址/O0/O3执行通过。单表叶函数范围，不代表一般间接跳转。 |
| 早期 switch 原 x86 对照 | 独立 scalar 切片的288次正常ARM与144次原PE字节对照保留；该历史批次窗口callback不是新的原x86差分。 |
| 标量／内存／ABI | 多项组件差分和拒绝测试已通过；它们各自的支持范围不同，不等于通用 Windows 运行时。 |
| 前批v7生产lookup与新App | 仅替换instruction查找，状态快照/权限/回滚保留；650产品文件、新callback完整预算、两轮真实Cocoa及同档恢复通过。该批复用已有provider，未重建工具链或测App性能。 |
| 完整外层ABI观察 | 单次真实 DispatchMessage／callback／DefWindowProc／RET，完整State／Context恢复（两个计数槽另验）、映像oracle及40B marker／shadow通过；其余RSP以下栈仍缺全部字节独立oracle。不是新增API兼容或性能验收。 |
| 同进程ABI重放 | 每消息两次诊断＋一次原输入continuation，guest原址恢复、逐字节重放一致、每阶段State／Context转换及三宿主会话结构已验。其余栈独立语义oracle及完整FileTLS独立导出仍有缺口。 |
| 性能 | 已有局部微基准和资源记录；尚无代表性游戏性能、Wine＋Rosetta 同场景对比或整体提速结论。 |

</details>

## 接续开发规则

从工作流README及上方脚本队列开始，用新目录保留原始失败、命令、版本和文件身份。完成一个切片后独立复核，只重跑受影响验证。公开源码不包含所有大型历史现场；原始产物缺失时明确无法复核，不补造结果。当前不需要Steam登录。
