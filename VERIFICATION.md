# 验证记录

最新验收日期：2026-11-02。新增CPU回调基准完成构建、完整状态检查、原始采样与独立复核，时钟异常/调度扰动使稳定性能仍未验收。当前源码515文件，整链native构建与新App运行只绑定公开 `99a271d` 的499文件；doctor和CPU基准各自单独验收。本页以下分别保留各冻结版本、首次失败和验证边界；原始本机现场不随源码上传。

## 历史受限 switch 切片（2026-10-29）

验收日期：2026-10-29。实际环境：Apple Silicon M2／macOS。以下是本机实验的摘要；原始命令、stdout/stderr、完整状态、映像和逐例二进制响应保留在本地实验库，未随公开源码上传。公开入口测试可以使用登记的自产 PE 与 XED packet 重跑，不能据此声称完整 native 重建已在另一机器通过。

| 层 | 实际结果 |
| --- | --- |
| 输入 | 两个由 Clang 编译并链接的真实 PE；不同寄存器、guard 和目标布局；均保持真实 8 项 signed rel32 只读表。 |
| 独立准入 | 23 项普通/优化模式测试通过：字节解码、unsigned guard、高32清零、闭包/无旁路、只读file-backed范围、DIR64交叠、目标边界和flags；2..32项，重复目标允许。 |
| 有限 IR | 两份产物各一个 8 目标 LLVM switch；保留每条 begin/commit；没有任意 __remill_jump 回退，default 明确故障。缺证明及5种证明/字节错配均拒绝生成IR。 |
| ARM64 | 144组输入 × O0/O3 = 288次正常执行；完整3504B State、寄存器、flags、内存和返回结果一致；原C独立编译参考仅校验返回值。 |
| 原始机器码 | 144次原始PE字节在x86 Rosetta测试进程执行，与288条ARM记录比较16GPR、已定义flags、归一化地址以及完整image/stack；通过。Rosetta不是产物运行依赖。 |
| 绑定与事务 | 原表字节、exact READ权限和逐项目标在启动前绑定。24次错误绑定拒绝；36次预算/故障guest执行验证guard/load/add/JMP/case边界；4次memory-helper事务验证只读写拒绝。后者不是新增PE store指令覆盖。 |
| 公开接口 | harness的5项参数接口测试、公开样例的23项准入测试均普通/-O通过。新增显式输入路径接口后没有重新执行native；旧实际运行记录绑定旧源码副本，接口变化与语义验证明确分开。 |

宿主契约是单线程可信宿主在绑定后保持backing bytes与页权限稳定。绑定后修改仅用于故障注入，不是支持自修改代码或防恶意宿主并发写。静态门禁仅支持一个根中的一个有限表与窄标量叶函数，不支持任意函数指针、一般computed goto、额外间接跳转或导入。该切片尚未接入正式窗口App流程，也未做性能对比。

保留的失败包括第一次COFF解析失败、XED隐式字段不匹配、C++接口编译错误、第一次测试fixture错配，以及第一次Rosetta身份查询受执行环境限制而失败。修复后使用新结果目录；未把失败覆盖成成功。

关键本地摘要：

- ARM runtime第二轮 result：`da53537e3bfb78a714de3acaf309f899b370bdaf36e0a3d16b0aa6b0eafd8403`。
- 原字节 oracle result：`a5b783bb9446358f7e41fc374e587c5fc988cbe36111deddad2c79f4918f8b55`。
- 第二轮 ARM 与同一 raw oracle 只读重算：`f6d8143b54d59091b353d285e9d2cb7ac180dc57061f934760af52e7d647f315`。
- 公开输入准入结果：`63909cd793faeb16d7f86f3e948ab1de0bc8d75d0ee8c47212e3f5fc7c5c0aac`。

摘要用于识别记录，不替代原始证据或审查。当前Go结论仅为继续受限静态翻译开发；通用游戏兼容、整链高性能和完整发行仍未验收。


## 正式窗口 switch 集成追加（2026-10-29）

本轮记录见 [完整验收](docs/WINDOW_SWITCH_V1.md)。新schema2/capability全根证明已生成实际App；原路径与搬移副本两次直接bundle executable启动，Cocoa系统事件触发switch 2/1次，steps 1197/917，分别保存position/moves/draws=4/3/5和5/4/8，均正常退出、TEST_QUEUE=0、proc_translated=0。第二轮实际绘制3次，draws=8为存档累计值。独立790文件复核普通与优化结果SHA相同。

实际WndProc两PE基址×O0/O3×8位置共32次通过；使用API拒绝stub的组件探针，不能计成32次App或新原x86差分。旧版16次rebased故障6的负对照保留，修正LLVM switch动态PC规范化后重建并通过新输入。86项纯Python门禁普通/-O通过，低层真实事务另有旧/新模式O0/O3及sanitizer记录。

公开源码包含新模块、补丁与自产PE；完整本机现场仍不上传。没有Finder/LaunchServices、物理键盘、像素等价、长测、第二台干净机器或性能优势结论；旧install-v1尚未自动安装新switch overlay。


## v6完整离线安装与恢复追加（2026-10-29）

从固定缓存新建CPU、overlay、graphics、App，真实受控SIGTERM保留原图形失败；重验复用CPU/switch后新图形目录重建并完成五阶段。被接受builder记录144条构建/验证命令；独立5722文件读验普通/-O摘要相同。观察器最初ps权限失败、接管孤儿退出码null、旧UNOBSERVABLE与后来的ABSENT分别保存，没有抹除失败。

本轮新产物32次ARM64 callback通过；原路径PID40550 steps1229/switch2，搬移PID40998 steps949/switch1，正常保存position/moves/draws=4/3/5→5/4/8；独立790文件运行读验普通/-O一致。属于直接bundle执行与工具OS事件，不是Finder/LaunchServices、物理键盘、像素、长测或性能验收。

新installer27项（每模式含1个受控Python锁child）与reader13项普通/-O通过；源码默认队列126项。完整证据、实际失败与复现入口见 [验收记录](docs/MIGRATION_INSTALL_V2.md)。公开源码检查不是另一台干净机器native验证，原始现场不随源码发行。

## 公开源码独立目录完整复现（2026-11-02）

构建来源为公开提交 `99a271db68ab97c059af376ce4bd5ecca8bb79a1` 的499文件，从本地Git archive导出并逐项核SHA/大小。既有固定CPU/图形缓存、同一M2/Python/Xcode/SDK下新建CPU、switch、graphics provider和v6 App，未把旧已安装provider作为本轮构建。固定输入仍为 `examples/window-switch/switch_tile.exe`，新identifier为 `org.peaotlab.publicrepro39cfa624.v1`。

| 验收 | 实际结果 |
| --- | --- |
| 完整安装 | CPU41、switch5、graphics29、App69，共144条被接受命令；五阶段首次完成，本轮没有安装恢复/重试。 |
| 独立静态核对 | 正式reader普通/-O逐字节一致，实读5459文件；额外标准库审查实读1700文件，核对实际命令和新provider/产品来源。 |
| callback | 两PE基址×O0/O3×8位置，共32次真实ARM64 callback；没有重跑原始x86 oracle或将其计成32次App。 |
| 新App正常运行 | 原路径PID4630、搬移PID4688均退出0、TEST_QUEUE=0、proc_translated=0；steps/switch为1165/2与917/1，存档position/moves/draws为4/3/5→5/4/8。790文件运行reader普通/-O一致。 |

首次PID4433因桌面绑定调用超过600秒监督期限而超时，返回-15，没有方向键输入；之后的同路径PID4571经精确身份核对后单独终止，OS退出码null、启动原因未证实，存档仍为空。后续正常运行使用新证据目录，不覆盖首次失败。两轮成功来自Cocoa系统自动化事件，不是物理键盘、Finder/LaunchServices、像素等价或长测验收。

详情与证据摘要见 [完整复现报告](docs/PUBLIC_REPRODUCTION_V1.md)。本轮证明同机公开源码配合既有固定缓存可新建并运行，不是网络clone、冷获取、第二台干净机器或App二进制逐字节可重复构建；约1303.884秒的一次构建耗时也不是运行性能结论。

## 新v6前置诊断单独验收（2026-11-02）

当前发行另追加5个 `migration_doctor_v1` 文件及2份报告，共506文件；doctor不属于上述499文件构建版本。实现测试与独立反例各14方法、普通/-O通过，公开副本的14项测试另已两模式通过；本轮没有重跑旧126项队列。

实际正例11PASS、退出0；负例损坏临时CPU缓存和不存在PE产生7PASS/3FAIL/1SKIPPED、退出2，图形缓存仍独立通过，work-root/out均未创建。两次诊断各9条Apple发现查询，共18条，没有编译、guest或App运行。独立审查最终轮含4个隔离Python CLI child验证有/无 `-B` 的字节码行为；较早4个另保留，不称全mock或零进程。

使用 `-B` 时只读项目文件和字节码；Apple工具可能更新系统缓存。11组只报告前置观测：现有实现清单不保证全部资源完整，doctor源摘要不证明加载代码或全程不变。见 [诊断验收](docs/MIGRATION_DOCTOR_V1.md)。下一项是固定CPU/ABI工作负载测实际命中与成本，干净机器和性能仍未验。


## CPU回调测量工具与首轮采样（2026-11-02）

新增 `window_callback_bench_v1` 使用既有正式产品的真实ARM64 WndProc对象和相同事务引擎；prepare两基址/O0/O3×8位置共32例完整状态相同。measure两基址实际执行790736次回调，其中计时786432次、未计时4304次，384原始批次和16计时末态独立读验通过；4047文件身份检查普通/-O结果同字节。独立报告SHA为 `d996750d695c37615154153f40529e73ab91fef0937d056af692560cb4e52244`。

runner10项与reader26项反例普通/-O通过；公开源码副本相同36项测试亦分别通过，未重新启动native基准。完整范围、复现入口与证据摘要见 [本轮报告](docs/WINDOW_CALLBACK_BENCH_V1.md)。

7条CPU>wall逆差166–500ns（wall报告分辨率1000ns）及最大wall/CPU约4.013的扰动原样保留，`CLOCK_ANOMALY_REQUIRES_REVIEW`未关闭。只能验收工具、正确性和原始采样；不称严格双时钟/稳定性能已验，不扣reset，不证明ABI/App/FPS或优化收益。下一批先改进计时/配对协议，再验证指令查找候选；旧前缀快路径没有集成到本次产品。
