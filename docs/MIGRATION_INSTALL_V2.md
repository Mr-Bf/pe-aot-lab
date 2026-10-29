# v6 完整离线安装与恢复验收

日期：2026-10-29。v6完整离线安装及受控失败恢复已在本机Apple Silicon M2／macOS实际通过，新产品的32次ARM64 callback与原路径/搬移两轮真实Cocoa存取档也已验收。结论仅覆盖固定自产输入、既定缓存及同一主机；没有干净机器、真实游戏或性能优势结论。

## 实现范围

新入口 `python3.13 -B -m migration_install_v2 plan/install/resume` 从固定缓存串联普通CPU、window-rel32-v1 overlay、图形provider、v6 App及静态verify。旧v1保持原profile合同。本轮改变安装与恢复流程，不新增CPU指令、Windows API、图形格式或游戏兼容范围。

阶段只在实际provider/源码树/收据/返回值及父角色绑定通过后正式接受；状态索引不能代替验证。CPU与graphics的外层receipt形式不同于switch overlay，分别校验。产品绑定冻结原PE、原始profile文本SHA与规范化profile字节SHA、spec、实际overlay及graphics身份。

失败目录不覆盖。成功provider保持绝对位置，恢复分配新的失败stage序号，并重验输入、缓存、Apple SDK/工具、实现与资源闭包。不同源码版本、SDK或输入不共用旧完成阶段。

worker以独立session/PGID运行，继承同一安装锁FD；调用builder前排他、原子、持久注册身份。协调器退出只close自身FD，不能显式解开仍被worker继承的共享锁。恢复同时要求取得原锁inode和实际观察历史进程组消失；未知/活进程组、缺锁或不明未注册产物均拒绝重试。合同不支持daemonize或逃离其进程组的builder。

## 已有测试证据

- 新安装器27项普通/优化测试通过，源码前后摘要一致。每模式包含一个真实短Python子进程，验证生产取消/finally路径关闭父FD后继承锁仍阻止恢复；其它阶段使用合成builder，无native/App/GPU。
- 独立reader的13项反例普通/优化通过，不调用runner的成功判定。包含伪造worker/parent/capability、frozen身份、journal/组/锁、source patch重放、实际产物配方、Python可执行路径别名及attach孤儿退出码约束。
- 旧v1的19项普通/优化回归通过；不把旧完整App成功转移到本轮新产品。
- 源码默认测试队列为126项：旧scalar/window/run的86项、新installer27项、独立reader13项。公开导出另外保存资源闭包与CLI检查，不把它们算成native安装或第二台机器验收。

## 当前真实实验

实际输入仍为本项目自产窗口PE `39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`；新标识 `org.peaotlab.installv2switch39cfa624.v1`。使用原固定CPU/图形缓存，在新 `pe-aot-fresh-06/work/install-01` 内重建，没有使用此前已安装provider充当新构建。

| 步骤 | 当前实际证据 |
| --- | --- |
| 只读plan | 输入/缓存/Apple工具/空间通过；302个实现文件被固定；plan未创建安装输出。 |
| 首次CPU | `full-01/attempts/cpu-build-0001` 已正式接受；provider SHA `6b558185bfd18637eb386c1e81ea1b02dc0705dd1f3db4356c399423036db269`。 |
| 首次switch | `switch-build-0001` 已正式接受，依赖该CPU原路径；provider SHA `8d2d4945ae52aca9c3e5cc47f9a2b8354981789517d210a7d734762e6a224166`。 |
| 首次图形 | worker25754被受控SIGTERM；原失败结果保留，未覆盖。 |
| 恢复 | `resume-01/revalidated.json`重新验收并复用CPU/switch；图形改用 `graphics-build-0002`，实际重编LLVM15/DXMT并正式接受。 |
| 最终App与验证 | 新 `app-build-0001` 实际生成O0/O3对象、宿主和完整App，随后独立worker静态verify；五阶段全部完成。 |
| 构建命令 | 被接受阶段CPU41、switch5、graphics29、App69条命令全达到预期，共144条；不含失败图形的部分命令、协调器预检或Python worker启动。 |
| 安装独立读验 | 普通/优化逐字一致，实读5722文件、核对641产品文件与69条App命令；从固定archive重放源码/patch，重算proof/IR/header并核对真实Mach-O。 |
| 新产品callback | 两PE基址×O0/O3×8位置共32次真实ARM64执行，完整State/image/stack及trace一致；API为拒绝stub，单独于App/GPU验收。 |
| 新App两轮 | 原路径与字节一致搬移副本均直接Bundle executable/argc=1启动，以真实Cocoa系统事件输入、同档恢复、保存并正常退出；独立790文件复核通过。 |

首次中断观察器的`ps`查询被sandbox拒绝，观察器退出时安装协调器21637与图形worker仍运行。root以有权限的只读`ps`确认原PID/PGID/父子/job/编译命令后，使用独立attach观察器接管现有构建，未重启CPU/switch或另建安装。SIGTERM只发向该图形组；原worker-exit为-15，原失败JSON固定SHA `64bea95fc94359cf042059d329b22853ccfc3c14d32fd14d4117104d5720f05f`，随后确认两个旧组均ABSENT。

协调器成为孤儿后不是attach的child，退出码未被wait取得，明确记录为null；不由源码分支推断成实际OS退出码1。原观察失败、原失败安装与attach结果分开保留。恢复前新增实际历史组观测，不能把后来的ABSENT回填原worker-exit时的UNOBSERVABLE。两处安装结果与全部失败目录保留，不借用旧App或旧安装provider的成功。

## 新产品实际运行

| 项目 | 原路径 | 搬移后同档恢复 |
| --- | --- | --- |
| PID | 40550 | 40998 |
| 输入 | Right, Right, Left, Escape | Right, Escape |
| guest步骤／switch提交 | 1229／2 | 949／1 |
| 最终position/moves/draws | 4／3／5 | 5／4／8 |
| 本进程Draw/Present | 5／5 | 3／3，draws=8为存档累计 |
| 保存20B | `434f573101000000040000000300000005000000` | `434f573101000000050000000400000008000000` |
| 实际结果 | host/guest正常退出、proc_translated=0、TEST_QUEUE=0、无超时/强制清理 | 同左 |

输入由桌面工具发出OS事件，不是物理键盘或原始OS追踪。第一轮退出键首次遇桌面状态变化提示；先以OS查询确认同PID仍活、刷新既有handle后再发退出键，没有重复启动。两轮Cocoa焦点等系统消息会改变guest步数；不能拿它与旧App的步数或墙钟时间比较性能。

运行结果、原始stdout/stderr、dyld路径/UUID、wrapper、实际PIDs与Cua操作转录各自保存。第一次reader因转录policy字段少一个字而拒绝；旧转录备份和失败原因保留，仅把声明改为实际已经执行的“等待监督器后非激活listApps”字面规范，PID、事件与操作没有改写。修正后普通/优化独立复核逐字一致。

另保留首次运行命令在错误证据父目录处被预检拒绝（没有启动App），以及安装reader首次把指向同一Python文件的路径别名误判为不同程序的失败。reader改为解析到相同目标并核SHA、补回归后重验；生产安装器和本轮产品均未修改。

## 关键记录

| 文件 | SHA256 |
| --- | --- |
| `resume-01/result.json` | `9e97eccc69ec2a31a9c9143f982715cdc337f7ef99c60c79419208298ec0acd9` |
| 新产品 `result.json` | `2f7b09f9736d6402dac223df4279f817e60c45852dcdd23a09ca0a4acb535837` |
| `independent-review-02.json`及优化版 | `3a591e080af2f1a94b6f12ac1dfb5b608a072ec00c5f6097c131ff1ffcde9eba` |
| `callback-probe-01/result.json` | `68d19db8b81113e68116484c24ccfbce0b424d88fbe578ade4a938dbb93e215d` |
| `runtime-review-02.json`及优化版 | `f4faa687a087e28fcea277e20d02d32d92496f7841756e0a57b5d48e18887d9e` |

上述相对文件位于 `build/migration-install-v2/`；两轮运行原件位于 `build/migration-run-v3/install-v2-{original,relocated}-01/`。产品位于新work-root的 `attempts/app-build-0001/`，完整命令、失败与source副本保留本机，不随公开源码上传。摘要用于定位，不替代读验原始记录。

## 复现入口与边界

一般plan/install/resume命令见 [安装器README](../migration_install_v2/README.md)。显式中断实验模块为 `migration_install_v2.recovery_probe`，接管模块为 `recovery_attach`；只用于核对所属进程后的受控实验，权限不足时保留未知状态，不能重启未确认结束的builder。

最终只读验收入口为 `migration_install_v2.review --installation ... --session ... --probe ... --out ...`。本轮真实新App另经 `migration_run_v3` 验收。当前没有Finder/LaunchServices、干净机器、真实游戏、像素等价、长测或性能优势结论。

下一项是公开源码从独立新目录完成整链native复现并完善诊断；随后以明确热点和原始字节/状态差分为前提推进性能优化。继续扩大ISA/ABI/图形范围与实际游戏迁移均有独立验收门槛，不由一次完整install推断。

锁与进程接口依据：[Apple flock](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/flock.2.html)、[Python subprocess](https://docs.python.org/3.13/library/subprocess.html)。
