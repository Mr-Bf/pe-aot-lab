# 有限 switch 正式窗口集成验收

验收日期：2026-10-29。实际环境为本机 Apple Silicon M2／macOS；没有使用 Windows 实机或第二台干净机器。当前结论是继续固定目标 AOT 开发，有限单表叶函数已接入正式窗口链；尚无通用游戏兼容或整体性能优势结论。

## 本轮能力状态

| 层 | 状态与实际证据 |
| --- | --- |
| 代码 | schema2 profile、显式 `window-rel32-v1` provider overlay、全根证明、版本化 lifter/producer/package、同Context窗口事务及 `migration_v6` 已实现。 |
| 构建 | `provider-02` 5条命令；`app-04` 69条实际命令全部退出0，包括两根O0/O3对象、独立C3 shim、六个宿主单元、链接、签名、打包及搬移静态校验。图形复用此前固定provider，本轮未重编LLVM/DXMT图形链。 |
| 正确性 | 新旧门禁、header绑定、helper ABI、flags及运行监督共86项普通/优化模式通过；真实事务旧/新模式各O0/O3/ASan+UBSan共6进程通过。真实WndProc两基址×O0/O3×8位置共32次执行，状态/全映像/64KiB栈及commit trace在同基址的优化模式间一致。 |
| 整链集成 | `app-04` 原路径和字节一致的搬移副本各一次真实Cocoa输入、保存和正常退出；独立790文件复核普通/优化摘要一致，另一次只读复核重算实际proof/IR/header及源身份。 |
| 性能 | 未验。此次没有FPS、长时稳定性、像素逐字比较、Wine＋Rosetta同场景或游戏负载测试。 |

## 真实输入与契约

自产PE为 `examples/window-switch/switch_tile.exe`，SHA256 `39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`。entry RVA为0x1140，callback为0x1000。真实RIGHT路径在0x111c执行CALL至0x1c30；leaf含67B、25条指令及0x2610处32B只读signed-rel32表。返回值经AND7实际改变位置，随后用于绘制与20B存档。边界位置7同样执行switch，但不多记移动。代码、COFF重定位、种子和返回消费均有原字节复核。

Profile仅声明leaf入口；不允许配置table/targets授权执行。所有main/callback先完整decode，再从全根候选提取leaf并独立解码原PE字节、证明guard/flags/闭包/只读范围/表和目标边界。跨根只允许DIRECT CALL进入leaf根，禁止任何外部边、callback或root进入leaf内部。逐root proof、规范化指令表、header、原PE身份及preferred base均精确绑定。

窗口runtime仍保留IAT/COM、回调和真实CALL/RET。全部region注册后绑定原表、exact READ页权限及有序目标，失败永久禁止执行；kind5不改变调用深度，成功事务才增加switch计数。LLVM switch按trace入口的运行地址差规范化selector，事务和故障保留真实PC。

限制为单表、单个无imports/calls/stores的scalar leaf、2..32表项、一个非`.reloc`且无DIR64的READ数据节（≤64KiB）及32KiB代码范围。可信单线程宿主须保持绑定后backing/权限稳定。这不是一般computed goto、函数指针、动态代码或恶意宿主防护。

## 两轮真实 App

两轮直接启动最终Bundle可执行文件，argc=1；不是Finder/LaunchServices启动。输入由桌面工具发出Cocoa系统事件，TEST_QUEUE始终0，不声称物理键盘或原始OS事件追踪。操作转录与实际PID/路径/运行结果分别保存。

| 项目 | 原路径 | 搬移后同档恢复 |
| --- | --- | --- |
| PID | 17648 | 17757 |
| 事件 | Right, Right, Left, Escape | Right, Escape |
| ARM身份 | proc_translated=0 | proc_translated=0 |
| guest步骤 | 1197 | 917 |
| 实际switch提交 | 2 | 1 |
| 最终position/moves/draws | 4 / 3 / 5 | 5 / 4 / 8 |
| 本进程Draw/Present | 5 | 3；draws=8为存档累计值 |
| 保存字节 | `434f573101000000040000000300000005000000` | `434f573101000000050000000400000008000000` |
| 退出 | host/guest正常、无超时或强制清理 | host/guest正常、无超时或强制清理 |

独立reader读取790个文件、核对641个产品文件的集合/摘要/模式，核对实际dyld路径和UUID、wrapper、PID、键盘来源、guest状态、switch计数和存档连续性；普通与`-O`输出完全一致。另一只读审查从app-04原PE重算全根proof、对实际lifted.ll重新retarget、逐字重生成header，并核对宿主与runtime编译输入，未借用旧App成功。

## 真实 callback 与失败反例

`callback-probe-02` 链接实际WndProc O0/O3对象与真实窗口transaction/new switch hooks，在0x140000000和0x180000000各对位置0..7执行：共32次，全部符合RIGHT饱和移动、moves/dirty及Win64非易失寄存器契约。每次恰1 CALL、1 switch、2 RET，最终深度0；API拒绝stub调用0。110个实际编译依赖、生成header及复制对象前后摘要一致。

该探针的COM/IAT为拒绝stub，RIGHT路径无API；它不代替两轮真实App，不是32次App运行、原x86差分、GPU或性能验收。

保留的失败/修复包括：首次样例验证脚本错误；app-01打包误用旧provider loader；header中间表/proof/PE身份关联缺口及其失败回归；初版switch用preferred常量匹配动态PC。旧app-03真实负对照为16次preferred成功、16次rebased故障6，另存 `callback-probe-old-rebase-01`，未计入新32次或补写新源码SHA。修正selector规范化后重建provider-02/app-04并重新执行。

## 可复查证据

以下为本地原始记录标识，公开源码不上传完整实验现场。摘要只是定位记录，不能替代原始内容审查。

| 记录 | SHA256 |
| --- | --- |
| `build/window-switch-v1/app-04/result.json` | `6fed15c8b1e352d8b5983a55c5f7f1f15f3112b99ef0525fdd341eb5bee261fd` |
| `build/window-switch-v1/provider-02/result.json` | `15b4bdb5c879b895cfd378ecc790d5b7f5ebb12603bf70ebb5cb40296a6fdc6b` |
| `build/window-switch-v1/callback-probe-02/result.json` | `453c18f9cc4bd544a01bf9a2099404d8e90f73e36be4cf81eeca23d435f14aab` |
| `build/window-switch-v1/callback-probe-old-rebase-01/result.json` | `dddf067ee55f0beba7fd247f3abd1fe21dacc24049b31006670d2e0f7d71c7af` |
| `build/migration-run-v3/roundtrip-review-01.json`及优化版 | `8ecf00d8656b9e9881660d66dae8c92dc164c5fa6779d4f5d1d84fdb276e35f0` |
| `build/window-switch-runtime-v1/final-readonly-01/result.json` | `e229e5ba79ac165a184f7b8ee9c29b4caff6fd88b0626add492ef7008f85752f` |

复现构建命令见 [window_switch_v1](../window_switch_v1/README.md)，实际运行及独立reader见 [migration_run_v3](../migration_run_v3/README.md)，自产PE准备及旧provider实际拒绝见 [fixture](../switch_window_fixture_v1/README.md)。保持输出目录全新，不覆盖失败。

## 下一开发项

优先把v6及switch provider overlay纳入完整离线install计划/构建/失败恢复，避免要求调用者手工拼接三个provider角色；旧install-v1仍是原profile，不从本轮App成功继承正常运行。随后验证公开源码完整native复现与独立干净环境，再扩大真实输入并根据热点做性能优化。通用CRT/TLS/SEH/SIMD/并发、图形资源和真实游戏仍需各自验收。
