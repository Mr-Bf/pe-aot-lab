# 公开源码独立目录完整构建与运行

日期：2026-11-02。公开提交 `99a271db68ab97c059af376ce4bd5ecca8bb79a1` 的 499 个文件从本地 Git archive 导出至独立 `pe-aot-fresh-07/source`，逐项 SHA/大小核对后，从既有固定缓存完整新建 CPU、switch、图形 provider 和 v6 App。构建、独立静态复核、32 次 ARM64 callback、原路径及搬移副本的两次正常 Cocoa 存取档均已通过。

这是同一台 M2/macOS、既有 Python/Xcode/SDK 和缓存的源码交付复现；不是联网冷获取、另一台干净机器、任意游戏兼容或整个 App 二进制逐字节可重复构建的证明。产物运行路径为原生 ARM64，实际两个成功进程 `proc_translated=0`；未测性能优势。

## 输入与构建来源

输入仍为自产 `examples/window-switch/switch_tile.exe`，SHA `39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`，使用 schema2 profile。新标识为 `org.peaotlab.publicrepro39cfa624.v1`。本轮不增加指令、API 或图形兼容范围。

公开实现固定 210 项资源；私有旧清单为 302 项，交集 SHA 一致，差集主要是未导出的历史实验资源。没有把旧的已安装 provider 充当新构建。CPU 使用固定 LLVM17 预编译工具包并重新编译 Remill/XED 等依赖；图形 LLVM15/DXMT 实际重新编译。

| 验收项 | 本轮结果 |
| --- | --- |
| 完整安装 | 五阶段首次全部成功，无本轮恢复/重试；CPU 41、switch 5、graphics 29、App 69 条被接受命令，共 144 条。 |
| 构建时间 | 外层监督记录约 1303.884 秒，即 21 分 44 秒；仅为本机 jobs=2 的一次构建耗时，非运行性能基准。 |
| 正式独立 reader | 普通/`-O` 逐字节一致，实读 5459 文件。静态结果不替代执行。 |
| 额外独立审查 | 标准库脚本实读 1700 文件，核对导出、冻结实现、144 条命令/原始输出、provider 角色和产品权限。实际命令未引用私有源码或旧安装前缀。 |
| 新 callback | 两 PE 基址 × O0/O3 × 8 位置，共 32 次真实 ARM64 callback；不是新的一轮原始 x86 差分或 GPU 测试。 |
| 成功 App 运行 | 原路径 PID 4630 与搬移副本 PID 4688 均正常退出；运行 reader 普通/`-O` 逐字节一致，核对 790 文件。 |

换源码目录后，旧 `OLD_WORK` 路径保护会随 ROOT 重新推导，不能独自证明隔离。独立审查额外检查了实际 argv/cwd/env 和新 provider 依赖：三次 App 解码使用 fresh07 overlay，实际链接使用 fresh07 图形库，CPU/GFX runtime、driver/semantics 均重新核 SHA。这是记录中的实际来源审查，不是 OS 全文件访问追踪。

## 真实运行与保留失败

首次监督 PID 4433 的桌面绑定调用耗时 700.0069 秒，超过监督期限 600 秒；监督器记录超时、返回 -15。没有发送方向键，不能算正常运行。之后出现的同路径 PID 4571 经 UID/路径/进程身份核对后单独 SIGTERM，确认消失，存档仍为空。它不是监督器的 child，OS 退出码记 null；没有独立证据确认其启动原因。

原失败记录保持原样。新目录 `public-repro-original-02` 重试时，bundle identifier 查询返回歧义，随后按精确 App 路径绑定已运行进程成功；未因此启动第二个受监督实例。两轮最终动作后仅等待监督器和非激活 listApps，未再 getApp/AX。

| 项目 | 原路径重试 | 搬移同档恢复 |
| --- | --- | --- |
| PID / 退出码 | 4630 / 0 | 4688 / 0 |
| 系统自动化输入 | Right, Right, Left, Escape | Right, Escape |
| guest 步骤 / switch | 1165 / 2 | 917 / 1 |
| 本进程 Draw/Present | 5 / 5 | 3 / 3 |
| 最终 position/moves/draws | 4/3/5 | 5/4/8，draws 是存档累计 |
| 保存 20B | `434f573101000000040000000300000005000000` | `434f573101000000050000000400000008000000` |

两轮 TEST_QUEUE 均为 0。输入来自桌面工具产生的 Cocoa 系统事件，不是物理键盘或原始 OS 输入追踪。运行 reader 重算存档连续性、PID/argv、wrapper、实际 dyld 路径/UUID、产品身份及正常退出。首次失败和额外实例清理不计入两次正常退出。

## 复现与记录

完整参数见 [安装器入口](../migration_install_v2/README.md)。正常首次安装完成时，独立 reader 的 `--installation` 和 `--session` 都指向本次安装目录；不要照抄恢复实验的 `resume-01`。App 路径取本次 `result.json` 的 `product`，运行与搬移使用 [运行器入口](../migration_run_v3/README.md)，不要沿用旧示例 `app-04`。本轮同时交付 [v6 只读诊断](MIGRATION_DOCTOR_V1.md)，它不替代真实构建。

主要证据位于本机 `build/public-reproduction-v1/`；运行原件位于 fresh07 源码根下 `build/migration-run-v3/public-repro-{original-01,original-02,relocated-01}/`。完整 native 产品、缓存和本机原始日志不随公开源码上传。

| 记录 | SHA256 |
| --- | --- |
| `install-01/result.json` | `f224e3a606c6cbe526a2adb69773d933787ebb5345d62f787995bb8bce28bec8` |
| 新产品 `result.json` | `bb66b1c7a8de5569c951d9570be3ccde5642d4eb47d1da7619c86b610abc073d` |
| `independent-ordinary-01.json`及优化版 | `1cbc3c1ca0c4e131ce4cbc1ec4b734d483e98d0bc9923abc492c4dbf78f61fee` |
| `peer-review-01/result.json` | `4f8b6f43337905a83e245278253852bb160fc016810ba96cfee5b6817147b784` |
| `callback-01/result.json` | `6ee0375dd9cab3d0fcc67197d5f1e15bf5c95bfb35cbcdfa6171a78ba62bda0e` |
| `runtime-ordinary-01.json`及优化版 | `698b93ad50826f7422e7fa4f98cd3764dd95cbcf8e6237434e10a269a6bfe821` |

下一项以本轮可交付构建为基线，固定可重复 CPU/ABI 工作负载，记录实际热路径命中与成本，再在状态/原字节差分门禁下优化。第二台干净机器、长时稳定性、Finder/LaunchServices、像素验收、实际游戏和 Wine/Rosetta 同场景性能仍分别待验；不再把同机公开源码整链构建列为未完成。
