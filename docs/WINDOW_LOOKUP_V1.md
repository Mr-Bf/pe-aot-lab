# 指令查找优化的版本化生产接入

本批已将前批验证的固定指令查找实现接入新的 `migration_v7`，生成并实际运行独立 ARM64 App。69 条构建命令、1488 次回调内核执行及完整预算检查、原路径和搬移路径的两轮 Cocoa 存取档均通过；三层独立 reader 在普通／`-O` 模式结果分别一致。正式运行时接入已验，本批没有测量 App 或游戏性能。

本轮输入仍是自制 Windows x86-64 PE `examples/window-switch/switch_tile.exe`，SHA256 为 `39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`。没有加入商业游戏、Steam SDK、DRM 或反作弊处理。目前不需要用户安装或登录 Steam。

## 技术变化与保持的契约

`window_lookup_v1/runtime.py` 固定三份源文件身份：旧 `runtime.c`、旧 `transaction_v1.c` 和新 `lookup_impl.inc`。生产器在本次产物的 `native/runtime-source/window_bridge/window_runtime/` 下生成两个 C 文件。`runtime.c` 与旧模板逐字节相同；`transaction_v1.c` 只将唯一的 `instruction()` 函数替换为已验证的内联二分查找。候选实现与前批 `window_callback_single_v1/lookup_impl.inc` 字节一致，SHA256 为 `ebb0a1a8ffa6be1df541b01645dc0a4629b4fb9ad3888def4082eb7c320c3ea0`。

原实现通过通用 `bsearch()` 和比较器寻找指令起始 RVA；新实现直接比较有序 `AotInstruction.rva`。低于模块基址、超出 32 位 RVA 或没有精确起始地址仍返回空指针。构造器继续排序并拒绝重叠、非法长度、越界和非法类别。Context 布局、权限检查、每指令完整 State 快照、故障回滚、预算、CALL/RET、有限 switch、已有宿主TLS 与外层回调 ABI 均保持原代码。运行时没有策略选择器，也没有取消快照。

六个宿主编译单元中，只有 runtime 单元改用生成的 C 文件，并在原参数后加入 `-iquote` 指向原 runtime 目录，使其余相对头文件与 include 按原来源解析。编译器依赖清单必须实际包含两个生成 C 文件并排除原 runtime/transaction 编译源码。生成位置、模板、查找实现与生成文件哈希写入 `native/runtime-source/runtime.json`，再由 producer 和 product 的相同 `runtime_lookup` 描述绑定。

新产品类型为 `window-lookup-v7`；PE profile 保持 schema2／`win32-d3d11-tile-switch-v1`。新生产器复用原提升、图形 provider 验证及打包逻辑，重新生成提升对象、六个宿主对象、可执行文件和 App。原 `migration_v6`、旧 producer、旧运行工具及既有回执均不修改。

静态门禁不只检查自洽哈希：它要求 overlay 位于本产品的 `native/runtime-source`，核对实际 runtime 编译源码／编译器／完整参数、原始 `.d` 与记录一致，并确认 manifest、三份模板及两个生成 C 文件均在相同的编译前后身份清单内。独立 reader 使用标准库重新构造预期替换，读取实际命令、对象和包内代码，不导入生产 validator，不运行 native 或 UI。

## 本轮已取得的证据

| 层次 | 当前结果 | 验证边界 |
|---|---|---|
| 代码与源码门禁 | 已实现；22 项生产测试普通／`-O` 通过 | 15 项 runtime、7 项产品绑定；无 native 执行 |
| 新回调采集脚本 | 8 项纯 Python 测试普通／`-O` 通过 | 包括接口合同、完整 State/Context 与后部预算记录篡改、截断／追加拒绝 |
| 新 App 运行适配 | 24 项纯 Python 测试普通／`-O` 通过 | 新 `migration_run_v4` runner／reader，保留单进程、退出和存档约束 |
| 新静态／callback 独立 reader | 32 项纯 Python 测试普通／`-O` 通过 | 源码变换、命令环境、Mach-O符号、依赖与源码闭包反例 |
| 构建 | `app-01` 成功，69 条内部命令；约 22.73 秒 | 复用已有 CPU／图形 provider；不是重建工具链或运行速度测量 |
| 静态独立复核 | 普通／`-O` 均通过，650 个产品文件、3806 个独立文件身份 | 源码变换、真实编译、runtime 对象无 `_bsearch`／实验选择器、打包代码段不变 |
| 新产品 callback／预算 | 32 份正常完整输出、1456 份完整预算记录，共1488次回调；5148文件独立读验 | 两基址 × O0/O3，新提升对象及实际生产 transaction；逐字节比较前批已验候选；无计时 |
| 原路径及搬移 App | 两进程正常退出，存档连续；805文件独立读验 | 真实 Cocoa 输入、正 switch 计数、实际绘制与释放、保存／恢复；TEST_QUEUE=0 |
| App／游戏性能 | 未验 | 不由 CPU 子组件结果或构建时长推导 |

最终测试共86项（22＋8＋24＋32），普通／`-O` 均通过，见 `build/window-lookup-v1/unit-02/`；此前54项集合保留在 `unit-01/`。纯 Python 测试没有启动 native 或 App。新回调每配置另执行53个查找边界context、169987次查询；查询次数不计为guest回调次数。

产品 `build/window-lookup-v1/app-01/result.json` SHA256：

```text
cd28493d3f7f3afd3851af9586cbb7d79a44250801c40df73f73f2815924419a
```

最终 `product-review-ordinary-03.json` 与 `product-review-optimized-03.json` 内容一致，SHA256 均为：

```text
4082cebd257fb7f5fbe6cfa8bfdf0a9cba27779b34869d1c6725feb4fe4368ea
```

本次 identifier 为 `org.peaotlab.inlinelookup39cfa624.v1`。CPU provider 来自 fresh07 的 `switch-build-0001`，图形 provider 来自同次安装的 `graphics-build-0001`。本次验证的是已有 provider 被新 App 正确消费，不能声称本轮重新执行了 LLVM／DXMT 完整安装或干净机器复现。

`probe-01/result.json` SHA 为 `f08e27c45f5968a79685ec487bf77fdb6ccf0341c26da480c283cbfeeb01d192`；两模式 callback reader 同为 `0e9f15e385eeaa42986ec25077227f0c367bf28b7b6f062df2aca631e22e64cf`。预算记录保留全部3504B State、20480B映像、65536B栈与5792B规范化Context，含故障前缀；不只比较摘要或通过标记。副本对象显式绑定新产品原对象，结束时重新校验已接受参考的全部文件身份。

实际 App 记录位于 `build/migration-run-v4/`：

| 运行 | PID／退出码 | 实际事件 | guest步数／switch | 保存结果 position／moves／draws |
|---|---|---|---|---|
| `original-02` | 19489／0 | Right、Right、Left、Esc | 1229／2 | 4／3／5 |
| `relocated-01` | 19561／0 | 恢复同档后Right、Esc | 917／1 | 5／4／8 |

两轮均使用 App 内 ARM64 可执行文件、无额外参数，`proc_translated=0`，未依赖 Rosetta执行。本轮直接启动可执行文件，不是 Finder／LaunchServices 验收。第二轮带空格搬移路径的冻结读档逐字节等于第一轮保存结果；真实Cocoa事件、guest观察、保存字节及图形计数互相核对，未注入 TEST_QUEUE。截图观察到绿色方块相应移动；没有做全像素等价验证。`cua-actions.json` 是实际工具结果转录，不是原始OS输入trace或物理键盘证明。

两模式 `roundtrip-review-*-01.json` 同为 `6376b172b43bd15aa2641f7d63d977f4f942b57846b01ea6f34bc23d0d9a46ee`。两进程都已经退出，无额外实例。该新版运行 reader 仍限定当前15.2部署契约；静态 reader 能按provider声明核对更高最低系统版本，不代表运行reader已泛化。

## 审核发现与失败保留

- 生产验证最初只验证 overlay 描述自洽，可能把另一个产品的同内容 overlay 当成本次来源。审核后增加本产品固定路径、编译前后输入及实际源码／参数／依赖绑定，并增加拒绝测试；修复在本次正式构建前完成。
- 首次开发测试修改临时 manifest 时误用了独占写函数，产生 `FileExistsError`。测试改为明确覆写临时测试文件，普通／`-O` 重跑通过。此错误没有触发 App 或 native 执行。
- 新 callback 采集脚本在 native 执行前发现两个接口不匹配：既有准备 reader 返回二元组；既有依赖解析器要求 `pair:` 目标名。接口适配与两项测试已补齐，没有把未执行算作成功。
- 首次实际静态 reader 报 `ValueError: command context differs`。原因是 reader 对命令上下文／环境记录的假设不符合两层记录方式：内层记录请求的覆盖项，外层 Recorder 记录合并固定默认值后的有效环境。修复为精确检查两者关系，并保留错误环境与错误 cwd 的拒绝测试。首次失败记录保存为 `build/window-lookup-v1/product-review-failure-01.json`；它是实际工具错误的转录，初次 shell 没有另存独立 stderr 文件，不声称原始 stderr 已保存。生产代码和已成功构建的 App 没有因 reader 修复而重建或改写。

- reader 的 `02` 两模式输出保留，但采集期间reader仍有收紧修改，不能保证当轮加载代码与记录源码完全一致，不采用为最终证据。最终用精确核对六个外层附加环境变量的冻结 reader SHA `a50f5cc09eba8628c07c1860b769a91e24b430cdb77280cc46688b3ad9d32c8e` 重跑 `03`；旧 `02` 保留，不作为最终验收。
- App `original-01` 在启动前因沙箱禁止 `/bin/ps` 失败，PID为空、没有App执行；原 `evidence.json` 保留。获得执行权限后在新 `original-02` 完成正常运行，未覆盖旧失败。
- 首次写入UI动作转录时误读不存在的 `result.json`；监督器实际文件名为 `evidence.json`。查明后从真实记录填写转录，两轮App与存档均未改写或重跑。

## 可复查命令

以下命令从仓库根目录执行。本机路径是本批真实环境，不是可搬移的全自动安装命令。已经存在的输出不可重跑覆盖；复现实验须选择新输出目录，并使用新产品回执 SHA。静态构建不会启动 App。

```sh
python3.13 -B -m migration_v7 build examples/window-switch/switch_tile.exe \
  --profile examples/window-switch/profile.json \
  --identifier org.peaotlab.inlinelookup39cfa624.v1 \
  --cpu-prefix /Users/feng/Documents/Codex/pe-aot-fresh-07/work/install-01/attempts/switch-build-0001 \
  --backend-prefix /Users/feng/Documents/Codex/pe-aot-fresh-07/work/install-01/attempts/graphics-build-0001 \
  --out build/window-lookup-v1/app-01

python3.13 -B -m migration_v7 verify build/window-lookup-v1/app-01

python3.13 -B -m window_lookup_v1.review \
  --product build/window-lookup-v1/app-01 \
  --product-receipt-sha cd28493d3f7f3afd3851af9586cbb7d79a44250801c40df73f73f2815924419a \
  --out build/window-lookup-v1/product-review-ordinary-03.json
```

新 callback 检查消费本产品新提升的 O0/O3 对象和本产品生成的 transaction，使用冻结的单策略 CPU harness，与前批已验候选逐字节比较正常输出、规范化 Context 及每个预算前缀。它不执行完整外层回调 ABI、Cocoa 或 GPU，不进行性能计时。

`--accepted` 需要按[前批说明](WINDOW_CALLBACK_SINGLE_V1.md)本地生成的受验准备目录及其依赖；公开源码不包含本机的大体积原始产物。仅clone仓库不会自动拥有此目录。

```sh
python3.13 -B -m window_lookup_v1.probe \
  --product build/window-lookup-v1/app-01 \
  --accepted build/window-callback-single-v1/prepare-01 \
  --out build/window-lookup-v1/probe-01

python3.13 -B -m window_lookup_v1.probe_review \
  --product build/window-lookup-v1/app-01 \
  --product-receipt-sha cd28493d3f7f3afd3851af9586cbb7d79a44250801c40df73f73f2815924419a \
  --probe build/window-lookup-v1/probe-01 \
  --accepted build/window-callback-single-v1/prepare-01 \
  --out build/window-lookup-v1/probe-review-ordinary-01.json
```

App 运行按两轮顺序执行。出现 `LIVE_NATIVE_APP_PROCESS` 后，由外部 UI 操作绑定已有 PID，发送真实 Cocoa Right 等事件并正常退出；监督器不会自动操作窗口或注入 TEST_QUEUE。第一轮必须完成并保存证据后才能运行第二轮。实际动作转录由完成后的工具结果填写，禁止预先写成成功。

```sh
python3.13 -B -m migration_run_v4 \
  --product build/window-lookup-v1/app-01 \
  --out build/migration-run-v4/original-02 --timeout 600

python3.13 -B -m migration_run_v4 \
  --product build/window-lookup-v1/app-01 \
  --out build/migration-run-v4/relocated-01 --relocate --timeout 600

python3.13 -B -m migration_run_v4.review \
  --product build/window-lookup-v1/app-01 \
  --product-receipt-sha cd28493d3f7f3afd3851af9586cbb7d79a44250801c40df73f73f2815924419a \
  --run build/migration-run-v4/original-02 \
  --run build/migration-run-v4/relocated-01 \
  --out build/migration-run-v4/roundtrip-review-ordinary-01.json
```

各 reader 再以 `python3.13 -B -O -m ...` 写入另一全新输出，比较结果。纯 Python 测试入口如下；reader 的测试另列，最终数量以实际测试回执为准。

```sh
python3.13 -B -m unittest \
  window_lookup_v1.test_runtime migration_v7.test_build \
  window_lookup_v1.test_probe \
  migration_run_v4.test_run migration_run_v4.test_review -v

python3.13 -B -m unittest \
  window_lookup_v1.test_review window_lookup_v1.test_probe_review -v
```

## 下一批开发与 Go／No-Go 边界

结论：**GO——保留新v7生产入口，进入完整外层ABI负载与工具集成；NO-GO——宣称通用游戏支持或App性能提升。** 新产品callback、预算、两轮真实App与独立复核已分别通过。前批单策略 CPU 组件中 16 个场景的配对中位耗时下降 5.9%–8.6%，属于[前批冻结实验](WINDOW_CALLBACK_SINGLE_V1.md)，本轮没有新增 App、FPS 或游戏加速结论。

后续任务按验收推进：

1. 完成完整外层 ABI 的固定负载与正确性差分，分离 callback 入口／TLS／save-restore、执行内核、导入和图形后端成本；保留完整状态与失败门禁。
2. 设计代表性持续负载和同条件基线，分别记录启动、稳态、输入、帧时间、CPU/GPU、资源和退出，不从人工交互时间推导性能。
3. 将 v7 接入新的 install／resume／doctor 版本，验证 provider 恢复、拒绝错误版本及搬移消费。本轮尚未完成这条接线；现有 install/doctor 不自动代表新 v7 入口。
4. 完成新 App 持续稳定性和更广开源输入，再固定合法单机目标、版本与资源许可。需要用户 Steam 游戏时再通知登录和交接文件。

通用 PE loader、一般间接控制流、多模块、动态代码、复杂 Windows 异常、线程／TLS、广泛 API／图形／Steamworks 兼容、干净机器和真实游戏性能仍是整体未完成项。本轮只推进已有受限窗口契约的生产集成，不据此关闭这些任务。
