# v7 离线安装、恢复与前置诊断

**本批完整离线安装、受控恢复和新 App 两轮运行通过。** 新 `migration_install_v3` 从固定缓存新建 CPU、switch、graphics 和 `window-lookup-v7` App；实际 App 编译阶段受控中断后，重验复用前三阶段并在新 attempt 完成。安装独立读验读取5514个文件身份，运行独立读验读取805个文件身份，各自普通／`-O`报告逐字节一致。`migration_doctor_v2` 的12组正例与拒绝负例、80项新模块测试通过。首次 App 监督超时和额外实例清理单独保留，不计为正常运行；本批无 App／游戏性能结论。

本轮输入仍为自制 `examples/window-switch/switch_tile.exe`，SHA256 为 `39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`。输入 profile 仍是 schema2／`win32-d3d11-tile-switch-v1`；没有扩大 PE、Windows ABI/API 或图形兼容范围，没有商业游戏、Steam SDK、DRM 或反作弊处理，目前无需 Steam 账号。

## 来源与本轮安装范围

本轮执行源码位于 `/Users/feng/Documents/Codex/pe-aot-install-v3-01/source`，由本地公开版提交 `ede6d8d636864db7c4dae52f8ddd19c9d41f2da8` 的564文件，加上本批14个新模块文件构成，共578文件、5,391,126字节。新增文件属于 `migration_install_v3` 与 `migration_doctor_v2`；这是公开基线加本地新代码的冻结副本，**不能将该来源记录称为已推送的新版本或网络 clone**。本报告及后续开发入口文档不属于此次578文件构建快照；最终公开发行树另有清单，文件数不能与构建源混用。

源码清单位于本机任务目录的 `work/install-v3-source-manifest-01.json`，SHA256：

```text
c1bef50a459f19cf6e7cce57b14eccf06b91d42573a47bff361651f2ae38bd0c
```

两份固定缓存分别来自任务目录 `work/public cpu cache moved 01`、`work/public graphics cache moved 01`。缓存归档可复用；本轮没有把旧安装好的 provider 当作新构建。CPU base、switch overlay、graphics provider 都分配在全新 `/Users/feng/Documents/Codex/pe-aot-install-v3-01/work/attempts/` 下，通过真实 builder 生成后才能接受。CPU 使用固定缓存里的预编译 LLVM17 工具包，Remill/XED 等依赖及图形 LLVM15/DXMT 另行编译；不能声称所有第三方工具均从源码重新编译。

实际安装 identifier 为 `org.peaotlab.installlookup39cfa624.v3`，初始协调证据在 `build/migration-install-v3/install-01`，受控实验在 `interruption-01`，实际恢复证据为 `resume-01`。这些 `build/` 路径均相对私有项目仓库，实际参数由 `work/install-v3-run-arguments-01.json` 和 `build/migration-install-v3/launch-01.started.json` 留存。正式实验前已保存 `protocol-01.json`，列明阶段、信号合同及验收范围。

启动前所在卷约有19GiB可用空间。安装器沿用6GiB工作区加1GiB证据区的保守预留，jobs为2；这不是实测峰值、可用空间下限保证或性能数据。失败 attempt 继续占用空间，ENOSPC 必须作为失败保留。选择 App 阶段中断是为了让先前实际新建的三个 provider 在重验后复用，避免仅为恢复实验再次编译大型图形依赖。

## 新版本合同与恢复门禁

- **计划与结果：** schema3，明确 `installer=migration_install_v3`、`product_profile=window-lookup-v7`、`runtime_lookup`。lookup 身份包括 `inline-instruction-search-v1`、候选实现SHA和三份固定模板摘要。
- **固定资源：** plan和安装源码扫描都显式读取旧 `runtime.c`、旧 `transaction_v1.c` 与新 `lookup_impl.inc`，验证固定内容并在内存重建唯一函数替换。缺失文件不能因为目录扫描未发现而被跳过。
- **版本隔离：** session与worker job为schema2，并记录新installer；job另绑定产品profile。旧v2计划、会话、job或旧v6产品均不能冒充本轮成功，跨版本应建立新安装。
- **App准入：** 核对原始PE、canonical profile、CPU/switch及graphics父角色、identifier和输出目录；再执行v7完整静态验证，要求实际lookup合同及实现摘要与计划一致。保持前批生成源码、编译依赖和产物身份门禁。
- **恢复：** 成功阶段的 `accepted.json` 仅用于定位候选，复用前重新读取实际provider、源码、receipt、父关系及产物。未接受的失败attempt原样保留，重试使用新序号目录；源代码、缓存、SDK/工具或输入变化会拒绝恢复。
- **进程：** 协调器持排他锁，worker在独立session/PGID内继承同一锁FD，先持久注册再调用builder。活进程、不明状态、缺失或变化的锁inode、无法观察的历史组都不能按“已经退出”处理。当前builder合同不允许daemonize或逃离所属组。

本轮没有增加自动重试或故障忽略分支。成功静态状态为 `OFFLINE_V7_APP_BUILT_VERIFIED_NOT_EXECUTED`；该状态本身明确不包括 App、guest 或 GPU 执行。

## 受控 App 构建中断

`migration_install_v3.recovery_probe` 创建自己的一次新安装，等待 `app-build` 注册。它先发现该worker组，再以精确PID集合进行第二次OS进程查询；只有PID、PPID、PGID、worker job、plan和输出前缀一致，并看见属于该前缀的实际clang编译子进程，才向自己持有的App构建组发送SIGTERM。

仅将第二次限定PID的原始进程输出保留为证据，避免保存用户其他进程命令行。若两次查询之间短命编译子进程消失，必须重新采样，不能用不完整观察发信号。该实验不终止用户运行中的App，不按进程名批量杀进程。成功信号调用、worker退出、进程组消失及安装失败必须分别记录；观察失败不能算作实际中断。

本轮实际 App worker 的 PID／PGID 为35337，SIGTERM 后退出码为-15，最终组状态为 `ABSENT`；初始安装状态为 `INSTALL_FAILED`，协调器退出1。当时已经完成 CPU、switch、graphics 三阶段；失败 `app-build-0001` 未接受，也未删除或覆盖。证据为 `interruption-01/result.json` 及其限定进程观察、信号与worker退出记录。

恢复命令在 `resume-01` 重验并复用 `cpu-build`、`switch-build`、`graphics-build`，在新 `app-build-0002` 编译App，并由 `app-verify-0001` 完成静态verify。被接受的构建命令为CPU41、switch5、graphics29、App69，共144条；这个数字不包含失败App attempt中的未接受命令，也不把verify计为额外native构建。独立reader核对失败、复用、角色、源和实际产品，不仅依赖协调器的成功状态。本版本没有接管入口；观察器中止或权限不足时仍必须先核对实际进程。

## 最终证据与范围

| 层次 | 已取得结果 | 边界 |
|---|---|---|
| 新模块测试 | 普通／`-O`各80项通过：安装33、独立reader17、中断工具11、doctor19 | 除受控短Python继承锁测试外为纯文件/合成stage测试；无native编译、App或GPU |
| doctor正例 | 12 PASS，退出0 | 只读前置观测，不证明解码、构建或运行 |
| doctor已存在输出负例 | 10 PASS、1 FAIL、1 SKIPPED，退出2 | 路径拒绝后空间检查跳过，其他独立组继续；原目录不改写 |
| 旧v2实际恢复拒绝 | 退出2，新恢复目录未创建 | 保留旧安装及其证据，未调用新builder |
| 完整CPU/switch/graphics新构建 | CPU41、switch5、graphics29条接受命令，三个新provider均通过 | 缓存归档复用；不是复用旧安装的provider |
| 实际App编译中断与恢复 | worker35337退出-15，组消失；保留失败0001，重验复用三provider，新App0002完成69条命令 | 不等于任意阶段／任意故障恢复已覆盖 |
| 安装及产品独立读验 | 普通／`-O`均退出0，实读5514个文件身份，报告逐字节一致；产品内650文件 | 静态读验不执行App、guest或GPU |
| 新App完整回调及Cocoa存取/搬移 | 原路径35973、搬移36283均退出0，实际switch提交2／1；同一20B存档恢复通过 | 两次短时自制样例运行；首次超时另外保留 |
| 新App运行独立读验 | 普通／`-O`均退出0，805个文件身份，报告逐字节一致 | 静态绑定lookup与实际运行计数；不是新的内核矩阵或性能测量 |
| App／游戏性能 | 未测 | 构建时长与CPU组件比值都不代表App/FPS收益 |

测试记录位于 `build/migration-install-v3/unit-01/`；doctor实际记录位于 `build/migration-doctor-v2/positive-01.*` 与 `existing-output-01.*`，旧v2拒绝在 `build/migration-install-v3/reject-v2-01.*`。

最终产品为 `/Users/feng/Documents/Codex/pe-aot-install-v3-01/work/attempts/app-build-0002`，App为其下的 `PE AOT Converted.app`。以下摘要均是相应JSON文件的SHA256，不是整个目录的单一摘要：

| 文件／回执 | SHA256 |
|---|---|
| 新产品 `result.json` | `2b1f2f38189aaf5412e48efd08295c71e86993eb61929c4fa8d9eef2f5272b33` |
| 安装 `review-ordinary-01.json` 与 `review-optimized-01.json` | `536f143b6440e15f1b8e71d38b4f16a113f4d028f02626e37f58018b5da4c78e` |
| 运行 `run-review-ordinary-01.json` 与 `run-review-optimized-01.json` | `f19e9e0208fa09bd75652afb56e82a6ccd8bae0e7830e169598aa9ef5262c75b` |

两组review及各自 `*-mode-parity-01.json` 均在 `build/migration-install-v3/`。安装reader重算来源与命令、失败及恢复关系，并通过冻结lookup reader核对精确单函数替换和真实编译输入／对象；运行reader状态为 `PASS_LOOKUP_V7_COCOA_RUNS_INDEPENDENTLY_REVIEWED`，`roundtrip_verified=true`。这两个reader自身没有执行native、UI或GPU命令。

开发时首次一个installer测试因为临时目录使用 `/var` 别名，提前触发了路径拒绝，没有抵达预期的旧worker job拒绝分支。测试改为规范路径后33项普通／`-O`通过，生产代码没有因这个测试错误改动。实际构建、观察、恢复和reader的成功与失败另存，旧attempt保留。

## 新产品实际运行与首次失败

运行现场位于冻结源码目录下的 `build/migration-run-v4/`，与私有项目的安装协调证据分开。两次成功运行均直接启动包内可执行文件、argc=1，使用外部工具生成的Cocoa系统事件，`TEST_QUEUE=0`；不是物理键盘证明，也不是Finder／LaunchServices验收。原始host输出中的 `proc_translated=0`、`proc_translated_errno=0` 均由reader核对，Mach-O与实际加载库身份也通过检查。

| 运行目录 | PID／退出码 | 实际输入 | guest steps／switch提交 | 本轮Present | 保存后position／moves／累计draws |
|---|---|---|---|---|---|
| `original-02` | 35973／0 | Right、Right、Left、Escape | 1165／2 | 5 | 4／3／5 |
| `relocated-01` | 36283／0 | Right、Escape | 917／1 | 3 | 5／4／8 |

第二轮从含空格的搬移路径启动，保留同一identifier；其冻结 `data-before/switch-tile.bin` 与第一轮20B保存结果逐字节相同。第一轮保存SHA256为 `d028262d405197c87f00be59d96f89e8eca97b147074b803b24534da0b1f794a`，第二轮为 `d760c18e2cd107c3cab6ce013bb58d506c6f413a835a77e7ca7cd716d95253c1`。每个成功run的 `cua-actions.json` 保存实际工具观测的转录，reader用原始guest/Cocoa计数、保存内容、PID／dyld／wrapper记录交叉检查；该转录不是原始OS输入trace。

首次 `original-01` 为失败：受监督PID35644未在600秒内正常退出，监督器终止自己的子进程，返回码-15；`getApp` 工具调用报告耗时1309.1406秒。随后观察到同产品路径的额外实例PID35895，核对完整路径和启动时间后发送SIGTERM，后续精确PID查询确认不存在。观测仅能说明上述时间和进程事实，**不能断言getApp内部为何延迟或额外实例为何启动**。失败记录仍在 `source/build/migration-run-v4/original-01`；私有协调证据另保留 `app-first-timeout-observation-01.json`、`app-extra-instance-cleanup-01.json`。没有为重试删除默认Data；首次失败后目录存在但无存档，后续正常轮从该实际状态继续。该失败及额外实例均不计入两次成功运行。

最后一次非激活式listApps检查中，项目running列表为空；这是检查时点的观察，不是持续保证。最后退出动作后未再对已退出App进行getApp／AX／截图操作。

本轮实际覆盖了新产品的完整窗口分发、回调和RIGHT／switch路径，并静态绑定生产lookup源码、编译输入和对象。**没有重跑前批32正常＋1456完整预算、共1488次回调内核矩阵**；该矩阵属于 [前批v7生产接入](WINDOW_LOOKUP_V1.md)，不能改记成本轮新产品的独立执行次数。本轮也没有像素等价、长时负载或完整外层ABI性能结论。

## 可复查入口

以下是本轮参数的表达方式。已存在的输出禁止覆盖；复现实验必须换全新work/evidence目录及identifier，源码副本和所有缓存身份也要重新留存。报告中的绝对路径为本机证据位置，不承诺任意机器直接可用。

```sh
AOT_TASK_ROOT='/Users/feng/Documents/Codex/2026-10-27/referenced-chatgpt-conversation-this-is-an-2'
AOT_SOURCE_ROOT='/Users/feng/Documents/Codex/pe-aot-install-v3-01/source'
AOT_INSTALL_WORK='/Users/feng/Documents/Codex/pe-aot-install-v3-01/work'
AOT_INSTALL_EVIDENCE="$AOT_TASK_ROOT/outputs/pe-aot-lab/build/migration-install-v3"
AOT_CPU_CACHE="$AOT_TASK_ROOT/work/public cpu cache moved 01"
AOT_GRAPHICS_CACHE="$AOT_TASK_ROOT/work/public graphics cache moved 01"
cd "$AOT_SOURCE_ROOT"

python3.13 -B -m migration_doctor_v2 \
  --cpu-cache "$AOT_CPU_CACHE" --graphics-cache "$AOT_GRAPHICS_CACHE" \
  --pe examples/window-switch/switch_tile.exe \
  --profile examples/window-switch/profile.json \
  --identifier org.peaotlab.installlookup39cfa624.v3 \
  --work-root "$AOT_INSTALL_WORK" --out "$AOT_INSTALL_EVIDENCE/install-01" --jobs 2

python3.13 -B -m migration_install_v3 plan \
  --cpu-cache "$AOT_CPU_CACHE" --graphics-cache "$AOT_GRAPHICS_CACHE" \
  --pe examples/window-switch/switch_tile.exe \
  --profile examples/window-switch/profile.json \
  --identifier org.peaotlab.installlookup39cfa624.v3 \
  --work-root "$AOT_INSTALL_WORK" --out "$AOT_INSTALL_EVIDENCE/install-01" --jobs 2
```

普通安装将上述 `plan` 改为 `install`。**本轮故障实验实际以以下probe代替首次install，不同时执行两种安装命令。** doctor的 `--out` 是待安装目录，不是报告文件；JSON写到stdout，调用者按新文件另存。12组全通过退出0，失败或跳过退出2；它不创建work-root/out，不下载，不启动builder或App。Apple发现查询可能维护系统缓存，`-B`用于防止Python字节码写入。诊断不能代替安装器重新验证，也不是恢复凭据。

```sh
python3.13 -B -m migration_install_v3.recovery_probe \
  --cpu-cache "$AOT_CPU_CACHE" --graphics-cache "$AOT_GRAPHICS_CACHE" \
  --pe "$AOT_SOURCE_ROOT/examples/window-switch/switch_tile.exe" \
  --profile "$AOT_SOURCE_ROOT/examples/window-switch/profile.json" \
  --identifier org.peaotlab.installlookup39cfa624.v3 \
  --work-root "$AOT_INSTALL_WORK" \
  --installation "$AOT_INSTALL_EVIDENCE/install-01" \
  --out "$AOT_INSTALL_EVIDENCE/interruption-01" --jobs 2

python3.13 -B -m migration_install_v3 resume \
  --installation "$AOT_INSTALL_EVIDENCE/install-01" \
  --out "$AOT_INSTALL_EVIDENCE/resume-01"

python3.13 -B -m migration_install_v3.review \
  --installation "$AOT_INSTALL_EVIDENCE/install-01" \
  --session "$AOT_INSTALL_EVIDENCE/resume-01" \
  --probe "$AOT_INSTALL_EVIDENCE/interruption-01" \
  --out "$AOT_INSTALL_EVIDENCE/review-ordinary-01.json"
```

安装reader是文件读验，不调用installer成功validator、builder、subprocess或App；它重算来源与阶段关系，并调用前批冻结的lookup只读reader核对实际生产源码和代码段。普通与 `python3.13 -B -O -m ...` 分别写入全新输出后比较；本轮两份报告已取得上述同一SHA。

以下是本轮成功运行与独立读验的参数；已存在的现场仅供复查，重新运行必须换新的证据目录。原路径正常结束后才执行搬移轮，不能并发启动，也不能提前伪造 `cua-actions.json`。

```sh
AOT_PRODUCT='/Users/feng/Documents/Codex/pe-aot-install-v3-01/work/attempts/app-build-0002'
AOT_PRODUCT_RECEIPT='2b1f2f38189aaf5412e48efd08295c71e86993eb61929c4fa8d9eef2f5272b33'

python3.13 -B -m migration_run_v4 \
  --product "$AOT_PRODUCT" \
  --out build/migration-run-v4/original-02 --timeout 600

python3.13 -B -m migration_run_v4 \
  --product "$AOT_PRODUCT" \
  --out build/migration-run-v4/relocated-01 --relocate --timeout 600

python3.13 -B -m migration_run_v4.review \
  --product "$AOT_PRODUCT" --product-receipt-sha "$AOT_PRODUCT_RECEIPT" \
  --run build/migration-run-v4/original-02 \
  --run build/migration-run-v4/relocated-01 \
  --out "$AOT_INSTALL_EVIDENCE/run-review-ordinary-01.json"
```

实际输入和退出流程见 [v7运行入口](../migration_run_v4/README.md)。该命令本身不会生成Cocoa操作；需等待监督器报告实际PID，再操作该已有实例。运行reader的优化模式另写 `run-review-optimized-01.json`，本轮两份报告已逐字节一致。本批没有额外调用内核矩阵probe。

```sh
python3.13 -B -m unittest \
  migration_install_v3.test_install migration_install_v3.test_review \
  migration_install_v3.test_recovery_probe migration_doctor_v2.test_doctor -v
```

源快照、固定资源检查和当前发行清单分别提供不同证据。doctor摘要是读取时的身份，不证明正在执行的字节或整个诊断期间源码完全不变；对其他非Python资源的完整性不能从三份lookup文件检查推广。本批原始完整构建与独立读验提供后续证据，也不使doctor报告本身变成构建证明。

## Go／No-Go与下一开发任务

**Go：接受本机、固定缓存和受限自制PE范围的v7安装／恢复／诊断工具闭环，并接受本轮新产品的两次短时Cocoa存取与搬移运行。** 新代码测试、实际重建、受控失败、重验复用、静态产品读验和新产品运行分别有证据。首次失败没有被后续成功覆盖；本轮结果不自动扩大到其他故障类型或输入。

**No-Go：将本轮成功解释为完整迁移工具、通用Windows兼容或App／游戏性能优势。** 外层ABI计时、代表性负载、干净机器和实际游戏仍未验收。

后续按能力推进：

1. 按 [完整外层ABI设计](WINDOW_OUTER_ABI_NEXT_V1.md) 先闭合A0：明确同一live State／Context地址的字段恢复清单、实时MSG的受控确定性输入、Context每轮增量与TLS累计账本；保持原始捕获边界供最终continuation使用。当前只有设计与复审，A0尚未闭合，A1–A6均未实现或实测。
2. A1生成新诊断overlay／reader和源码门禁；A2先无计时地通过真实RIGHT与KEYUP纵向切片，验证原DispatchMessage、嵌套DefWindowProc、callback／import RET及正常退出。不得用TestOwner或成功stub替代完整运行时；通过后才扩展矩阵并冻结计时合同。
3. 用代表性持续App负载检查帧时、CPU/GPU、资源释放和长时稳定性，再安排同条件Wine/Rosetta基线；不给出尚未测得的加速比。
4. 继续更广PE/编译器形态、一般控制流、CRT/DLL、线程/TLS/SEH、图形与输入/音频支持，按实际合法单机目标需求扩展。
5. 另一台干净机器、网络冷获取、二进制逐字节可重复构建、签名/公证和发行义务另验；本批同机、已有缓存和本地源码导出不覆盖这些目标。

本轮不承诺任意Steam游戏可迁移，不进行DRM或反作弊绕过，不将组件测量外推为App或游戏性能；整体迁移项目仍在推进。
