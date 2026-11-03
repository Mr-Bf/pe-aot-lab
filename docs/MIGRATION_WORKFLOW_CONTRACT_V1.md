# 单配置迁移工作流合同 v1

本文件记录源码审核后的当前实现合同，并单列尚未完成的更强交付体验；实际验收结果见[本批报告](MIGRATION_WORKFLOW_V1.md)。按用户最新优先级，先完成迁移脚本的配置、诊断、计划、构建、恢复及静态验收闭环，再进行真实应用测试与兼容修补；Chocolate Doom／TLS 专用开发暂缓。当前目标是把已有受限能力做成可靠入口，不能把增加一层 CLI 算作通用 Windows 游戏兼容。

## 已有能力与当前连接

| 能力 | 已有真实入口 | 当前工作流与边界 |
|---|---|---|
| PE／profile 准入 | `window_switch_v1.profile.read_input/read_profile/validate/analyze` | 自动选择已冻结样例 recipe；未知输入给出阻断，不猜测 callback、switch 根或参数语义 |
| 使用现有 provider 构建 | `migration_v7.build.build/verify` | 配置绑定、provider 前置检查、拥有子进程与锁、失败保留、新 attempt 重试、实际产品身份验收 |
| 缓存到完整工具链与 App | `migration_install_v3.runner.plan/install/resume` | 把一个配置转为正确且互斥的路径／参数；保留原五阶段、收据及恢复协议 |
| 前置诊断 | `migration_doctor_v2.doctor.host_python` 及 installer／provider 检查函数 | 归并八组检查；未直接调用完整 `diagnose`，不把它称为原 doctor 的全部十二组诊断 |
| 原始证据独立读验 | `window_lookup_v1.review`、`migration_install_v3.review.review` | 单独执行并绑定实际产品或 installation／session；不是 workflow `verify` 的自动步骤 |
| 未知 PE 的事实清单 | `real_pe_inventory_v1.inventory.analyze_bytes` | 从原字节生成精简 inventory，包括 SHA、头／目录、发现项及导入数量；未自动执行完整 `inventory_path`／`real_target_gap_v1` 报告 |
| 实际 App 监督与读验 | `migration_run_v4.runner.run` 及其独立 reader | 暂作为后续显式操作交接，不由 build／verify 自动调用；当前需要真实 Cocoa 输入及独立动作证据 |

v7 已有构建不自动执行 guest／GPU／App；`ELIGIBLE_FOR_BUILD_NOT_DECODED` 只说明前置合同通过，实际译码仍可能拒绝。install v3 已有 CPU base → switch overlay → graphics → App → verify 的恢复协议；直接调用 v7 builder 没有同等断点续建能力。

## 一份配置与七个操作

当前入口为 `python3.13 -B -m migration_workflow_v1`。`init --config CONFIG --pe PE` 加一种依赖来源，只创建配置文件；`check CONFIG --out WORKSPACE`、`plan CONFIG --out WORKSPACE` 和 `build CONFIG --out WORKSPACE` 显式选择一个尚不存在的工作区。建立工作区后，使用 `resume WORKSPACE`、`verify WORKSPACE`、`status WORKSPACE`。输入／依赖参数只在配置中保存一次，但当前并非所有后续命令都只接受 config。完整命令见[入口 README](../migration_workflow_v1/README.md)。

| 操作 | 当前行为与成功含义 |
|---|---|
| `init` | 只创建新配置，拒绝覆盖；不检查 PE 或选择 recipe，不创建 workspace。成功状态为 `MIGRATION_CONFIG_CREATED_NOT_CHECKED`，未知输入要到 check 才获得缺少 recipe 的诊断 |
| `check` | 汇总输入、recipe、依赖、主机及路径问题；独立项继续检查，依赖项显式 skipped。只诊断，不构建或改变已有产品 |
| `plan` | 复用 check，在 stdout JSON 中附阶段列表和 build 命令；只读、不持久化独立计划，不创建 workspace，无 guest 译码／执行 |
| `build` | 重新检查配置、输入和依赖后，创建 workspace 并冻结身份及输入，分派唯一路线；新 attempt 构建及生产静态验证，返回具体 App／证据路径 |
| `resume` | 在原工作流内重新校验身份与进程所有权；离线路线委托原 installer 恢复，现有 provider 路线只允许安全的新 attempt 重试 |
| `verify` | 使用生产 validator 读取实际产品及下层原始收据，重验配置／输入／provider／attempt 关联；offline 还核对完整已接受安装阶段。不运行独立 reader 或 App |
| `status` | 只展示路线、attempt 数、最近历史结果和 verify／resume 提示；不检查锁、活 worker 或实际产品，状态明确为 `MIGRATION_STATUS_OBSERVATION_NOT_VERIFIED` |

配置采用固定 schema、严格键集合与类型、大小上限；拒绝重复 JSON 键、NaN／Infinity、布尔值冒充 jobs。路径相对配置文件解释，归一化后固定；不使用 shell 求值、变量替换或任意命令字段。identifier 首次确定后保存，offline jobs 限 1..2。配置 `build.mode` 恰选 `providers`（`cpu_prefix`、`graphics_prefix`）或 `offline`（`cpu_cache`、`graphics_cache`、`jobs`）；两组字段互斥，不在失败后偷偷换路线或下载依赖。

profile 自动化只允许按原 PE 完整 SHA 命中已审核 recipe，并核对 profile 原字节 SHA。首个可用 recipe 为 `examples/window-switch`：PE SHA `39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`，profile SHA `c3974063866c3c80c4e1cb9af46748cc8c2f6039ae286bc6c8afb12c1dd74d76`。这是对已知输入免手工参数，不是自动推导任意 PE 的 profile。专家可显式提供 profile，但仍须通过全部现有校验；仅凭文件名、导入名或相近 CFG 不准入。

未知输入在 check／plan／build 的前检中获得精简静态 inventory；没有内置 recipe 且未提供显式 profile 时，以 `PROFILE_REQUIRED` 阻断，返回 `MIGRATION_BLOCKED` 和非零退出码，不调用 producer。显式 profile 仍须通过原 PE／profile 准入。精简报告不包含完整逐导入参数／能力 gap；完整 gap 是另一个工具的显式操作，不能由库存生成成功或导入名称推断迁移准入。诊断区分缺少 recipe、合同不匹配和依赖／环境缺失，不把实现限制说成文件损坏或永远不能迁移。

## 目录、身份与恢复

用户选择 CONFIG 与 WORKSPACE，工具管理其内部冻结输入、attempt 和证据；offline 的 work 与 installation 为工作区内互不包含的兄弟路径，并与输入、cache 分离。检查路径与符号链接后才创建，使用原子排他创建；不删除未知目录或覆盖失败记录。当前 check／plan 的 `--out` 是拟建 workspace，不是报告文件；它们不创建该目录。原 doctor 的同名参数仍有其独立入口语义，不能混用。

check／plan／build 明确服务于新工作区，传入已存在的 out 会拒绝并提示 resume 或新目录；它们尚未实现自动识别已有 workspace 的检查模式。已建立任务用 verify／resume 重验，不把 fresh-path 拒绝当成已有产品损坏。重复 check／status 不分配 builder attempt、启动 App 或修改产品。

build 创建的 workspace 绑定配置内容、PE、原始与规范化 profile、依赖角色与收据、实际工具／SDK／Python、实现及强制 lookup 资源身份；此前 stdout plan 不是恢复凭证。执行前后重新核验；变化需新配置／新 workspace，当前没有原地修订计划协议。哈希检查不声称能抵御恶意主机的瞬态篡改。源码树中新资源可能改变 installer 的实现清单，不能默认为旧安装可跨实现 resume。

单个工作流只允许一个写入者。worker 必须在 builder 开始前登记自己的 PID／PGID／job，并继承工作流排他锁；协调器退出后活 worker 仍持锁。不能把超时、缺少 result、PID 不见或旧状态文件当作全部子进程已结束；进程组状态未知应阻断，不能按进程名清理用户进程。不支持 builder daemonize／逃离所属组的恢复承诺。

离线路线继续使用 install v3；`offline.validate_existing` 在原安装锁下重验环境、锁 inode、成功阶段、provider 角色与依赖，成功产品须有完整五阶段闭合。workflow 自己的索引只作定位，不取代底层 accepted 校验。新 session 用新 evidence 目录，原安装位置及成功 provider 的绝对位置不变。该适配器复用生产检查逻辑，不因此变成独立 reader。

现有 provider 路线的失败不能原地继续 v7 builder；确认旧 worker／进程组消失且输入不变后，保存原失败并创建全新 product attempt。若 App 已生成但协调结果缺失，须核对 worker 注册、完整产品、workspace／attempt 身份及收据后才可接纳；实际非零退出不得改写为成功，缺失退出观测必须明确保留为未观测，不能伪造退出 0。已完成任务的 resume 可以返回经重新验证的现有产品；build 仍要求新 workspace，不接管旧目录。

## 当前最小脚本闭环的验收边界

以下项目按证据逐项验收，不用包装命令数或测试数换算游戏兼容率：

1. 已审核 PE 只在 init 输入一次 PE 与依赖参数；check／plan／build 使用该配置及显式新 workspace，resume／verify／status 使用冻结 workspace，普通用户不手填 callback／switch/profile。两条路线均有分派与产物身份绑定；静态终态明确 `NOT_EXECUTED`。
2. 未知／不合约 PE 在构建前得到可读缺口及非零阻断；缺失依赖、混用路线、损坏配置、路径重叠和 profile／provider／实现变更均不能误报成功。外部 JSON 不能替代重新读取原输入。
3. verify 是生产 validator；独立 reader 须单独执行、另存结果。篡改产品字节、收据、角色或输入关联会拒绝；没有执行 reader 的产品不能称独立验收。原始日志、命令、失败和恢复关联保留。
4. 并发与中断有实际小子进程实验验证锁继承及拒绝未知活动组；离线 stage 恢复和 provider fresh-retry 各自遵守其边界。仅模拟函数调用的测试要标为 orchestration 测试，不能充当本次 native 安装证据。
5. 命令提供 JSON 状态／退出码，help／README 给出统一构建和恢复入口；错误保留阶段、原因及适用的下一步提示。独立验收和运行仍需单独入口，不能声称所有后续操作都已自动连接。公开源码应包含所需模块、recipe 和固定资源，缺失资源主动拒绝。
6. 新工作流至少以已有 provider 做一次实际 fresh App 构建与静态 verify；离线路线先复用已验 installer 并单独记录本轮适配验证层级。若没有通过新入口完整重建缓存链，须写“离线整链复用已有验收，本轮未重跑”，不能报两路线本批 native 全通过。

本批已有 provider 路线的新 App 构建、verify、成功 resume 复用及单独独立 reader 已通过；offline 取得本机八组前检 PASS 与合成集成证据，未通过新入口冷重建整链。新受控 SIGTERM 的失败已记录，恢复结果以本批报告中的最终证据为准，不在合同中提前宣称完成。上述均不是生成 App 的实际交互运行。

## 尚未关闭的更强交付体验

早期设计提出的“init 决定工作流根、后续命令只传 config”“独立持久化 plan”“check 自动识别既有任务”“status 查询活 worker”“自动完整 gap／独立 reader”尚未实现，当前 CLI 不承诺这些行为。它们可作为后续体验与交付增强，不能写成此次最小入口已经完成的能力。

当前范围以已有、已核对的 provider 或离线缓存为起点。自动下载／安装 Xcode、缓存准备、另一台干净机器、签名公证和 App 交互验收不是上述静态闭环已经包含的能力；不能声称裸机一键安装完成。新入口的完整 offline 冷重建仍需单独实际验收，历史 installer 通过不能代替它。

独立源码审核结论：此分层可以减少操作负担，且不需放宽 v7 的拒绝门禁；状态绑定、两路线恢复差异及 recipe 拒绝边界已有针对性反例审核，实际测试层级见本批报告。真实第三方应用／游戏迁移成功数仍为 0；实际运行、兼容扩展和性能属于下一阶段，不由本合同宣布完成。
