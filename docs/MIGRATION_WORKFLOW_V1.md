# 单配置迁移工作流 v1

日期：2026-11-03。新统一入口的providers路线已完成实际fresh App构建、静态验证、成功复用及真实中断后重建。offline路线已完成适配测试和本机只读前置检查，本轮未通过新入口重建整条工具链。所有新App均未启动；本批验收的是迁移脚本工作流，不是新增游戏兼容性或性能。

## 本轮要解决的问题

此前用户需要分别调用doctor、install、v7 build／verify和独立reader，并在不同命令中重复填写PE、profile、provider／缓存和输出路径。主页又混列多批“当前”入口，容易把旧版本、离线缓存、已构建provider或实际App运行命令混用。

本轮收敛为`migration_workflow_v1`和一份schema1配置：`init → check → build → verify`，失败后对同一工作区`status → resume → verify`。`plan`提供与前置检查相同的无构建入口。用户命令和完整示例见[模块README](../migration_workflow_v1/README.md)。当前优先完成这条迁移脚本工作流，真实目标／TLS进一步适配后置。

## 接口合同

配置顶层字段为`schema`、`pe`、`profile`、`identifier`、`build`。`profile`为路径字符串或null；null仅在PE摘要命中固定window-switch自产recipe时选择现有profile，不生成新profile，不为第三方PE猜入口或API。未知输入没有显式profile时返回`PROFILE_REQUIRED`。

| 模式 | build字段 | 行为 |
|---|---|---|
| `providers` | `mode`、`cpu_prefix`、`graphics_prefix` | 复用经验证的CPU switch overlay及图形provider，构建新App |
| `offline` | `mode`、`cpu_cache`、`graphics_cache`、`jobs` | jobs为1..2，委托install_v3从固定离线缓存重建依赖链 |

配置内相对路径按config.parent解析，不随调用者cwd变化；不展开`~`或环境变量，不接受经过符号链接的路径。CLI的config、workspace及`--out`参数则按cwd解析。模式字段互斥，provider与cache不能互换。CPU overlay依赖的父base须保持实际可验证身份和位置。

| 命令 | 主要输入 | 写入／执行边界 |
|---|---|---|
| `init` | 新config路径、PE及显式依赖模式，profile可选 | 父目录须存在；仅新建配置，不覆盖已有config；返回CONFIG_CREATED而非输入已就绪 |
| `check` / `plan` | config、拟建`--out`工作区 | 父目录须存在、目标须不存在；JSON到stdout，不预写报告或工作区，不启动builder或App |
| `build` | config、新`--out`工作区 | 建立冻结输入与构建证据、调用既有构建链，不启动App |
| `status` | 工作区 | 读取已记录状态；不是重新完成构建或运行验收 |
| `resume` | 未完成工作区 | 重验身份后继续；旧失败产物和日志保留 |
| `verify` | 工作区 | 验证已记录产物，不启动App |

主要状态包括`MIGRATION_CONFIG_CREATED_NOT_CHECKED`、`MIGRATION_READY_NOT_DECODED_NOT_BUILT`、`MIGRATION_BLOCKED`、`MIGRATION_COMMAND_REJECTED`、`MIGRATION_BUILD_FAILED`、`MIGRATION_APP_BUILT_VERIFIED_NOT_EXECUTED`、`MIGRATION_APP_VERIFIED_NOT_EXECUTED`和`MIGRATION_STATUS_OBSERVATION_NOT_VERIFIED`。成功退出0、输入或前置条件阻断退出2、构建失败退出1、键盘中断退出130。status退出0不等于构建或产物验证成功。前置检查沿用既有profile／loader门禁，不将`ELIGIBLE_FOR_BUILD_NOT_DECODED`提升为全指令兼容结论。

## 恢复与失败消息

providers失败恢复不是恢复半截编译：重新核对冻结输入和provider，在新的attempt完整构建App。已经成功的最近产物经重验可复用，不创建多余attempt；已登记worker完成而协调器未记录结果的情况，只有经过旧进程组和产物验证才能接受。offline恢复委托install_v3阶段协议，成功阶段重验后复用、失败阶段新建attempt；保持已有锁、进程组和身份检查。恢复和verify均重读原config、原输入及相关身份，不能通过修改配置或搬移workspace改变任务。

已实现的检查失败项／命令异常字段为`stage`、`code`、`field`、`message`、`next_action`、`error_type`；field／next_action可为null。构建失败另有attempt、failure或worker状态，其下层结果不强行套成同一schema。正常结果及check报告在stdout，命令拒绝和中断在stderr；参数语法错误可能输出usage文本。已解析的绝对路径可从config规范化结果和具体错误中核对，解析未完成时不虚构路径。机器可识别code与下层原始诊断分开，不根据英文错误字符串猜测二进制兼容性。固定的`PROFILE_REQUIRED`表示缺少已建立的profile，不是该PE经过完整解码后的结论；`INPUT_NOT_ADMITTED`保留下层合同拒绝信息。

| 失败类别 | 消息应区分的事实 |
|---|---|
| 配置或profile缺失 | 配置字段、解析后路径、缺失还是格式错误 |
| 合同不被接受 | 保留下层`profile-or-loader`阶段及原始原因；不得自动补profile |
| 依赖不匹配 | provider角色、父base绑定或cache身份问题；不能只说“依赖错误” |
| `OUTPUT_EXISTS` | 已有工作区不能用check／plan／build；用status／verify查看产物，未完成任务用resume |
| 构建失败 | 阶段、失败attempt、原始日志位置、返回状态；保留现场 |
| 恢复被阻断 | 身份变化、历史worker仍活或状态无法验证；不能按超时推断安全恢复 |

上表其余类别是诊断范围，不是另造错误码。实际CLI已验证：修改自产PE一个字节后，未知SHA返回`PROFILE_REQUIRED`／退出2，且没有创建工作区；对既有工作区再check返回`OUTPUT_EXISTS`／退出2。plan仅在stdout报告检查结果、阶段和build命令，不能在检查前创建report文件或已有工作区来改变输出门禁。

## 本轮验收记录

本机为Apple Silicon macOS；使用现有、重验通过的CPU switch overlay和graphics provider。新产品绑定PE SHA `39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8`，原profile SHA `c3974063866c3c80c4e1cb9af46748cc8c2f6039ae286bc6c8afb12c1dd74d76`。原profile字节摘要与规范化profile摘要分别记录，不混用。

| 能力 | 本批实际结果与边界 |
|---|---|
| 代码／边界 | 36项测试普通／`-O`各通过；每模式含实际隔离Python worker的锁继承和独立PGID测试，dispatch故意失败。其余编排测试不冒充native构建 |
| 独立源码复审 | 另11项／模式通过：7项接纳／失败边界，4项原installer fixture集成；后者真实文件／锁但mock builders/provider/SDK |
| init／check／plan | providers和offline两模式实际CLI通过，前置8组PASS；check／plan均未创建拟建workspace |
| fresh构建 | `workspace-01`经新CLI生成新v7 App；69条底层命令，670条受限指令，650个产品ledger文件；返回`MIGRATION_APP_BUILT_VERIFIED_NOT_EXECUTED` |
| 成功复用 | verify通过；resume返回`reused_verified_product=true`，attempt仍只有1个，不重复编译；status仅输出历史观测 |
| 真实失败与重试 | `workspace-recovery-02`的首个worker在第008条lift命令started记录出现后受控SIGTERM，退出-15，CLI退出1；此前001–007命令已有实际结果，第008子进程开始执行未独立观测。resume新建attempt-0002完成构建，verify通过。旧失败135文件前后摘要完全一致 |
| 协调器缺记录恢复 | `workspace-recovery-01`的测试驱动因沙箱拒绝`/bin/ps`提前结束，未发送signal；worker完成但协调器未记录exit。resume重验后接纳并明确`worker_exit_status_observed=false`、`returncode=null`，没有补造退出0 |
| 独立产品读验 | fresh与中断恢复后的两个产品分别由既有独立`window_lookup_v1.review`普通／`-O`读验，每产品每模式3806个唯一文件、650产品文件，报告各自逐字节一致；另独立核验失败135文件和worker／信号／退出关联。reader不调用生产validator或执行native／UI命令 |
| offline路线 | 新适配器与原安装协议集成反例通过，本机cache／SDK／空间check与plan通过。离线整链复用已有验收，本轮未重跑；不称新入口两路线native全通过 |
| 实际运行／性能 | 本批App／guest／GPU执行均为0；不报告帧率、Wine＋Rosetta对照或新增第三方迁移成功 |

独立审查修复了成功复用缺少产物回执／attempt关联、孤儿worker接纳可能掩盖非零退出、离线复用漏验原安装环境、失败登记字段不严、构建后身份未重验、超限JSON先读后拒以及父CPU provider路径重叠等问题。原失败和初始反例保留；上述测试与native构建均针对修复后冻结源码。

本批fresh构建耗时约24.99秒，只是这台机器、已有provider、固定样例的一次命令耗时，不是冷安装成本、运行性能基准或未来构建时限。

本地完整原始证据在`build/migration-workflow-v1/`；公开仓库只发布源码、测试、合同和本报告，不分发本机工具链与App。主要定位如下：

| 路径 | 内容 |
|---|---|
| `unit-initial-01/`、`unit-final-01/` | 初始反例与修复后36项两模式结果、源码前后摘要 |
| `review-01/final-review.json` | 独立源码／11项两模式复审 |
| `cli-01/`、`workspace-01/` | exact argv、stdout／stderr、退出码、冻结输入、worker与产品 |
| `product-review-01/` | fresh产品独立两模式读验及文件身份 |
| `recovery-product-review-01/` | 恢复产品独立两模式读验、历史失败与恢复链的独立核对 |
| `recovery-01/`、`workspace-recovery-01/` | 测试驱动失败与未观测退出状态的接纳记录 |
| `recovery-02/`、`workspace-recovery-02/` | 准确PID／PGID登记、信号前身份、-15失败、新attempt和原失败前后摘要 |
| `offline-check-01/`、`negative-cli-01/` | offline只读接线及未知SHA／既有输出的实际拒绝 |
| `public-check-01/` | 导出公开源码后的36项测试，两模式通过且新实现与本地源码相同 |

本轮新增公开文件为7个模块文件及2份报告／合同，主页与剩余清单同步更新；导出源码测试普通／`-O`各36项通过。公开文件集不携带本机provider、App或完整原始读验报告；本地提交与线上推送分别记录，本批不自动推送。

## 接续开发顺序

先完成迁移脚本的交付验收：新入口offline完整链与中断恢复、公开源码独立环境复现、可维护发行和资源占用记录。既有provider路径依赖原绝对位置，不能把工具链目录搬移当作已支持。自动依赖获取、签名公证、长时稳定性仍是明确余项；不因增加CLI就宣称裸机一键完成。

随后使用已固定的真实Windows应用做测试，按首次真实失败补指令、TLS／CRT／DLL／SEH／API和图形能力。Chocolate Doom原PE库存及CFG报告作为后续输入保留，本轮不继续其专用TLS切片、不请求Steam账号。进度继续按代码、构建、正确性、集成及性能分别验收。

## 上一阶段产物规模（只读盘点）

在本轮开始时按实际文件长度汇总。下表是磁盘文件逻辑字节，不是运行时RAM，也不是可直接释放的空间；没有删除或压缩任何产物。

| 范围 | 文件数 | 逻辑字节 | 约MiB |
|---|---:|---:|---:|
| `build/real-pe-cfg-v1` | 113 | 391,175,898 | 373.054 |
| `build/real-target-inventory-v1` | 136 | 166,221,473 | 158.521 |
| 仓库外`work/real-target-v1` | 38 | 30,782,835 | 29.357 |
| 合计 | 287 | 588,180,206 | 560.932 |

主要体积来自多份独立运行的原始graph JSON（约81.4–83.6 MB／份）、约24.5 MB的全.text oracle，以及普通／优化模式各自的gap和库存JSON。它们代表不同运行或复核来源，不能只凭内容相近直接删除；后续若压缩或归档，需要另建可验证索引并保留失败来源。本轮优先完成用户工作流，不扩大真实目标分析或生成新的大矩阵。
