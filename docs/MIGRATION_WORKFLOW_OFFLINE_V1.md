# 统一入口的离线整链与恢复验收

本批继续优先完成迁移脚本，使用`migration_workflow_v1`的offline模式。新公开源码目录已从固定缓存完成全部依赖与App，首次App构建受控中断后由统一入口恢复成功；生产verify、重复resume复用、失败目录不变检查及独立整链读验均已通过。固定已支持输入的同机静态构建／恢复MVP完成；未启动App，不代表通用游戏兼容。

## 来源与范围

从本地公开仓库提交`7db91d2de51649b157e8e66d4587bd8e77a5adc5`执行`git archive`，导出639文件、6,034,336字节到新目录`/Users/feng/Documents/Codex/pe-aot-workflow-source-01`。逐文件与公开manifest校验一致；没有复制私有实验树或已安装provider。archive SHA为`7cb387dbf2cacf42b9de9c363a4f5e1e1b5f0e939af8528060170e851150a323`，公开manifest SHA为`f519d31cbd99efe59e9126cd2c95da38abda6ebbcb0bb6d702dc79b383c2c940`。

新工作区为`/Users/feng/Documents/Codex/pe-aot-workflow-offline-01`，构建前工作区、`offline-work`与`offline-install`均不存在。顶层CLI及后续worker的源码根均为新导出目录，清除`PYTHONPATH`／`PYTHONHOME`后启动；配置引用新源码内的自产window-switch PE，使用已固定的CPU和graphics缓存，jobs为2。源码在构建过程中冻结。

这是同机、已有缓存、公开提交的独立目录复现，不是网络clone、网络冷下载、第二台干净机器或逐字节可重复构建。CPU链使用固定的LLVM17工具包，Remill／XED及图形LLVM15／DXMT等仍按原builder实际构建；不能把“新provider”改称所有依赖都由源码重新编译。所有步骤均不启动App、guest或GPU工作负载，不新增游戏兼容性或性能结论。

## 实验步骤与验收标准

1. 新目录运行`init → check → plan`。本机8组PASS，后两命令未创建工作区。
2. 由统一`build CONFIG --out WORKSPACE`启动新离线安装。CPU base、switch overlay、graphics必须在本轮新前缀建立，并保留每阶段原始命令与收据。
3. 在首次App阶段，先验证顶层CLI→外层workflow worker→内层installer stage worker的两层父子关系、job／plan／锁／输出前缀，再看到实际属于该前缀的clang子进程，才对**内层App构建PGID**发送SIGTERM。外层workflow与CLI继续等待、保存结果。
4. 预期内层worker退出-15、原安装失败；外层worker正常返回失败结果，退出0；统一CLI返回`MIGRATION_BUILD_FAILED`／退出1。三者退出码含义不同，不互换。
5. 旧组均已消失后，对同一工作区执行统一`resume`。CPU／switch／graphics成功阶段先重验再复用，只在新App attempt重新构建，不原地续编译失败目录。
6. 失败stage的原证据与对应prefix在恢复前后逐文件核对；installation的session索引会合法追加，不能要求整个安装树无变化。
7. 对实际恢复session执行既有独立`migration_install_v3.review`普通／`-O`两次；再单独核验外层workflow、受控信号、失败不变与新产品关联。生产`verify`与独立reader分开报告。

私有实验驱动`build/migration-workflow-offline-v1/run_interruption.py`仅复用旧probe的进程观察与所有权检查函数，没有调用会自行启动旧installer CLI的`probe.run()`。原reader的`--probe`格式也不直接套用本轮新外层协议；使用本批单独的关联复核。

## 已有实际观测

原始证据保存在私有项目的`build/migration-workflow-offline-v1/`，构建产物在上述新工作区。初始可用空间约14.17GB；既有7GiB门禁保持不变，不下调门槛以通过实验。该门禁是保守预留，不能算作实测峰值；本批会另记实际空间观测。

构建运行中实际执行过`status`及一次重复`resume`。status退出0但仅报告历史观测；resume因工作区锁返回`MIGRATION_COMMAND_REJECTED`／退出2，错误为`BlockingIOError`／Errno35。两次观测前后只有`attempt-0001`，没有重复builder。当前该诊断仍用通用`CHECK_FAILED`且`next_action=null`，不是已实现了专门BUSY错误码。

首次整链故意中断，实际结论为“整链经恢复完成”，不是首次不中断构建成功。内层App-stage PID／PGID为92283，原始进程观察中包含其实际clang++子进程92341；外层workflow worker为77320。发送SIGTERM后内层退出-15，外层正常返回失败状态并退出0，统一CLI退出1。原安装接受了CPU、switch、graphics三个阶段，失败App没有accepted marker。

统一resume在`attempt-0002/offline-resume`重验并复用三个provider，分配新的`app-build-0002`和`app-verify-0001`。原失败`app-build-0001`的证据与prefix共有103个普通文件、1,077,226字节；恢复前、恢复后和当前再次读取的字节、模式、inode及目录／链接身份一致。随后verify与重复resume均退出0，后者返回`reused_verified_product=true`，workflow attempt仍为2，没有重复建provider或App。

| 本轮接受的阶段 | 实际命令数 | worker时段 |
|---|---:|---:|
| CPU base | 41 | 82.04秒 |
| switch overlay | 5 | 13.08秒 |
| graphics | 29 | 1,234.64秒 |
| 恢复后的App | 69 | 22.06秒 |
| App verify | 不计为native构建命令 | 0.33秒 |

四个构建阶段共144条接受命令，不包含失败App的命令。整个统一resume命令约50.44秒，含环境／收据重验、App构建及验证；单独verify约9.42秒，成功产物复用约9.49秒。这些是本机已有缓存的一次时段观测，不是代表性性能基准或未来耗时承诺。

新App包含670条受限指令，产品ledger为650文件。产物receipt SHA为`2813b78b582aa7241a56ce996d9966c2c7f4596f9655dab88117f12bdf4e6f12`，可执行文件SHA为`08f69c9ec6ce7990d4602344937862fc05cc9bf2102c7d674810820a10e25c75`。App、guest与GPU执行均为0。

本批最终工作区的普通文件逻辑长度合计3,538,390,225字节，`stat.st_blocks`合计3,758,698,496字节；后者不是去重后的唯一物理空间或可直接释放空间，两者均不是RAM。完成后观测可用磁盘约9.74GB。只建了一套新工具链，未为恢复重复构建CPU／graphics，未新建Git worktree，也未删除旧现场。图形编译警告保留在原始日志，不将成功构建解释为所有shader路径或运行行为通过。

## 独立复核与当前边界

源码导出已独立核对：639文件的集合、字节、SHA及落盘mode均匹配公开manifest。原内存archive未保留，后来从同一提交重建并验证与原记录SHA完全相同，再逐成员核对；不能称保存了原始流。首次辅助reader直接要求archive mode等于落盘mode而拒绝，失败证据保留；按实际`tarfile.extractall(filter='data')`的安全解包规则核对0664→0644后通过，没有修改source或旧export记录。

本批运行的是冻结公开`7db91d2`的实现，没有修改生产转换器、安装器或workflow源码；最终文档发布会另有提交。因此本批不把源码导出后的文档数量变化混算为native构建来源，也不重复旧单测来累计完成量。既有双模式36项测试见上一批[工作流报告](MIGRATION_WORKFLOW_V1.md)。

既有独立`migration_install_v3.review`从本轮实际源码根分别以普通／`-O`运行，每模式读取5,510个唯一文件；产品650文件、69条App命令、全部五阶段及本轮新provider关联通过。两份原始报告逐字节一致，SHA为`5bc5525ec5039438ddda56288cc31b149c88d8dedb3e0bb8e66c5f37cc968e00`。reader不调用installer的成功validator、builder或App；它复用既有元数据loader并调用冻结的产品reader，不称为纯stdlib实现。

本批补充的外层链reader只读核对公开manifest／archive／SOURCE、原config、workspace、两层worker、真实clang观察、信号与退出、两次session、三个provider的原前缀复用、新App和失败树。两模式均通过；原始JSON唯一差异为引用普通／优化安装报告的文件路径，引用文件SHA相同，其余内容一致，不能写成外层报告原字节完全相同。另对实际JSON解析后的8项变异逐模式验证，全部拒绝，包括错来源／config、旧provider、PID、缺clang观察、锁回执、失败树漂移及额外session；这是记录层反例，不是native执行矩阵或raw JSON解析fuzz。

独立复审修补了辅助reader对公开文件集合、原配置与新SOURCE、必备workflow源码、准确两session及活动锁回执的关联检查；没有修改生产转换器。初版archive mode假设导致的拒绝保留在`review-plan-01/export-review-failure-01/`。最终独立汇总SHA为`ffae170ea56a7d34dbcd60c75ea2e8f3378410dee00310950039e3b52137b0b8`。

主要证据索引：`source-export.json`、`archive-retained.json`、`protocol-01.json`、`preflight-01/`、`active-lock-01/`、`interruption-01/`、`resume-01/`、`native-facts.json`、`install-review-01/`、`chain-review-01/`及`independent-review-summary-01.json`。原始native产物和大型reader清单留在本机，Git仅保存精简元数据、辅助工具与摘要。

## 脚本收口与下一任务

已有provider路线的上一批证据，加上本批offline整链经恢复完成、公开源码新目录复现，满足固定已支持输入的迁移脚本MVP：一份配置、明确准入、全新构建、活动任务拒绝、失败保留、恢复、产物验证与独立验收。未知PE仍需已建立的profile及后续兼容实现，不自动猜测或绕过门禁。

下一主任务转到已固定的Chocolate Doom原Win64 PE，以startup／TLS的reason、状态和ABI小切片建立可验证测试，再根据真实失败修补。第三方应用完整迁移成功数仍为0。工作区忙的专门错误码／可执行下一步、网络冷获取、第二台干净机器、签名公证、长时运行和性能对照继续列为诊断与交付余项；它们不再无限串行阻塞真实输入研究。需要Steam材料时再通知用户，当前目标资料已具备。

## 复现入口

以下在新导出的公开源码根执行；将输入与缓存替换为本机已核对路径。配置与工作区均用新位置，工作区不得预先创建。

```sh
python3.13 -B -m migration_workflow_v1 init \
  --config /absolute/evidence/offline.json \
  --pe /absolute/source/examples/window-switch/switch_tile.exe \
  --identifier org.peaotlab.workflowoffline.v1 \
  --cpu-cache /absolute/verified/cpu-cache \
  --graphics-cache /absolute/verified/graphics-cache --jobs 2
python3.13 -B -m migration_workflow_v1 check /absolute/evidence/offline.json \
  --out /absolute/new-workspace
python3.13 -B -m migration_workflow_v1 build /absolute/evidence/offline.json \
  --out /absolute/new-workspace

# 仅在已有构建结束并核对失败状态后恢复；不要重复build。
python3.13 -B -m migration_workflow_v1 resume /absolute/new-workspace
python3.13 -B -m migration_workflow_v1 verify /absolute/new-workspace
```

以上是普通构建／恢复流程，不自动制造中断。受控中断需要像本批驱动一样确认自己的准确worker身份，不能按进程名发送信号。独立reader必须从与实际安装相同的导出源码根执行；`--session`取实际成功恢复回执里的路径。

```sh
python3.13 -B -m migration_install_v3.review \
  --installation /absolute/new-workspace/offline-install \
  --session /absolute/new-workspace/attempts/attempt-0002/offline-resume \
  --out /absolute/evidence/review-ordinary.json
```

优化模式另加`-O`并使用新输出文件。完整原始现场依赖本机工具链、缓存和native产物，公开源码仓库不分发这些大型文件；缺少现场时只能复查公开实现与报告，不能补造独立读验通过。
