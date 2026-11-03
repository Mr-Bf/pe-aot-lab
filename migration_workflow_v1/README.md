# 用一份配置完成迁移构建

`migration_workflow_v1`统一配置、前置检查、构建、失败恢复和产物验证。当前复用v7的受限转换能力，支持的是已建立合同的自产Windows PE；真实第三方游戏适配另行推进。生成配置或前置检查通过，都不代表未知PE能够转换。

所有命令都不会自动启动App。实际运行仍是独立、显式的验收步骤。

## 已有provider：最短流程

在仓库根目录运行。将下面两个provider路径替换为已经验证的实际路径；CPU路径必须是支持window-switch的overlay provider，其父CPU base仍需保留在原位置。

```sh
mkdir -p build
python3.13 -B -m migration_workflow_v1 init \
  --config conversion.json \
  --pe examples/window-switch/switch_tile.exe \
  --identifier org.peaotlab.converted \
  --cpu-prefix /absolute/verified/switch-provider \
  --graphics-prefix /absolute/verified/graphics-provider

python3.13 -B -m migration_workflow_v1 check conversion.json \
  --out build/workflow-conversion-01

python3.13 -B -m migration_workflow_v1 build conversion.json \
  --out build/workflow-conversion-01

python3.13 -B -m migration_workflow_v1 status build/workflow-conversion-01
python3.13 -B -m migration_workflow_v1 verify build/workflow-conversion-01
```

先检查`check`结果，再执行`build`。`check`也可写为`plan`；两者的`--out`表示拟建工作区，仅输出JSON，不创建这个目录、报告文件或开始构建。`plan`还列出阶段及对应build命令。三个命令均要求工作区不存在且父目录已存在；示例先用`mkdir -p build`准备父目录，不预建`workflow-conversion-01`。已有工作区会报`OUTPUT_EXISTS`，应改用`status`／`verify`／`resume`。最终产品和App路径以成功JSON为准。

这份示例不传`--profile`，配置中的`profile`为`null`。只有PE摘要匹配仓库固定的window-switch自产样例时，工具才选用现有recipe/profile。它不会根据未知PE猜测入口、API或图形合同，也不会自动生成第三方profile。其他输入必须显式提供已建立的profile：

```sh
python3.13 -B -m migration_workflow_v1 init \
  --config another-conversion.json \
  --pe inputs/app.exe --profile inputs/profile.json \
  --cpu-prefix /absolute/verified/switch-provider \
  --graphics-prefix /absolute/verified/graphics-provider
```

提供profile只满足配置前提，仍必须通过PE/profile合同及后续提升、构建门禁。不要把其他样例的profile复制给一个未知程序以绕过诊断。

## 配置与路径

`init`只创建新的配置文件，父目录须已存在，已有文件不覆盖。它返回`MIGRATION_CONFIG_CREATED_NOT_CHECKED`，不会因此确认PE、profile或依赖已经可用。以下是providers模式的完整结构：

```json
{
  "schema": 1,
  "pe": "examples/window-switch/switch_tile.exe",
  "profile": null,
  "identifier": "org.peaotlab.converted",
  "build": {
    "mode": "providers",
    "cpu_prefix": "/absolute/verified/switch-provider",
    "graphics_prefix": "/absolute/verified/graphics-provider"
  }
}
```

配置中的所有相对输入／依赖路径都以**配置文件所在目录**为基准，与执行命令时的当前目录无关；`init`中提供的这些路径也按这一规则写入和理解。例如，配置在`jobs/conversion.json`时，`"pe": "../inputs/app.exe"`指向`inputs/app.exe`，不是`jobs/inputs/app.exe`。配置路径不会展开`~`或`$VAR`，请写普通相对路径或绝对路径，并使用不经过符号链接的路径。CLI的config／workspace／`--out`参数若为相对路径，则按调用时cwd解析；换目录执行时建议使用绝对路径。

`identifier`可在`init`省略，默认`org.peaotlab.converted`。它是App标识，不是游戏兼容开关。配置版本为`schema: 1`；两种build模式互斥，不能混填缓存和provider字段。

## 离线缓存：重建完整依赖链

缓存是用于构建provider的固定输入；provider是已经构建、带有验证收据的依赖产物。两种目录不能互相替代。已有有效provider时优先使用上一节流程；需要重建整条依赖链时才使用offline模式：

```sh
mkdir -p build
python3.13 -B -m migration_workflow_v1 init \
  --config offline-conversion.json \
  --pe examples/window-switch/switch_tile.exe \
  --cpu-cache /absolute/verified/cpu-cache \
  --graphics-cache /absolute/verified/graphics-cache \
  --jobs 2

python3.13 -B -m migration_workflow_v1 check offline-conversion.json \
  --out build/workflow-offline-01
python3.13 -B -m migration_workflow_v1 build offline-conversion.json \
  --out build/workflow-offline-01
```

该配置的`build`为：

```json
{
  "mode": "offline",
  "cpu_cache": "/absolute/verified/cpu-cache",
  "graphics_cache": "/absolute/verified/graphics-cache",
  "jobs": 2
}
```

`jobs`只接受1或2。offline委托已有`migration_install_v3`，从CPU／图形离线缓存重建provider和App。缓存、工具链、SDK与空间检查仍然执行；填写路径不会自动下载或安装缺失依赖。完整安装比复用provider需要更多磁盘和构建时间，失败尝试也保留。

## 失败后恢复

对同一工作区使用`status`查看已记录状态，再执行`resume`：

```sh
python3.13 -B -m migration_workflow_v1 status build/workflow-conversion-01
python3.13 -B -m migration_workflow_v1 resume build/workflow-conversion-01
python3.13 -B -m migration_workflow_v1 verify build/workflow-conversion-01
```

- **providers模式：**重新验证输入与依赖身份，在新的attempt目录完整重建App，不复用未完成的编译目录。
- **offline模式：**沿用安装器的分阶段恢复；成功阶段重验后才可复用，失败阶段分配新attempt，原失败日志保留。

若最近一次attempt已经成功，`resume`会在重验后复用其完成产物，不重复构建。若协调器结束但已登记worker留下完整成功结果，也必须先验证进程组已消失和产物有效，才可接受该结果。

不要向已有工作区再次执行`build`，也不要覆盖或删除失败attempt来伪装新安装。恢复会重读原始config、PE、profile、实现及相关依赖身份，工作区路径也不能改名；需要应用不同输入或配置时，新建工作区。仍有构建进程、身份发生变化或恢复记录无法验证时，应先按明确诊断处理，不能只因等待一段时间就认为可以恢复。

`verify`检查工作区所记录的产物及身份，不启动App。静态验证成功与实际窗口、输入、存取档、性能验收分别记录。

## 怎样读结果

正常结果及`check`报告写到stdout。检查失败项和命令异常包含`stage`、`code`、`message`、`error_type`；`field`和`next_action`在有具体信息时给出，也可能为null。命令拒绝或中断写到stderr；参数语法错误可能是usage文本，不是JSON。构建失败另外记录`attempt`及`failure`或worker状态，完整下层结果和日志保留在对应attempt。`check`的独立组以`PASS`／`FAIL`／`SKIPPED`记录，不把因前置失败跳过的检查当作通过。

退出码0表示本命令成功，2表示输入／前置条件阻断，1表示构建失败。被键盘中断时退出130，worker状态仍需核对，不能重复build。核心状态如下：

| 状态 | 含义 |
|---|---|
| `MIGRATION_READY_NOT_DECODED_NOT_BUILT` | check／plan前置检查通过，尚未提升指令或构建App |
| `MIGRATION_BLOCKED` | 至少一个前置检查失败或被跳过 |
| `MIGRATION_COMMAND_REJECTED` | 配置、命令或验证被明确拒绝，具体原因在stderr JSON |
| `MIGRATION_BUILD_FAILED` | 本次构建未成功，保留attempt和下层失败信息 |
| `MIGRATION_APP_BUILT_VERIFIED_NOT_EXECUTED` | 构建并验证产物成功，本流程未启动App |
| `MIGRATION_APP_VERIFIED_NOT_EXECUTED` | verify重新核对已完成产物成功，未启动App |
| `MIGRATION_STATUS_OBSERVATION_NOT_VERIFIED` | 只读取已记录状态，不替代verify |

`status`退出0只表示读取成功；还需查看`latest_recorded_result`，不能据此宣称构建成功。

| 情况 | 应采取的动作 |
|---|---|
| `PROFILE_REQUIRED` | 输入没有命中固定自产recipe；提供为该PE建立的profile，或先开展适配分析。不是让工具猜一个profile |
| 显式profile路径不存在或内容无效 | 检查按配置目录解析后的路径和profile格式；不要把它解释为指令兼容性结论 |
| PE/profile合同不被接受 | 查看下层原始诊断；当前工具范围没有因统一入口而扩大 |
| provider角色／身份不符 | 确认CPU overlay、父base及图形provider；缓存目录不能填作provider |
| 离线缓存、SDK或工具缺失 | 按具体缺项准备依赖，再重新`check`；不会自动下载或全局安装 |
| `OUTPUT_EXISTS` | check／plan／build需要新工作区；已有产物用`verify`或`status`，未完成任务用`resume` |
| 恢复时身份或进程状态无法验证 | 保留原工作区，根据诊断核对实际依赖与构建进程；不覆盖旧证据 |

当前能力、验证记录与已知限制见[本批报告](../docs/MIGRATION_WORKFLOW_V1.md)。底层版本化CLI继续保留供开发和追溯使用；新用户从本入口开始，不需要逐个拼接这些命令。
