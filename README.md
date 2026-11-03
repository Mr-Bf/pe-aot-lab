# PE AOT Lab

将受限的Windows x86-64 PE在构建期翻译为Apple Silicon ARM64代码，打包为macOS App。项目以正确性与性能为目标；既有版本已经跑通自产窗口PE的原生App闭环，一般Windows／Steam游戏仍未支持。

**开发入口统一为 [`migration_workflow_v1`](migration_workflow_v1/README.md)：一份配置完成init、check、build、resume和verify。** 固定已支持输入的迁移脚本MVP已完成同机静态交付闭环，覆盖既有provider与固定缓存offline两条路线、失败恢复和独立产物复核。工作流不自动启动App。

本轮从本地公开提交`7db91d2`的639文件完整导出到新源码目录，建立新CPU／switch／graphics provider；首次App阶段受控中断后，统一resume重验复用成功阶段并生成新App。整链经恢复完成，独立安装reader普通／`-O`报告逐字节相同；103个原失败文件保持不变。详见[离线整链与恢复报告](docs/MIGRATION_WORKFLOW_OFFLINE_V1.md)。本轮没有修改生产源码或新增App／guest／GPU执行，不是网络冷获取、第二台干净机器或性能验收；本地交付，不推送。

下一主任务是固定Chocolate Doom原PE的startup／TLS reason、state与ABI切片。锁占用诊断、冷获取、第二机器和签名等交付余项继续保留，不再阻塞开始真实输入适配。未知PE不会自动生成profile，第三方迁移成功数仍为0。

## 从一份配置开始

需要Apple Silicon macOS、Python 3.13、所选Xcode／Metal SDK，以及已验证的CPU switch overlay和图形provider。仓库不携带这些大型依赖。将两个占位路径替换为实际路径；CPU overlay依赖的父base须保留原位置。在仓库根目录执行：

```sh
mkdir -p build
python3.13 -B -m migration_workflow_v1 init \
  --config conversion.json \
  --pe examples/window-switch/switch_tile.exe \
  --cpu-prefix /absolute/verified/switch-provider \
  --graphics-prefix /absolute/verified/graphics-provider
python3.13 -B -m migration_workflow_v1 check conversion.json --out build/conversion-01
python3.13 -B -m migration_workflow_v1 build conversion.json --out build/conversion-01
python3.13 -B -m migration_workflow_v1 verify build/conversion-01
```

先确认check通过，再执行build。config与工作区都使用新路径；check／plan仅向stdout输出JSON，不创建拟建工作区或报告文件。已有任务可用：

```sh
python3.13 -B -m migration_workflow_v1 status build/conversion-01
python3.13 -B -m migration_workflow_v1 resume build/conversion-01
```

配置内路径按配置文件目录解析。示例省略profile时，仅PE摘要完全匹配仓库固定自产样例才选择已有recipe；未知PE必须提供已审核profile，工具不会猜测或生成第三方profile。只备有离线缓存时，使用同一入口的offline模式重建provider，详见[完整配置、离线模式与错误处理](migration_workflow_v1/README.md)。

**build、resume和verify均不自动启动App。** 构建成功状态为`MIGRATION_APP_BUILT_VERIFIED_NOT_EXECUTED`；实际运行、交互与性能分别验收。providers恢复新建attempt重建未完成App，offline恢复沿用安装器阶段协议，旧失败证据保留。

## 能力边界

- 已有原生运行证据来自固定自产PE、有限Win32／COM／D3D11合同和明确的回调／switch范围；不等于通用Windows运行时。
- 首个真实第三方输入已固定为Chocolate Doom 3.1.1官方Win64包，34个PE完成静态盘点；主程序入口及TLS根的保守图已经独立核对。**第三方游戏迁移成功数仍为0**，静态解码不计为AOT或运行成功。
- CRT／多模块装载、一般TLS／SEH／线程、间接目标、广泛SIMD和图形资源等仍有缺口。未知能力必须明确拒绝或保留未解析项。
- 已验自产App的ARM64执行路径不依赖Rosetta；部分原始字节差分借助Rosetta，不能当作Windows或Wine游戏性能基线。尚无代表性游戏FPS或整体提速结论。
- 研究使用合法输入，不做DRM／反作弊绕过；仓库不分发商业游戏、Steam SDK或Apple SDK。

## 资料导航

- [单配置工作流](migration_workflow_v1/README.md)：新任务从这里开始；[离线整链与恢复](docs/MIGRATION_WORKFLOW_OFFLINE_V1.md)记录本轮结果，[已有provider工作流](docs/MIGRATION_WORKFLOW_V1.md)保留上一批证据。
- [剩余工作](REMAINING.md)：受限脚本MVP已闭合，下一主任务为真实原PE的startup／TLS边界切片；发行余项单列。
- [能力与验收队列](REMAINING.md)：按可验证能力推进，不按周数或估算百分比汇报。
- 历史构建／运行：[v7离线安装与恢复](docs/MIGRATION_INSTALL_V3.md)、[公开源码同机复现](docs/PUBLIC_REPRODUCTION_V1.md)、[真实运行监督](migration_run_v4/README.md)。各报告只证明其冻结版本。
- 历史CPU／ABI研究：[正式lookup集成](docs/WINDOW_LOOKUP_V1.md)、[同地址ABI重放](docs/WINDOW_OUTER_REPLAY_V1.md)。局部性能不能外推为游戏收益。
- 真实输入研究：[PE／依赖库存](docs/REAL_TARGET_INVENTORY_V1.md)、[原PE控制流需求](docs/REAL_PE_CFG_V1.md)。它们用于后续适配，不是现阶段用户构建入口。
- [路线研究](docs/RESEARCH.md)与[反证审查](docs/REVIEW.md)：公开资料及研究时点结论。

历史实验常依赖未公开的大型原始产物，不建议刚clone后运行全仓`unittest discover`。按对应模块列出的前提与命令验证；缺少历史产物时说明无法复核，不补造成功。

## 许可与发行

原创部分采用[MIT](LICENSE)。第三方代码和派生产物遵守各自固定版本许可，见[第三方归属](THIRD_PARTY.md)。公开内容是源码、依赖配置、补丁和小型自产样例；完整工具链缓存、私有实验现场及预构建游戏App不在本源码发行中。
