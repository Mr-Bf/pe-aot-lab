# 源码导出范围

当前完整安装入口为 `migration_install_v2`，窗口switch低层入口为 `migration_v6`、`window_switch_v1` 与 `migration_run_v3`；基础及旧profile入口为 `migration_cache_v2`、`portable_graphics_v2`、`portable_lifter_v1`、`migration_v5`、`migration_install_v1`。保留被这些模块复用的旧源码目录、所有实际补丁、锁、C/C++ runtime 和 shader header。

当前源码发行506文件：公开 `99a271d` 的499文件加上5个 `migration_doctor_v1` 文件和2份验收报告。完整native构建与新App运行绑定499文件的原提交；新增doctor单独完成测试和实际预检，不能将其追加推断为506文件重新完整构建通过。见 [公开源码复现](docs/PUBLIC_REPRODUCTION_V1.md)及[doctor验收](docs/MIGRATION_DOCTOR_V1.md)。

此源码导出不携带原私有仓库Git历史、`build/`、`work/`、运行日志或已安装provider。四个第一方PE例外为 `examples/integer-tile/integer_tile.exe`、`examples/switch/switch8.exe`、`examples/switch/switch8_variant.exe`、`examples/window-switch/switch_tile.exe`，各自来源和SHA在样例目录登记；不包含第三方游戏二进制。README与剩余工作清单单独维护，历史实验源码按发行范围保留。

部分保留的旧 helper/test 仍引用历史 evidence，它们用于理解既有边界，不属于独立公开仓库的默认测试入口。尤其 `portable_app_v1/test_lift.py`、`test_producer.py`、`migration_v5/test_boundaries.py`、`migration_install_v1/test_install.py` 需要历史产品；请勿把全仓库 unittest discover 当作自包含 CI。公开排除依赖私有 build parser 的 `portable_graphics_v2/review_build.py`、历史公开获取 reviewer，以及包含本机绝对路径的 `window_profile_v1/derivation.json`。

核心 CLI help、样例 analyze 和静态资源闭包 smoke 只说明该源码导出的入口与资源完整；不是重新编译所有 C++、运行 App、干净机器或性能验证。历史 fixture C++→PE 生成入口仍有旧工具链依赖，公开示例提供了已登记自产 PE 供重现迁移构建。

公开 `99a271d` 后续已从本地Git archive导出到同机独立目录，使用既有固定缓存新建全部provider/App并完成运行；这一实际native证据与上述源码smoke分开。它不是联网clone/冷下载、另一机器或bit-repro验证。安装器公开实现身份清单为210项，不要求与私有历史302项相等；独立审查核对交集摘要及实际命令来源，没有将差集当成未验证的兼容能力。


## 历史研究与后续追加

`docs/RESEARCH.md`、`docs/REVIEW.md`、`research/code-review.md` 是 2026-10-27 的历史研究/代码核对快照，原文保留；其中当时的阶段描述或建议不是当前进度。当前能力、许可证固定版本与未完成项以根 README、REMAINING、THIRD_PARTY 为准。

追加的 `examples/switch/` 含两个明确登记的自产 PE 与候选 packet；三个 switch fixture 目录只保留真实源码/构建脚本，其公开 README 单独撰写以移除本机路径。`switch_aot_v1` 在本轮参数接口最终冻结后同步；不能用这些输入的存在代替其正确性证据。


## 参数化源码与历史 native 证据的区别

公开 switch harness/test/oracle 增加显式 PE 参数或输入目录，以读取公开 examples。历史 288 次正常 ARM64 / 144 次原 x86 对照绑定的是原实验中保存的源码；后续仅参数化的公开接口做纯 Python 测试与 CLI 检查，未重新执行完整 native 差分，不改写历史收据 SHA。原始 x86 capture assembly `d3d11_bridge/scalar_oracle.S` 也原样保留；它只用于明确的测试 oracle。


## 正式窗口switch追加

本轮追加window_switch_v1、migration_v6、migration_run_v3、switch_window_fixture_v1及examples/window-switch登记自产PE。窗口runtime/host新增编译时AOT_WINDOW_SWITCH_V1挂点；未启用宏的旧路径继续拒绝kind5。旧scalar _prove只有默认保持entry要求的私有复用钩子，旧公开入口仍拒绝带imports或非entry输入。

新源码及组件probe可复用已有固定provider；不携带provider安装、macOS/Windows SDK、原始App数据或构建日志。公开CLI/测试重跑与原本机native/App执行证据各自保存，不回填旧收据。

静态资源审查额外补齐了保留的 `window_profile_v1/build.py` 所引用的 `migration_v3/__init__.py` 和 `migration_v3/__main__.py` 两个第一方纯 Python 文件；这仅补足旧源码快照引用，不代表旧 CLI 整链重新运行或新增兼容能力。


## 离线install-v2追加

追加migration_install_v2生产协调器、独立reader、边界测试及显式recovery_probe/recovery_attach实验。安装器捕获自身实际Python闭包及非Python构建资源；独立reader/test/probe不混入生产实现身份。恢复实验会针对自行核对的本次图形worker发SIGTERM，属于显式测试入口而非自动重试，不作为普通安装必经步骤。

公开不携带缓存、安装provider、App、运行日志或用户AppData。真实M2从固定缓存的构建/恢复/运行证据与公开源码Python检查分别记录，不能互相替代。

## v6安装前诊断追加

追加 `migration_doctor_v1` 的三个生产Python文件、README及独立测试文件，以及两份验收报告。诊断器调用现有v2只读验证入口，分别报告11组PASS/FAIL/SKIPPED，stdout JSON，不创建安装work-root/out，不自动启动builder或App。

项目文件只读承诺按文档的 `-B` 或 `PYTHONDONTWRITEBYTECODE=1` 调用解释；普通无-B运行可生成pycache，Apple发现可能维护系统缓存。implementation清单是扫描所得，不是必需资源完整性证明；doctor自身摘要是报告时的文件快照，不是加载代码身份或全过程稳定性证明。预检完成不能绕过安装准入，也不新增ISA/ABI/图形兼容范围。
