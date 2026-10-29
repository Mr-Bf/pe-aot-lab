# 源码导出范围

当前窗口switch入口为 `migration_v6`、`window_switch_v1` 与 `migration_run_v3`；基础及旧profile入口为 `migration_cache_v2`、`portable_graphics_v2`、`portable_lifter_v1`、`migration_v5`、`migration_install_v1`。保留被这些模块复用的旧源码目录、所有实际补丁、锁、C/C++ runtime 和 shader header。

此目录是独立源码快照，没有原仓库 `.git`、`build/`、`work/`、运行日志或已安装 provider。唯一初始二进制例外是 `examples/integer-tile/integer_tile.exe`，其第一方来源与 SHA 已记录。README 与剩余工作清单由主维护者单独撰写；本轮收口的 switch 实验源码已单独同步。

部分保留的旧 helper/test 仍引用历史 evidence，它们用于理解既有边界，不属于独立公开仓库的默认测试入口。尤其 `portable_app_v1/test_lift.py`、`test_producer.py`、`migration_v5/test_boundaries.py`、`migration_install_v1/test_install.py` 需要历史产品；请勿把全仓库 unittest discover 当作自包含 CI。公开排除依赖私有 build parser 的 `portable_graphics_v2/review_build.py`、历史公开获取 reviewer，以及包含本机绝对路径的 `window_profile_v1/derivation.json`。

核心 CLI help、样例 analyze 和静态资源闭包 smoke 只说明该源码导出的入口与资源完整；不是重新编译所有 C++、运行 App、干净机器或性能验证。历史 fixture C++→PE 生成入口仍有旧工具链依赖，公开示例提供了已登记自产 PE 供重现迁移构建。


## 历史研究与后续追加

`docs/RESEARCH.md`、`docs/REVIEW.md`、`research/code-review.md` 是 2026-10-27 的历史研究/代码核对快照，原文保留；其中当时的阶段描述或建议不是当前进度。当前能力、许可证固定版本与未完成项以根 README、REMAINING、THIRD_PARTY 为准。

追加的 `examples/switch/` 含两个明确登记的自产 PE 与候选 packet；三个 switch fixture 目录只保留真实源码/构建脚本，其公开 README 单独撰写以移除本机路径。`switch_aot_v1` 在本轮参数接口最终冻结后同步；不能用这些输入的存在代替其正确性证据。


## 参数化源码与历史 native 证据的区别

公开 switch harness/test/oracle 增加显式 PE 参数或输入目录，以读取公开 examples。历史 288 次正常 ARM64 / 144 次原 x86 对照绑定的是原实验中保存的源码；后续仅参数化的公开接口做纯 Python 测试与 CLI 检查，未重新执行完整 native 差分，不改写历史收据 SHA。原始 x86 capture assembly `d3d11_bridge/scalar_oracle.S` 也原样保留；它只用于明确的测试 oracle。


## 正式窗口switch追加

本轮追加window_switch_v1、migration_v6、migration_run_v3、switch_window_fixture_v1及examples/window-switch登记自产PE。窗口runtime/host新增编译时AOT_WINDOW_SWITCH_V1挂点；未启用宏的旧路径继续拒绝kind5。旧scalar _prove只有默认保持entry要求的私有复用钩子，旧公开入口仍拒绝带imports或非entry输入。

新源码及组件probe可复用已有固定provider；不携带provider安装、macOS/Windows SDK、原始App数据或构建日志。公开CLI/测试重跑与原本机native/App执行证据各自保存，不回填旧收据。

静态资源审查额外补齐了保留的 `window_profile_v1/build.py` 所引用的 `migration_v3/__init__.py` 和 `migration_v3/__main__.py` 两个第一方纯 Python 文件；这仅补足旧源码快照引用，不代表旧 CLI 整链重新运行或新增兼容能力。
