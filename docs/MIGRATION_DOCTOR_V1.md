# v6 安装前置诊断验收

日期：2026-11-02。新增 `migration_doctor_v1` 已完成实现、边界测试、本机正负诊断及独立审查。它面向 v6 的显式缓存、PE/profile 和新安装目录；较早 `migration_env_v1` 的固定 v4 路径诊断保持原样。

## 行为与边界

入口与完整参数见 [README](../migration_doctor_v1/README.md)。`python3.13 -B -m migration_doctor_v1` 将 11 个检查组分别报告为 PASS、FAIL 或 SKIPPED。路径失败只阻止依赖路径的磁盘检查；输入、两份缓存及其他独立组继续执行。全部通过退出 0，否则退出 2。输出为 stdout JSON，`--out` 是待安装的证据目录参数，不是本次诊断的报告文件，不会创建它或 work-root。

检查覆盖宿主/Python、validator 导入、参数、路径、磁盘预留、PE/profile 准入、Apple 工具/SDK、CPU 缓存、图形缓存、当前实现清单及诊断器源文件快照。实际是 11 组：宿主/Python 合为一组，其余逐项列示。各组记录第一个错误，独立组继续；Apple 查询失败当前提供失败命令定位，尚未单独保留失败查询的完整 stdout/stderr。

只读保证按上述 `-B` 调用解释；不用 `-B` 时 Python 可能写入 `__pycache__`。Apple 工具发现可能使用系统缓存。实现清单是现存文件的身份扫描，不能检测全部已删除但未被 Python 导入引用的资源；诊断器摘要是报告时的磁盘快照，不证明运行中加载的代码或全程不变。安装器仍执行自己的准入、构建和验证。

## 已运行证据

| 验收 | 实际结果 |
| --- | --- |
| 实现测试 | 普通/`-O` 各 14 项通过，源码前后摘要相同；未运行 native builder/App/GPU。 |
| 独立反例 | 最终普通/`-O` 各 14 项通过，覆盖缺源码仍保留 JSON、多组失败、依赖跳过、bool/jobs 拒绝、CLI 返回码及文件写入封锁。最终轮共 4 个隔离 Python CLI 子进程；较早审查另有 4 个，单独保留。 |
| 本机正例 | 11 PASS，退出 0；既有固定缓存、实际 Apple 工具和本项目窗口 PE。 |
| 本机负例 | 临时损坏 CPU 缓存和不存在的 PE 产生 paths/pe_profile/cpu_cache 三 FAIL，disk 为 SKIPPED，其余 7 PASS，退出 2；图形缓存仍独立通过。 |
| 目录与身份 | 两次诊断前后 work-root/out 均未创建；生产/测试/README 五文件摘要一致。 |

两次本机诊断各保存 9 条成功的 Apple 工具发现查询，共 18 条；它们不是编译、guest 或 App 执行。复核发现的末尾源摘要读取异常会丢失整个报告的问题已修复：现在是独立的 `doctor_source_snapshot` 失败项，其他分项 JSON 保留。

本机证据位于 `build/migration-doctor-v1/`：

- `unit-01/result.json`：`df858526bec691d5f95488e9a9141f71c87e5e31bb7d59ef883be9e8dd1efbc7`。
- `peer-review-01/result-02.json`：`c6d04ae5c13c3034f1accd108de3b5fca6fd2ac5c56260700871af99f815ce92`。
- `actual-01/result.json`：`6d28a0c0cffdf50b4a84e6d8999d2e2501f34d95953f7fda724b02c43a13f19b`。

本轮不新增指令、Windows API 或图形兼容能力，不据此得出性能、实际游戏或干净机器结论。公开源码整链复现另见 [独立目录验收](PUBLIC_REPRODUCTION_V1.md)。
