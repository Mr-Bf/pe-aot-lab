# v6 安装前诊断

`migration_doctor_v1` 为新的离线 v6 安装汇总前置条件，不创建安装目录。它与绑定历史工具链/已安装产物的 `migration_env_v1` 不同：本入口接受两份固定缓存、原始 PE/profile、新 work-root/out 和 App identifier，使用 `migration_install_v2` 的当前验证合同。

```sh
python3.13 -B -m migration_doctor_v1 \
  --cpu-cache "$CPU_CACHE" --graphics-cache "$GRAPHICS_CACHE" \
  --pe examples/window-switch/switch_tile.exe \
  --profile examples/window-switch/profile.json \
  --identifier org.peaotlab.install.switch.example.v1 \
  --work-root "$PWD/.local/install-v2-01" \
  --out "$PWD/.evidence/install-v2-01" --jobs 2
```

JSON 写到标准输出；`--out` 是待检查的安装证据目录，**不是 doctor 报告文件**。使用上述 `-B`（或 `PYTHONDONTWRITEBYTECODE=1`）命令时，doctor 不创建或改写 work-root/out、输入、缓存、源码或 Python 字节码；没有 `--report` 选项。需要保留报告时，调用者自行将 stdout 保存到与输入/缓存分离的新文件。诊断会执行有超时限制的 Apple 工具/SDK发现命令，系统工具可能更新自身缓存；它不运行编译器构建、下载、提权、App 或 guest。

结果按 `host_python`、验证模块导入、参数/spec、路径、空间、PE/profile、Apple 工具/SDK、CPU 缓存、图形缓存、安装器资源清单、doctor 源文件快照共11组记录 `PASS` / `FAIL` / `SKIPPED`。每组记录遇到的第一个错误；互不依赖的组继续检查。比如 out 已存在会使路径失败、空间检查跳过，但仍核对 PE、两份缓存与工具。非 Apple Silicon/macOS 环境跳过 Apple 工具发现，但仍尝试可用的文件验证。若当前平台连依赖模块都无法导入，相关组明确跳过。

`implementation` 沿用 v2 扫描器，只记录当前发现的源码/资源摘要；它不能证明所有必需非 Python 头文件、许可或补丁都存在，删除未被 Python 导入引用的资源可能不被该扫描发现。完整性仍需发行清单及 native 构建验证。doctor 自身摘要只对应报告时读到的文件，不证明正在执行的代码身份或整个检查期间源码不变；源文件缺失/不可读会结构化失败，已取得的其他诊断仍保留。

所有项通过时退出 0，状态 `V6_PREREQUISITES_READY_NOT_DECODED_NOT_BUILT`；失败或跳过时退出 2。命令语法错误由 argparse 退出 2。成功仅表示本次前置观测通过，没有解码、native 构建、运行或性能结论。随后仍需执行 `migration_install_v2 plan/install`，安装器会重新核对输入与身份，不能凭 doctor 报告绕过验证。磁盘预算沿用安装器，不是实测峰值保证。

```sh
python3.13 -B -m unittest migration_doctor_v1.test_doctor -v
python3.13 -B -O -m unittest migration_doctor_v1.test_doctor -v
```

测试使用临时输入与小型缓存 fixture；对 PE、路径、磁盘门禁及缓存摘要执行真实代码，SDK发现与外部缓存配置采用受控替身。没有 native、guest、App、GPU 或网络执行。
