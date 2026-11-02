# v7 安装前诊断

`migration_doctor_v2` 对接 `migration_install_v3`，检查新的 `window-lookup-v7` 安装前提。输入仍是 schema2／`win32-d3d11-tile-switch-v1` 的受限 PE/profile，不是新 Windows 兼容契约。旧 doctor v1 及安装器 v2 保持冻结。

```sh
python3.13 -B -m migration_doctor_v2 \
  --cpu-cache "$CPU_CACHE" --graphics-cache "$GRAPHICS_CACHE" \
  --pe examples/window-switch/switch_tile.exe \
  --profile examples/window-switch/profile.json \
  --identifier org.peaotlab.install.lookup.example.v1 \
  --work-root "$PWD/.local/install-v3-01" \
  --out "$PWD/.evidence/install-v3-01" --jobs 2
```

JSON 写到标准输出；`--out` 是待安装证据目录，**不是 doctor 报告文件**。doctor 不创建或修改 work-root/out、输入或缓存，不下载、不提权、不启动builder、App、guest或GPU。使用 `-B` 防止 Python 字节码写入；有限时的 Apple 工具发现命令可能维护系统缓存。需要保存报告时，由调用者将stdout写到与输入/缓存分离的新文件。

输出 schema2 报告中的12组检查：host/Python、v3验证模块及v7产品合同、参数/spec、路径、空间、PE/profile、Apple工具/SDK、CPU缓存、图形缓存、`lookup_runtime`、安装实现清单、doctor源码快照。各组为 `PASS`／`FAIL`／`SKIPPED`；每组记录第一个错误，独立组继续检查。旧v2安装器或v6 builder/status不能提供v7就绪报告。

新增 `lookup_runtime` 调用与安装计划相同的纯 `_lookup_identity()`。它明确读取并校验三份冻结资源：原 `window_bridge/window_runtime/runtime.c`、原 `transaction_v1.c`、新 `window_lookup_v1/lookup_impl.inc`，重新构造唯一查找函数替换，返回 `inline-instruction-search-v1` 身份。文件缺失、内容变化或经符号链接引用均失败，不能靠扫描器“未发现该文件”而遗漏该门禁。这里仅在内存中构造源码，不写overlay，不编译、不执行。

`implementation`仍是当前安装器发现的源码/资源清单，并且安装器自身也执行强制lookup检查。显式三文件门禁不等于所有非Python资源都有完整发行清单；更广的缺失文件检查仍依赖发行清单和实际构建。doctor源码摘要只说明报告时读取的文件，不证明执行中的代码字节或整个检查期间源码一直不变。

12项全部通过时状态为 `V7_PREREQUISITES_READY_NOT_DECODED_NOT_BUILT`，退出0；任一失败/跳过时为 `V7_PREREQUISITES_FAILED_NOT_BUILT`，退出2。之后仍需 `migration_install_v3 plan/install` 重新核对全部门禁，报告不能作为恢复凭据或绕过验证。空间预算沿用安装器保守预留，并非实测峰值保证。

```sh
python3.13 -B -m unittest migration_doctor_v2.test_doctor -v
python3.13 -B -O -m unittest migration_doctor_v2.test_doctor -v
```

19项测试普通／`-O`通过，均未进行native构建或App执行。测试使用实际PE/profile解析、路径/磁盘门禁、部分真实缓存摘要、真实固定lookup资源检查；大型缓存配置与SDK发现使用受控替身。新增反例覆盖旧版本模块/status/builder拒绝、三资源缺失/篡改/符号链接、即使inventory遗漏也必须失败、并行错误保留与CLI非零退出。实际本机诊断和完整安装须另存新证据，不能由这些测试推断成功。
