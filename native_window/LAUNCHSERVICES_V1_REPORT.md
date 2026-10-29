# 同一冻结 App 的 LaunchServices 对照

状态：**TIMEOUT；没有进入应用入口的证据，没有窗口/GPU/画面通过结论。** 本次没有修改 `native_window` v1 宿主源码，也没有覆盖正式 direct-exec 的失败记录。

在读取本机 `/usr/bin/open -h`、确认 `-n -W --stdout --stderr --env` 选项后，通过系统 LaunchServices 启动同一 `PE AOT Window Probe.app`。设置了 60 秒超时和独立输出，脚本与精确命令保存于 `build/native-window/probe-launchservices-v1/`。这是已批准的本机执行；显式 `--env` 提供实验环境变量，但不是对 LaunchServices 全部环境的完整证明。`open -W` 也不会替代独立记录的 child exit code。

- 执行 session **26231** 返回终态。记录为 `LAUNCHSERVICES_TIMEOUT`，没有 child JSON。
- child PID **5682** 的 stdout 始终为空；stderr 只记录了 executable 自身的一条 dyld 身份公告，尚无完整库闭包。
- 1 秒只读 `sample` 的 659 个样本均停在主线程 `dyld4::JustInTimeLoader::loadDependents → mapFileReadOnly → __open`，而非 `main`、Cocoa 创建函数或 D3D/Metal 调用。保存 `child-sample.txt`。
- 超时后先用 `ps -p 5682 -o command=` 核对完整测试可执行路径，再向本次自己的进程发 SIGTERM；1 秒后定向 ps 返回 1、无输出，确认已退出。保存 `cleanup.json`。
- 没有调用 CUA，没有取得截图，没有更改系统权限，也没有定位具体 `__open` 阻塞文件或操作系统原因。

这条对照没有证明 v1 的 `setActivationPolicy` 失败原因，也不是 Draw 生命周期问题的证据。它说明当前使用工作区绝对动态库路径的 bundle 尚不能按可交付 App 验收。下一步应在独立 v2 中把真实非系统库闭包放进 App 的 Frameworks，修正 install-name/rpath、签名并验证实际闭包；不能通过删除失败检查或反复启动同一路径制造 PASS。
