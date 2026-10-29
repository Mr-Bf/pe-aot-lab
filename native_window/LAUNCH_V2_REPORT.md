# 原生窗口 v2 App 搬移运行记录

本轮实际从 `/private/tmp/PE AOT Window V2 7la4igpw/Window Relocated.app` 启动了两个进程。包内 ARM64 executable 和三个非系统库成功加载，但两个进程都在 Cocoa 初始化检查退出；本轮没有窗口、GPU、Draw、guest PE 或 compositor 验证通过。

## 可复现实验与结果

生产包装器、v1 Cocoa 源码和 DXMT 后端均未修改。新执行脚本为 `build/native-window/launch-v2/run.py`，准备阶段复制完整签名 App，逐文件核对内容与权限、实际 load-command 图和严格签名。另一代理独立验证还核对源库与打包库所有 file-backed Mach-O section 内容相同；仅安装名、load commands 与签名发生允许的包装变更。

```sh
/opt/homebrew/bin/python3.13 build/native-window/launch-v2/run.py prepare
/opt/homebrew/bin/python3.13 build/native-window/launch-v2/run.py direct
/opt/homebrew/bin/python3.13 build/native-window/launch-v2/run.py launchservices
```

脚本拒绝覆写已存在的运行记录。以上是已执行命令，不应重新执行覆盖正式证据。

| 启动方法 | 进程 | 实际结束信息 | child 输出 |
|---|---:|---|---|
| 直接启动包内程序 | 9729 | 独立 child exit = 1；未超时 | 原生探针 `Cocoa_application` FAIL |
| LaunchServices `open -n -W` | 9800 | launcher exit = 0；child exit 未独立观测；未超时 | 同一原生探针 `Cocoa_application` FAIL |

这里输出来自**原生**探针，表中不代表 Windows guest 已执行。两次 `phases_done=0`，所有 D3D HRESULT 均为 null，registry 创建数为 0。两份 dyld 日志各 887 行，严格解析后实际非系统映像恰为临时 App 内 executable 与三个库，没有加载 Documents/work 中原库。构建输入、临时包字节和文件权限在运行前后相等。运行后只读 `ps` 均返回 1 且无对应 PID；未留下测试进程。

每次执行均设置 60 秒上限，记录 stdout/stderr 与启动命令。初次默认环境不允许 `/bin/ps`，随后只对两个测试 PID 使用获准的只读检查；这不改变运行结果。

主要证据位于 `build/native-window/launch-v2/`：`prepared.json`、`copy-signature.json`、`direct.json`、`launchservices.json`、两份独立 stdout/stderr、`postrun-review.json`、`final-receipt.json`。独立静态审计位于 `build/native-window/probe-v2-package3-review/evidence.json`。

## 边界

本轮证明 App 可以从工作区外搬移并实际装入所需库。它没有证明该版本的窗口初始化成功，也没有证明屏幕显示、跨机器分发、Developer ID、公证或 Gatekeeper 接受。`isVisible` 本身也不等于 compositor 截图。本轮没有调用 CUA。

后续隔离的两进程诊断已发现 Cocoa 检查对“初始已是 Regular”的错误处理，详见 `ACTIVATION_DIAGNOSTIC.md`。它是新证据，不覆盖本轮两次真实失败。
