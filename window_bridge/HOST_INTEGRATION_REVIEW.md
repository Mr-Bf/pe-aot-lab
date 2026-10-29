# 窗口宿主集成独立复审

本次只读审查 `window_bindings.py`、`window_host.c` 和 `window_execution_acceptance.py`，并对照已冻结 Cocoa/User32 接口和原始 `fixture.cpp`。没有启动完整宿主、Windows PE、Cocoa 窗口或 GPU。被审源码身份记录在 `build/window-bridge/consumer-review/reviewed-sources.json`，不把作者后续修改自动算作已审版本。

## 确认的问题与修正

1. **存档观察存在 FIFO 阻塞。** 原 `print_file` 先 `openat(O_RDONLY|O_NOFOLLOW)`，之后才检查 regular file。目录中若已有 FIFO，guest 文件兼容层会拒绝该文件，但结束时的观察函数会卡住；此时内部消息超时循环已经结束。将原函数原文抽取编译后，FIFO 无写端时实际 0.5 秒未返回，独立测试进程被终止并回收。隔离候选增加 `O_NONBLOCK` 后立即拒绝。

   作者已在生产宿主添加 `O_NONBLOCK`。再次从修改后的生产文件抽取原文编译，FIFO（EINVAL）、20B 普通文件（完整字节）、符号链接（ELOOP）三例全部符合预期。证据分别为 `fifo-proof.json` 和 `fifo-fixed-proof.json`；总共 5 次小型文件观察函数执行，**不是五次 guest/窗口运行**。当前修后宿主 SHA `b83c847bf33e98fefab70d8c01ce7db64b2eb846024a40b1ccda2f8f450c1c38`。

2. **退出 API 计数的验收期望错误。** 最初语义验收要求 `files.api_calls_4_to_9 == [1,1,0,1,0,1]`。现有 `wfile_api_calls` 对 signature 9 恒为 0，ExitProcess 在独立进程/D3D session 统计。已通知作者将文件向量修为 `[1,1,0,1,0,0]`，并独立要求 `d3d_before_cleanup.exit_calls == 1`。没有改生产计数来迎合测试。

## 启动、消息与停止

- main 创建 Cocoa owner 并安装 WSI 回调，worker 绑定单一队列 owner 后初始化 image/stack/proxy/map/scratch、D3D/file/callback/User32，最后执行 AOT entry。guest 业务状态仍来自 PE 映像。
- main 在 worker 运行期间持续 pump，包括 worker 的 D3D 和 view 清理阶段。worker 完成后以 release 写 `done`；main acquire 观察后才 join，再执行 Cocoa finish。受审路径没有发现 main 提前 join、停止 pump 导致 worker 同步 dispatch 主线程无法完成的锁顺序问题。这是源码审查结论，不是 TSan 或任意并发调度证明。
- 模拟输入只通过 `wb_host_test_post`，带固定 `TEST_QUEUE=3` 来源；没有直接写 tile position、draws、保存结果。输入需等实际 WSI HWND 已观察、队列进入新的 GetMessage wait、无 pending/paint，避免一批事件直接覆盖中间 render 边界。各条实际发出事件记录 wait 计数。
- `--timeout-ms` 结束消息队列，能唤醒 GetMessage；它不能取消阻塞的 GPU/backend 操作或任意正在执行的 guest 指令。Python 外部 60 秒监督及 terminate/kill 是独立的兜底。外部超时不被记作 clean exit，终止后的不完整日志不应转换为成功。
- 文件路径来自 trusted absolute data directory；观察函数只读已有保存文件。读取到字节本身不能证明本次写入，完整验收还必须核实 guest 的成功保存计数、WriteFile 字节数、真实磁盘内容以及初始目录条件。当前语义验收要求实际 20B WriteFile、Save 成功、磁盘内容等于 guest state，并由根任务在新空目录启动。

## 语义验收对照

原 fixture 从 position=3 开始，左右边界为 0..7，bit30 重复键不移动，keyup 不增加 keydown。主循环在 dirty 时先 Draw/Present，再进入 GetMessage。采用逐条 wait 之后注入的受控输入，`draws >= 1 + moves` 是可解释的下界；真实 expose/paint 可以增加次数，所以不固定 paint 次数。最终 `dirty=0`、`quit_requested=1`、stage=5、保存20B、释放8个应用接口、销毁一个窗口、注销类并调用 ExitProcess(0)，均与原代码匹配。

完整验收先运行 producer 的只读 `verify_run`，绑定实际执行文件、输入依赖、stdout/stderr、返回码和加载库，再读 raw guest observations 做语义判断。低层记录仍称 `ACTUAL_WINDOW_EXECUTION_OBSERVED_NOT_ACCEPTED`，不把结构有效的失败执行标为成功。确定性 TEST_QUEUE 验收要求真实 Cocoa key event 为0，避免实际输入污染被当作模拟序列证明。

当前没有发现除上述已修两项之外的确定阻断。根任务已补上固定 User32 成功调用次数、ValidateRect 与 paint 一致、最终 HWND=0、feature level=11_0、实际 client RECT 的交叉检查；本次对照与原代码一致。当前只读验收脚本 SHA-256 `f93eb92b04133ba3bb1017f46cb7ec807001862823925cec4e31f8453e49e39c`。

本轮仍不证明物理键盘、可见 compositor 内容、像素正确性、加载存档、Windows 原机兼容性或性能。真实窗口集成的后续记录应单独验收，不能从本只读审查升级得到。
