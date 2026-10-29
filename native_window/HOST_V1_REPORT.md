# Native window v1 宿主事实报告

**当前没有正式 App 验收通过。** 未打包的探索可执行文件完成了真实 clear/Present0/resize/cleanup；随后相同宿主的正式 `.app` 直接执行在 `Cocoa_application` 初始化阶段失败。两者证据分开保留，不能把探索 PASS 当成正式 App PASS。

## 已执行的范围

`build/native-window/probe-exploration/smoke.json` 记录未打包 ARM64 探索程序的第二次运行，SHA `058ff697c772543d8be469158f3ab609cf584877d49daf0d8992f866216f1a75`。它的机器可读状态保留 `EXPLORATORY_NOT_FINAL`；内部实际结果为 PASS：

- 实际原生 ARM64 进程，`sysctl.proc_translated=0`。
- Cocoa 主线程持续处理事件；工作线程执行 D3D11、真实 factory2/swapchain、清屏和 `Present(0,0)`。
- 640×360 和 800×450 两相，合计 590,400 个像素 / 2,361,600 个通道读回，误差为 0；按 API RowPitch 读取。Present 后 EVENT query 返回 GPU 完成。
- 未登记 HWND 精确返回 `DXGI_ERROR_INVALID_CALL`；v1 不支持的 Present 同步间隔 1 精确返回 `DXGI_ERROR_UNSUPPORTED`。
- 关闭是测试主动发出的 `performClose:`，先记录停止请求、保留活动 view，工作线程释放 swapchain 后才销毁 window。13 个应用 COM 引用释放，view 创建/释放各 1、活动 view 0、window 已 tombstone。
- 首轮探索在检查 Present1 时因测试预期错误提前停止：实际已经拒绝为 UNSUPPORTED，测试当时错误要求 INVALID_CALL。失败源、二进制和原始输出保存于 `probe-exploration/history/unsupported-vsync-expectation/`，之后只改测试期望，没有改后端返回码。

## 正式 App 失败与停止的观察

正式构建成功：`build/native-window/probe-v1/build.json`。该 App 仍使用工作区绝对库路径，明确不是可搬移/分发的最终游戏 App。

执行命令为 `python3.13 native_window/probe.py run --hold-ms 10000`，使用已批准的 `require_escalated` 本机执行环境，工具 session **60849**。该 session 已返回终态 exit 1。真实记录：

| 文件 | SHA-256 |
|---|---|
| host.json | `de4210a35adc62bcd46b5fa226e9991452445733631fd5b1e180fafbab96fc77` |
| host.stdout | `6addfe8a3735a8c2fc6675366fbb946f102004491f05d01e895f83d284b253a2` |
| host.stderr | `3cc6ec599683a7ece5a04c885a67fea577a71d7384854d220a29c1d08db46d86` |

`host.json` 为 FAIL，错误为 `native window execution failed`；真实 stdout 的 `failure_stage` 是 `Cocoa_application`，所有 D3D HRESULT 为 null、phases 为 0、registry created 为 0。此次正式运行没有 D3D 调用或创建测试窗口。wrapper 的失败分支没有保存子进程 returncode，不能把工具最终 exit 1 伪称成独立保存的 child exit 记录。

源码的 `nw_registry_create()` 在主线程身份检查或 `setActivationPolicy` 返回 false 时会返回空指针。目前没有额外诊断区分该调用的前后 policy；可能与直接启动 bundle 内 binary 的应用初始化方式有关，但尚未确认。不能通过直接吞掉 false 将失败改成 PASS。

之后调用 UI 工具 `cua.getApp` 试图观察此 App，工具 **2029.1 秒未返回，最终被用户中断**。未得到应用状态或截图，未观察到 compositor 的呈现结果；不再重试 CUA。之后定向 `pgrep -fl 'Contents/MacOS/native-window-probe|probe-exploration/native-window-probe'` 返回 exit 1、无输出，检查时未发现匹配测试进程。

事实快照为 `build/native-window/v1-status.json`。后续 LaunchServices 或生命周期 v2 实验必须放新目录，不能覆盖以上失败事实。

## 生命周期与结论限制

registry 的 window/view map 和 Cocoa 对象访问通过主线程处理；view/layer 显式持有至 release，detach 与 release 配对。工作线程需要主队列时，主线程仍 pump；只在 worker 完成后 join 和 destroy。当前固定 profile 的审查未发现阻塞问题。

resize 是程序发出的尺寸请求；窗口 style 未启用 Resizable，本批没有鼠标拖动调整尺寸验收。关闭也是合成测试事件，没有真实用户输入/guest 消息队列验收。`isVisible` 与 GPU EVENT 都不等于已经取得屏幕画面证据。

错误主线程调用计数只用于可信宿主内部诊断，不承诺任意错误调用的并发安全，也没有 TSan 结论。registry 作为进程生命周期 callback owner 有意保持到进程结束，没有声明零泄漏。此 v1 后端没有合入随后发现的 Draw 异步销毁修复；本报告严格是 clear-only，不表示 Draw-ready 窗口库。没有 PE、guest HWND、shader Draw、键鼠、VSync1、全屏或可分发 App 能力结论。
