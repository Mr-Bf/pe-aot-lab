# 自包含原生窗口 App：Cocoa 修复与搬移执行

新版本已从 `/private/tmp` 带空格路径的签名 App 实际运行通过。单次原生 ARM64 进程完成 D3D11 清屏、两个 `Present(0,0)`、640×360 到 800×450 的程序请求调整尺寸、GPU 完成查询、全像素读回与资源释放。它验证原生窗口后端；Windows guest、Draw、真实键鼠和 compositor 截图均未在本轮执行。

## 具体问题与修复

旧完整 v2 App 在直接启动和 LaunchServices 两条路径均停于 `Cocoa_application`。隔离诊断使用完全相同的签名 executable 字节发现：裸文件初始 policy=2，切换返回 true，最终 policy=0；App 初始已为 policy=0，重复设置返回 false，最终仍为 0。此前代码错误地将重复设置的 false 解释为初始化失败。

新 `cocoa_registry_v2.mm` 保留旧文件，仅修改这一个条件：当前已为 Regular 时不调用 setter；非 Regular 时 setter 失败仍拒绝；最终再次读取并要求 Regular。新 `probe_v3.py` 验证整份文件必须等于冻结旧源码的唯一精确替换，并将新旧文件和实际编译头文件闭包纳入输入身份。并未无条件吞掉 setter 失败，也未更改图形代码。

这项语义由独立代理只读核对。其随后实际核对 2,276 个输入、16 个构建产物、两个位置的 App 字节/权限/依赖图以及真实严格代码签名，全部通过；独立审查不计作额外 App 或 GPU 执行。

## 实际执行

| 项目 | 结果 |
|---|---|
| 实际进程 | PID 10720，child exit 0，未触发 60 秒超时 |
| CPU | ARM64，`sysctl.proc_translated=0` |
| 第一阶段 | 640×360，RGBA8=(17,85,170,255)，230,400 像素零误差 |
| 第二阶段 | 800×450，RGBA8=(34,170,85,255)，360,000 像素零误差 |
| 合计 | 590,400 像素、2,361,600 通道逐项比对，最大误差 0 |
| GPU / 窗口提交 | 两次 Clear/Copy/Map/Unmap、Present0 与 EVENT 查询完成 |
| 生命周期 | 13 个应用持有 COM 引用释放；一个 view 创建/释放，active=0；一个窗口创建/销毁，tombstone=1 |
| 拒绝合同 | 未知窗口、重复安装、错误协议版本和不支持的 Present(1,0) 均按约拒绝 |

执行用的是完整 App 的临时副本，三个实际非系统库均在 `Contents/Frameworks` 内。严格 dyld 累计映像解析验证没有指回工作区的外部图形库。运行前后所有记录输入和副本字节/权限一致。标准输出、标准错误、实际子进程退出码和命令单独记录；成功后的等待已回收子进程，没有额外 LaunchServices 重跑。

## 构建、执行和只读验收入口

```sh
# 已执行且输出拒绝覆写；不重复构建或重放 GPU。
/opt/homebrew/bin/python3.13 native_window/probe_v3.py
/opt/homebrew/bin/python3.13 build/native-window/launch-v3/run.py prepare
/opt/homebrew/bin/python3.13 build/native-window/launch-v3/run.py direct

# 可再次只读核对当前证据；不启动 App 或 GPU。
/opt/homebrew/bin/python3.13 native_window/verify_launch_v3.py
/opt/homebrew/bin/python3.13 -O native_window/verify_launch_v3.py
```

`build/native-window/probe-v3/evidence.json` 是静态包证据，保留 NOT_EXECUTED 状态，不因后续运行而改写。实际运行证据另存 `build/native-window/launch-v3/direct.json`；普通与 `-O` 的只读验收记录为 `verify.json`、`verify-optimized.json`，分别校验正例及 6 个内存注入拒绝例（退出码、超时、raw stdout/summary 不同、缺实际映像、缺 stdout hash、前后同时删输入）。静态包另外通过 1 正例与 7 拒绝例。这些门禁计数不计为原生执行次数。

准确范围为本轮 **1 次**原生图形执行。证据门禁用于检测过期或误用记录，不提供数字签名或对抗敌对篡改的证明。

## 保留的限制

窗口 style 未开启用户拖动 resize，本次由程序请求尺寸变化。Cocoa `isVisible` 与 GPU EVENT 不等于 compositor 截图；没有宣称用户确实看到了屏幕帧。本轮未调用 CUA，未执行 shader Draw 或 Windows PE/WndProc，没有用户输入测试。

registry 为进程生命周期对象，有意保持 callback owner 存活，不宣称零泄漏；错误线程计数是可信宿主的诊断，不能当作 TSan 或任意并发误用证明。包使用本地 ad-hoc 签名，不表示 Developer ID、公证、另一台机器或 Gatekeeper 分发验收。新图形库组合了 WSI v1 与 lifetime-r2 补丁，但本次 clear-only 运行不能替代其他任务的 Draw 生命周期验收。

历史报告 `HOST_V1_REPORT.md`、`LAUNCHSERVICES_V1_REPORT.md`、`LAUNCH_V2_REPORT.md` 和诊断 `ACTIVATION_DIAGNOSTIC.md` 均保留：旧失败不会因本轮新版本成功被覆盖。
