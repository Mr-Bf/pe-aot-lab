# 长时间消息驱动验收准备 v1

当前完成的是静态 ARM64 构建、纯 C 控制器检查和只读验收代码。此文不代表已运行 30 分钟，也不代表真实键盘、逐帧像素或游戏性能通过。实际运行结果须另查独立 run 目录；旧窗口、像素、存档与 App 证据均未改写。

## 同一 PE 与新增范围

固定使用原始 save/load PE `0e1bcf809cb2aa56f23526f3bbd80e9ee233488a1a5b215f1f810b4bb67aa976`，从 `build/window-bridge/save-load-program-v1-01` 复用七个对象：main、WndProc、RET、文件/User32/D3D 运行时、D3D 后端、窗口后端与 Cocoa。只重新编译 `window_host_long_v1.c`，其机械变换由 `long_host_recipe_v1.py` 对冻结短时宿主逐段核验。

宿主只负责 API、消息来源、启动、时钟、资源统计和清理；不读取或修改游戏规则来代替 PE，不设置游戏位置，不代替 PE 保存。所有最终游戏状态、文件读写和 Draw/Present 决策仍由同一 PE 执行。

实际构建目录为 `build/window-bridge/long-program-v1-03`，原生可执行 SHA 为 `8aaa64077134d35b0f28300e97c9402b9d9d4803ddd04a1d3e0cd35356bb41f9`，构建 receipt SHA 为 `916c7129b63943f2b85c92798a34fe4e128916dc6197cb7a0df388f38771d411`。构建绑定 3,076 个输入、18 个产物；真实 `-M` 依赖包含原 save/load 生成头与新控制器，链接实际三库并核验不可变可执行身份。静态核验不会加载 DXMT 或启动窗口。

## 时间与输入合同

- 正式模式显式给出 `--duration-ms`，允许 1,800,000–2,047,000 ms；默认 30 分钟。独立 `--smoke-duration-ms 10000` 只用于 10 秒流程检查。
- 周期固定 250 ms；按 `right → right-up → left → left-up` 循环。在已经观察到真实 HWND、GetMessage 新等待次数、队列空且无待处理 paint 的边界投递。
- 下一个期限从实际投递返回时间加 250 ms 计算；延迟后不追赶、不集中补发。达到持续时间后完成当前四消息循环，再在下一个合格边界投 Escape。
- 最多 8,192 条记录。每条记录消息名、TEST_QUEUE 来源、实际等待次数、投递前后单调时钟、相对 first-ready 的纳秒和毫秒时间。正式最大参数需要至多 8,189 条。
- first-ready 后超过 5 秒没有成功消息，或一次实际投递本身超过 5 秒，明确失败。保护期从原生启动开始为 35 分钟；超时仅结束队列，不制造 QUIT、存档或正常退出。
- Escape 的开始时间减 first-ready 时间必须达到要求；worker-done 为真实工作线程在终结队列后、发布 done 前采集。主线程持续 pump，收到 done 后 join 与 finish。

这些是持续的**消息测试活动**，不是持续占用 CPU，也不表示 4 FPS 或游戏吞吐。输入全部标为 TEST_QUEUE，任何真实键盘污染会导致确定性验收拒绝。宿主采集启动、first-ready、结束三个资源快照：`getrusage` 用户/内核 CPU、fault/switch 次数及 Mach 当前/峰值 resident、virtual bytes。资源系统调用失败不能成为通过结果。没有逐分钟内存趋势或 GPU 计时证明。

## 验收与监督

`long_validation_v1.py` 对冻结 save/load 普通验证器仅扩展事件容量和时间字段；对冻结存档语义验证器仅把固定八消息序列替换为完整循环。源码变换逐文本核验，旧验证器不放宽。新增检查重建全部事件间隔、完整 phase、first-ready/Escape/worker-done、CPU 计数与资源系统调用状态，并比较真实 PE 状态、累计 moves/draws、实际文件、API/COM/User32/callback 清理。

`long_run_v1.py` 默认只读。显式启动时先写 `attempt.json`、`started.json`，Popen 成功后立刻写不可变 `launched.json`，包含实际 PID、同一 CLOCK_MONOTONIC 的监督开始时间、启动 SHA 和期限。跨会话应读取此文件确认原进程；不能因为工具会话号遗失就重启。stdout/stderr 直接保存，结束后核验同 PID 的实际 dyld 图、源/对象/库前后身份和真实存档；随后才写 PASS。文本输出在解析前限制为各 4 MiB，此限制是验收上限，不是运行中磁盘配额。

正式外部监督 36 分钟；smoke 外部监督 60 秒。内部队列停止不能取消阻塞 GPU/Cocoa 调用，外部终止不是干净退出。可由监督者独立记录 `caffeinate` 防止空闲休眠，不改变系统设置，不纳入性能结果。原生线程的时间与监督器均显式使用 CLOCK_MONOTONIC，避免把 Python 默认单调时钟实现与另一时钟混用。

仓库根目录命令：

```sh
/opt/homebrew/bin/python3.13 -m window_bridge.long_run_bindings_v1
/opt/homebrew/bin/python3.13 -O -m window_bridge.long_run_bindings_v1

# 仅监督者在 GPU 空闲时执行；此准备任务没有运行这两条。
/opt/homebrew/bin/python3.13 -m window_bridge.long_run_v1 --run --smoke --out build/window-bridge/long-smoke-v1-01
/opt/homebrew/bin/python3.13 -m window_bridge.long_run_v1 --run --duration-ms 1800000 --out build/window-bridge/long-formal-v1-01

# 已完成记录的只读重新核验；不再启动进程。
/opt/homebrew/bin/python3.13 -m window_bridge.long_run_v1 --out build/window-bridge/long-smoke-v1-01
/opt/homebrew/bin/python3.13 -O -m window_bridge.long_run_v1 --out build/window-bridge/long-formal-v1-01
```

`--initial-save` 可提供已存在的合法 20B 文件；新运行目录保存精确历史输入，再由 PE 自己 ReadFile。缺省为新空目录。一次长时执行本身不新证明“两次进程恢复”，该证明属于既有独立双进程证据。

## 已执行检查与历史

`long-controller-tests-v1-03`：真实 C O0、O3、ASan+UBSan 各 14 个相同 synthetic-time 场景，每模式 46,414 断言。覆盖正式最小/最大容量、10 秒模式、末循环、5 秒停滞、真实 post 延迟、错误顺序、重复 wait、无 catch-up。这里只人工推进整数时钟，没有等 30 分钟。Apple ASan 未启用不支持的 LeakSanitizer。

`long-review-v1/parser-ordinary.json` 与 `parser-optimized.json`：各 2 个 synthetic JSON 类型/时间正例、25 个拒绝、1 个明确未完成结果。额外确认“时间解析通过”的构造记录仍被真实游戏语义检查拒绝。不能把同源 JSON 测试当实际运行证据。

保留首次失败：`long-controller-tests-v1-01` 是工具调用缺 env 参数；`long-controller-tests-v1-02` 是 macOS ASan 不支持 `detect_leaks=1`，两者保留失败记录与当时测试源。修正仅测试驱动，正式在 `-03` 重新执行。`long-program-v1-01`、`-02` 是从未运行的静态候选；新增 post 自身停滞判断与默认目录收敛后，以 `-03` 为唯一当前入口，旧 receipt 不能冒充当前源的通过。
