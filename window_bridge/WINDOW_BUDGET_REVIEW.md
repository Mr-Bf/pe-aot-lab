# 三个实际预算前缀的只读复核

对 `window-run-budget-v1` 三份真实记录及 `window_budget_v1.py` 的普通/`-O` 只读检查均通过，没有增加 PE、Cocoa 或 GPU 执行。检查重新绑定 started、实际 stdout/stderr、child/dyld PID、构建和磁盘状态；聚合 status、3个预算、原始记录集合、driver hash 与 saved summaries 一致。

| budget=实际steps | main root fault RVA | 已完成回调 | 图形与清理 | 文件 |
| --- | --- | --- | --- | --- |
| 100 | `0x12ac` | 3 calls / 3 returns | 尚未创建图形对象；宿主最终强制清理1个窗口 | 无文件、写0B |
| 500 | `0x1666` | 5 / 5 | 已建8对象，3 Draw/Present；guest释放0，宿主ClearState/Flush各1、Release8、强制清理1窗 | 无文件、写0B |
| 1060 | `0x1800` | 14 / 14 | 5 Draw/Present，guest释放8；宿主补释放/强制清窗均0 | 保存20B，真实磁盘等于guest state |

三次都是 AOT_BUDGET=4、child exit=3、无内部或外部 timeout、没有 ExitProcess、没有把函数RET当进程退出。图形/view/窗口与文件资源在最终清理后平衡。100/500步的清理明确由宿主完成，不把它们写作 guest 已执行 DestroyWindow/Release；1060步之前已提交的存档保留，不因预算停止回滚文件副作用。

原始 metadata 显示三个 fault PC 都属于 main root 指令，且不属于注册 WndProc root；全部已启动 callback 均返回，callback depth=0。因此**这三例不是回调内部预算中断**，也不是每个指令边界的穷举或所有故障清理证明。driver 本身将范围标为 three prefixes/not exhaustive，当前没有发现它把这三例称作更强能力。其通用 `check` 校验预算终点和清理平衡，本独立复核进一步核对了上述实际阶段、callback范围和磁盘有无。

独立证据及只读脚本：`build/window-bridge/budget-review/`。

```sh
/opt/homebrew/bin/python3.13 build/window-bridge/budget-review/review.py
/opt/homebrew/bin/python3.13 -O build/window-bridge/budget-review/review.py
```

这3次是真实预算实验；与此前2次O0/O3正常结束的同工作负载重放分别计数。它们不提供物理键盘、像素、读档、性能或通用游戏兼容性证明。
