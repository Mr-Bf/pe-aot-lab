# 受限 User32 v1：实现与分层验收

本模块已实现 `201`、`210..222` 的窗口 API 分发。此次结果只覆盖 C 兼容层及受控宿主/回调模型，**没有执行 Windows PE、Cocoa 窗口或 GPU**。真实 PE 回调组件、Cocoa 队列和完整窗口程序分别验收；不能将它们的计数相加，或将本测试升级成 Windows 行为 oracle。

## 实现范围

- 一个已注册的 ASCII 类、一个当前窗口；类的 WndProc 必须是登记的 guest RVA。窗口是数值句柄，不是原生指针。
- 固定 `WS_CAPTION | WS_SYSMENU`、无菜单/父窗/扩展样式；`CW_USEDEFAULT` 位置由实际宿主窗口确定，客户区固定 640×360。`GetModuleHandleA` 只接受 NULL。
- `CreateWindowExA` 读取原 Win64 四寄存器及八个栈参数，先复制全部参数和字符串，再写独立 RW guest 页中的 80B `CREATESTRUCTA`、16B `RECT` 和字符串副本。实际外框坐标来自宿主主屏坐标转换；不伪造为 (0,0)。
- 创建同步进入真实回调接口的 `WM_NCCREATE → WM_NCCALCSIZE(FALSE) → WM_CREATE`。非零 NCCALCSIZE 返回、改变固定非客户区布局、递归创建或销毁都明确拒绝。该最小序列不包括 Windows 的 `WM_GETMINMAXINFO`、全部位置/激活通知、钩子或子窗口行为。
- `DestroyWindow` 要求图形层已经归还活动 view，先获得实际失焦变化，再同步 `WM_KILLFOCUS`（如需要）、`WM_DESTROY`、`WM_NCDESTROY`，最后销毁宿主窗口。销毁中的递归创建/销毁受限拒绝。故障后由宿主独立清理，不伪造 guest 销毁回调。
- `ShowWindow` 仅 SW_HIDE/SW_SHOW，返回先前可见状态；`SetFocus` 使用宿主实际前后焦点，不把前台申请当成功。API 引发的焦点消息在返回前同步回调，Cocoa 抑制重复通知；真实 OS 通知由消息入口处理。
- `GetMessageA` 只接受全线程、无过滤参数。写权限在消费队列前检查，pending sent 通知进入回调，不作为 MSG 返回；每次回调后重验输出映射。普通消息按 Windows x64 的 48B MSG 显式编码，保留 posted 时间与屏幕鼠标点，不覆盖已有时间点。WM_QUIT 返回 0，停止/宿主错误返回 BOOL -1 并设置受限错误码 995。
- 过期 HWND 的已排队消息可以被取出，分发时计数并丢弃，绝不调用 tombstone。`DefWindowProcA` 逐项实现限定的创建、非客户区计算、焦点、固定尺寸、绘制验证、关闭与三种键；未知消息拒绝。没有“所有消息都返回 0”的通用兜底。
- API 调用统计是进入已识别分支的次数；User32 `callbacks` 是尝试次数，实际 callback engine 另报告 calls/returns/rejections。宿主和 guest 均为单线程 owner 模型，非通用安全隔离层。

回调故障或 Exit 会立即停止当前 API，保留失败 State、已提交写入、步数和 guest 栈；不改写为普通 BOOL 错误，不继续后续消息，不执行外层兼容 RET。调用方最终 dispatcher 必须继续使用 `aot_should_exit`。

## 创建失败的依据与限度

Microsoft 的 [WM_NCCREATE 文档](https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-nccreate) 规定 FALSE 使创建失败；Raymond Chen 的 [Microsoft 官方说明](https://devblogs.microsoft.com/oldnewthing/20050726-00/?p=34803/) 明确这种失败只收到 WM_NCDESTROY，而没有 WM_DESTROY。

[WM_CREATE 文档](https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-create) 规定 -1 使窗口销毁并返回 NULL，但没有完整枚举失败消息顺序。本实现对 CREATE -1 采用固定 Wine commit `f343ca6085bfac807c33e9c1a8a43105071f1416` 的 [create_window_ex 失败路径](https://github.com/wine-mirror/wine/blob/f343ca6085bfac807c33e9c1a8a43105071f1416/dlls/win32u/window.c#L6210) 与 [destroy_window](https://github.com/wine-mirror/wine/blob/f343ca6085bfac807c33e9c1a8a43105071f1416/dlls/win32u/window.c#L5466)：发送 NCDESTROY 后清理。**该第二种顺序尚未在 Windows 实测**，不声称完整系统等价。创建失败不擅自覆盖回调最终设置的 LastError，包含零。

消息字段依据 [MSG](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-msg)，pending sent 优先依据 [GetMessageA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagea)。本模块不覆盖跨线程 SendMessage、DPI 虚拟化、IME、文本输入、鼠标输入、多屏或任意窗口管理。

参考原字节只存项目工作区 `work/user32-reference/`，未复制 Wine 实现进本模块。固定来源及 SHA：

| 参考文件 | SHA-256 |
| --- | --- |
| Wine win32u/window.c | `4e35a5528121d481f8d5a5e42fe257c30bbe6e9444137bd448ef7358b21ea523` |
| Wine user32/tests/win.c | `c05be8a2a65e40a43104ee5241fa251bb90295da7fb110b56bf2f6fe2a003303` |
| Wine user32/tests/msg.c | `6c9b960cfa4c4089a1be2159c49cbf0fb13b543eb970fa3a6936b3c6749da633` |

## 实际测试

`user32_test.c` 直接编译生产 User32 与事务层访存计划器，Cocoa 和回调执行器明确替换为测试模型。O0、O3、ASan+UBSan 各通过 **460 条断言**，是同一用例集的三种编译模式，不能称 1,380 个独立输入。ASan/UBSan 检查的是实际 C 测试二进制；没有 Remill IR 插桩，关闭泄漏检测，不能声称无泄漏。

覆盖包括成功创建/失焦/销毁、实际 RECT 到 CREATESTRUCT 布局、MSG padding/time/point、sent 回调与 posted 分发、tombstone、创建回调三处 fault/Exit 保留停止状态、两种业务创建失败、MSG 输出跨页权限拒绝不消费队列、sent 中断不写输出/不消费后续 QUIT、活动 view 拒绝销毁、scratch 只读拒绝且无写入、未知默认消息拒绝、NCCALCSIZE 非零拒绝，以及配置直接别名旧 TLS 配置时不会被初始化清零。最初 438 条探索保留；新增两类回归后为 460。

独立 reviewer 另以 O0/O2 各执行 11 个 case、202 条断言，检查旧 return slot/当前栈与 scratch 别名、四个递归创建/销毁拒绝、四个 NCDESTROY 修改 LastError 的失败例及正控，全部通过。这些是独立模型反例，不算本集合额外 guest 执行。证据 `build/window-bridge/user32-review/evidence.json` SHA-256 `4929f9810dda9b821993e7d69f20655adf6675431c0428d939c920ddd041ba43`；完整只读复审在同目录 `REVIEW.md`。

证据：`build/window-bridge/user32-tests/final/evidence.json`，SHA-256 `eb57d68f64928adc5e011816b4d65bacd8095fbf8eb94f11d71aa50cd4833bb4`。实际 clang、linker、ASan runtime、Python、源码和 `clang -M` 头依赖在运行前后绑定；普通和 Python `-O` 只读复验通过。6 个内存记录篡改负例检验 nested PASS/count/scope/退出码/诊断门禁，未增加任何 C/guest 执行。门禁用于过期及完整性检查，不是签名或敌对伪造防护。

```sh
cd outputs/pe-aot-lab
/opt/homebrew/bin/python3.13 window_bridge/test_user32.py --verify-only
/opt/homebrew/bin/python3.13 -O window_bridge/test_user32.py --verify-only
# 重新执行须使用新输出目录，避免覆盖历史：
/opt/homebrew/bin/python3.13 window_bridge/test_user32.py --out build/window-bridge/user32-tests/replay-1
```

冻结候选身份：`user32_v1.inc` `14a319668cd5e8856b017f9a7d54782556d461295033755f875fafadc14d20cf`；`user32_v1.h` `ffd2bc7a3e633a5ef4de49663625fe4f12e763ef6f0f1b193672993709772518`。完整窗口程序仍需独立真实 PE、回调、图形和输入验收；本报告不提前授予该能力。
