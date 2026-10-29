# window_bridge Cocoa / 消息宿主组件

已实现并独立运行受限宿主组件：生产队列 42 项检查通过；一个真实 Cocoa 进程的 26 项检查通过。后者验证隐藏创建、显示/隐藏、实际外框与 client 尺寸、worker/main 分工、测试消息、阻塞与退出唤醒和窗口销毁。**本组件验收没有执行 Windows PE、D3D/GPU 调用、真实按键、compositor 截图或存档业务。**

## 接口与所有权

`cocoa_host.h/.mm` 提供纯 C 宿主接口；生产同步队列位于 `message_queue.h`。Cocoa 不持有 `AotState`，不读取 guest 内存，不调用 WndProc。root 运行时负责 API 参数检查、Windows MSG/CREATESTRUCT 序列化、同步创建/销毁/WndProc 回调和错误映射。

main 创建 `WBHost`，worker 只能绑定一次；worker 的 Cocoa 操作同步转发到 main。队列锁在 dispatch 前已释放。主线程必须持续泵事件，直到 worker 的正常运行或错误清理结束，随后 join。不能只调用 `session_end` 就停止主线程泵或释放 callback owner。

数值 HWND 与 view token 由不同数值域单调生成，不是 Cocoa 地址，也不复用已销毁值。首版只允许一个活动窗口与一个活动 Metal view。窗口创建初始隐藏；`show_window` 和 `focus_window` 是独立操作。图形 view 仍使用冻结 WSI v1 的 C callback ABI，layer/native object 只存在于可信宿主存储。

`session_end` 是永久结束：唤醒等待线程，清除未送达消息，后续读取返回 -1；不会伪造 WM_QUIT。worker joined、D3D/view 释放后，main 才可调用 `finish`；它拒绝 active view，必要时清理残留 native window 并单独计数，不冒充 guest DestroyWindow 回调。WSI 没有 uninstall，registry owner 有意保留到进程退出，不宣称零泄漏。

## 消息合同

| 来源 / 事件 | 宿主记录 |
|---|---|
| Cocoa Left/Right/Escape | KEYDOWN/KEYUP；scan=4b/4d/01；箭头 extended 位；repeat/previous/transition 位保留；仅 key 且 visible 窗口 |
| Cocoa 关闭请求 | WM_CLOSE(0,0)，只排消息，不销毁窗口 |
| 实际 OS focus 变化 | SETFOCUS/KILLFOCUS，标记 SENT_NOTIFICATION；由 worker 实际调用 guest 后继续等待，不能当 posted MSG 返回 |
| 焦点失去时仍按下的支持键 | 合成 KEYUP，明确 FOCUS_RECOVERY 来源，不冒充物理按键 |
| Cocoa 尺寸变化 | SIZE_RESTORED 与当前 pixel width/height，SENT_NOTIFICATION；不使 guest ResizeBuffers 获得支持 |
| 曝光/显示 | invalid paint 状态；普通消息空时生成 WM_PAINT，ValidateRect(whole client) 才清除 |
| guest PostQuitMessage | HWND=0 的实际 WM_QUIT，保持完整 DWORD exit code；GetMessage 返回 0 |
| 测试注入 | 固定 TEST_QUEUE 来源，只允许 KEYDOWN/KEYUP/CLOSE/SIZE，不计为 Cocoa/物理输入 |

显式 Show/SetFocus 的实际 focus 前后值通过 `WBHostFocusChange` 返回；该操作的 Cocoa delegate 更新 native 状态但抑制重复排队，由运行时在 guest API 返回前同步发送相应 KILLFOCUS/SETFOCUS。相同状态不制造重复通知。

所有已 pending sent notification 先于 ordinary posted 队列，包括 posted WM_QUIT；同类别维持顺序，paint 最低。队列最大 256 条，溢出进入明确错误并唤醒等待，不静默丢键。此处遵循 [GetMessage 的 sent 优先说明](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagea)；没有实现完整跨线程 SendMessage、过滤器、timer、输入类别优先级或 Windows 全调度模型。早期人为 QUIT 屏障已移除，其未执行编译产物保留为历史，不用于当前通过结论。

消息 `time/pt` 在创建消息时采样，而不是 GetMessage 覆盖已有记录；键事件使用事件 timestamp，其它 post 用 uptime，point 来自主线程 `NSEvent mouseLocation`。生成 WM_PAINT 的采样发生在 queue take 释放锁之后，main 转换完才返回。这里遵循 [MSG 的 posted-time/point 定义](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-msg)，不代表已支持鼠标消息。未知键或 Cmd/Ctrl/Option 组合忽略并计数；没有文本/IME/系统快捷键承诺。

Destroy 后保留已入队的陈旧 HWND posted/sent 记录，只清该窗口的 paint 状态；运行时必须识别 tombstone 并丢弃/返回 0，不再次调用已销毁窗口的 WndProc。WM_QUIT 不随窗口销毁而丢失。

## 坐标与尺度

当前固定主屏与 backing scale，不实现通用 DPI virtualization。frame metrics、client size 和 `window_rect` 使用相同 primary-screen 设备像素转换；外框 RECT 是实际 `NSWindow.frame`，以主屏左上为 (0,0)，right/bottom exclusive，并非把居中的窗口虚构为原点。窗口移到不同屏幕或 backing scale 改变时明确拒绝/停止当前 profile。实际测试验证 640×360 client + frame metrics 等于真实 outer RECT。

首版 style 只有 caption/close，无用户 resize/minimize。Cocoa 事件源可报告实际 size 变化，但 guest 的 ResizeBuffers 仍明确未支持。焦点、窗口可见、图形完成与 compositor 看到某帧是不同事实。

## 焦点诊断与保留失败

首轮新测试错误假设 bare executable 的 ShowWindow 必须立刻取得前台。两次真实运行均显示窗口已显示、实际 focus_after=0，测试因此退出 -6；原记录在 `failed-show-focus/`、`failed-show-focus-with-values/`，未覆盖。

独立 `focus-diagnostic/` 创建原生窗口：请求激活前 active=false/key=false；请求后 visible=true、active/key=false；正常泵事件 1 秒后仍未获得前台。不能把这个结果归因为已证的短暂异步问题。Apple 的 [activate 文档](https://developer.apple.com/documentation/appkit/nsapplication/activate%28%29)明确激活是请求且不保证成功。

最终组件使用 `NSApp.activate`，不添加 sleep，不改假焦点。测试核对 FocusChange 与实际 WSI foreground 状态一致，并接受真实拒绝结果。最终 `focus_succeeded=false`、API focus transitions=0、sent notifications=0、Cocoa key events=0；测试队列注入=1。**实际前台激活与键鼠尚未验证**；后续完整 interactive App 可通过正常 LaunchServices 启动另行检验。组件的错误返回由 root 的 Win32 API 层映射到 LastError，本宿主不自行写 guest LastError。

## 证据与复现

```sh
# 已执行；构建/运行拒绝覆写历史。
/opt/homebrew/bin/python3.13 window_bridge/test_cocoa_host.py build
/opt/homebrew/bin/python3.13 window_bridge/test_cocoa_host.py queue
/opt/homebrew/bin/python3.13 window_bridge/test_cocoa_host.py cocoa

# 当前只读验收，不启动窗口/GPU。
/opt/homebrew/bin/python3.13 window_bridge/test_cocoa_host.py verify
/opt/homebrew/bin/python3.13 -O window_bridge/test_cocoa_host.py verify
```

最终记录为 `build/window-bridge/cocoa-host/final/`：构建收集实际 clang `-M` 的 2,212 项源/头文件/选定工具输入，运行前后身份一致；`queue.json` 与 `cocoa.json` 保存实际 child exit、原始 stdout/stderr 与身份。普通和 `-O` 只读验收重建源/header 依赖集合并核对精确产物/计数。不是完整 OS/动态编译工具链签名，也不抵御敌对重写全部证据。

当前正式执行数为 1 个纯队列进程 + 1 个 Cocoa 进程，不把 42/26 checks 或普通/-O 的只读验证加成 guest 次数。此前探索的 queue36/Cocoa18、两次过强 focus 断言失败、独立 focus 诊断分别保留，不当作当前源码的额外重放。对真正 Cocoa key/close/resize 输入、活跃 Metal view 保护以及同一 Windows PE 的交互保存仍待集成验收；不能从本报告推出这些能力已完成。
