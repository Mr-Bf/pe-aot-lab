# 同一原始 PE 首次窗口闭环：独立只读复审

**结论：当前记录通过受限 save-only 工作负载验收。** 独立复审重新读取 immutable started、原始 stdout/stderr、构建来源、加载库、原始 PE 和磁盘存档，并在普通 Python 与 `-O` 下各完成一次只读验证。没有再次执行 PE、启动窗口或运行 GPU。27 个不同的内存记录/日志反例在两种模式都被拒绝；不能把两次复验或反例算作第二次真实程序运行。

## 核对到的实际执行

| 项目 | 实际记录 |
| --- | --- |
| 原始 Windows PE SHA-256 | `a9997a6e542efee64c19d8a2ac343d28e294341a187ab954b9d8e0a6a9824da1` |
| 运行形式 | 原始 PE 的 main 与 WndProc 经 Remill AOT，O3 ARM64 原生宿主；没有宿主传入业务入口参数 |
| child PID / host exit | 28692 / 0 |
| ISA 观测 | `proc_translated=0`，构建验证为 ARM64 Mach-O |
| guest 执行 | 1,061 步；ExitProcess(0)，没有 AOT fault/timeout，没有把 RET 当退出 |
| 输入 | 8 个明确标记为 TEST_QUEUE 的事件，wait 边界依次 1..8 |
| 状态 | position=4、moves=3、draws=5；keydown=5、忽略 repeat=1、paint=1 |
| WndProc | 14 次实际调用、14 次返回；深度最终 0、拒绝 0 |
| 图形/窗口生命周期 | 5 次 Draw/Present；8 个应用对象均 guest Release，宿主补释放 0；window/view 各创建、销毁/归还一次 |
| 文件 | 一次 CreateFile、WriteFile、CloseHandle；写20B，读0B；存档与 guest state 完全一致 |
| 实际输入缺口 | Cocoa key=0，焦点 transition=0，sent notification=0；不声称获得前台或物理键盘支持 |

实际队列为 `right, right-repeat, right-up, right, right-up, left, left-up, escape`。从 position=3 开始，非重复右移两次、左移一次，结果 position=4；重复键不会产生额外移动。5 次绘制包含初始帧、一次 paint 以及三次移动对应帧。

磁盘文件为原运行目录下的 `data/integer-tile.bin`，字节：

```text
43 4f 57 31 01 00 00 00 04 00 00 00 03 00 00 00 05 00 00 00
```

按五个 little-endian uint32 解码为 `[0x31574f43, 1, 4, 3, 5]`。SHA-256 为 `d028262d405197c87f00be59d96f89e8eca97b147074b803b24534da0b1f794a`。pilot 在新建且原先不存在的输出目录中创建空 data 目录；started 中记录空初始文件集合，实际 driver 身份匹配。验收要求最终该目录只有这一个普通文件，磁盘当前字节、宿主读回、guest observations 三方一致。

## 身份与真实日志

本次执行证据位于 `build/window-bridge/window-run-pilot-01/`。`run.started.json` 的命令、预算、测试序列、3,054 项输入身份与最终记录一致；历史中的 STARTED 只是正常原子记录更新留档，不是另一次隐藏的执行或被抹掉的运行失败。

实际 native executable 为 `program-build-03/window-2ea542a520900ee985001f2eb0b363c65651f06a2eb908641808eb92be691e21`。完整 producer reader 重新检查当前编译/链接来源、生成头、原始 `.text` 字节与指令元数据、多 root/RET 提升产物及库依赖。原始 `input.exe` 与固定 prepared-v2 PE 的 SHA 相同。

stderr 中 1,097 个累计映像公告通过解析，所有 dyld PID 都实际等于 child PID 28692；非系统闭包是这个 executable 加 backend-v2 的 `d3d11.dylib`、`dxgi.dylib`、`winemetal.dylib`。没有用静态 graph 推测加载成功，而是核对本次真实 dyld 输出。当前库仍来自工作区路径，**此同 PE 宿主尚不是可搬移 App 包**。

日志保留了 DXMT 的 D3DKMT、GetCurrentThread/SetThreadPriority/GetModuleHandle 未实现警告。这些警告没有在本受限样本产生非零退出或错误 HRESULT，但也不意味着这些 Windows 功能已实现。原生依赖及该固定工作负载的成功不能外推成任意 D3D11 游戏兼容性。

队列 `error=1/stopped=1` 是 worker 正常完成后 `wb_host_session_end` 的已定义 STOPPED 状态；不是发生于运行中的队列错误被吞掉。本次 `queue_overflows=0`、WM_QUIT 一次、无强制窗口清理、无活动 view/map/object 或文件句柄遗留。

## 反例检查

23 个语义变体覆盖 PE 身份、child/guest 退出、超时、漏事件、输入来源、真实键污染、位置、moves、draws、repeat、保存长度/内容、文件读写计数、guest 对象释放、强制宿主清理、未注销类、少一次 callback return、client RECT、非零最终 HWND、feature level 和注册类调用次数。另有 3 个 dyld 变体（混合 PID、无公告 transition、多余非系统库）及一个重复 JSON key 变体。全部只改内存副本或新字符串，不改已保存真实记录。

producer 目前要求同一日志内 PID 一致；本独立复审额外明确核对它等于实际 `Popen` child PID。本次相等，没有证据冲突。未来 producer 可将这个跨字段绑定纳入通用门禁；不需要重跑本次 PE 来得出当前身份结论。

普通和 `-O` 的详细证据、反例理由、源码/证据哈希在 `build/window-bridge/first-run-review/{ordinary-evidence.json,optimized-evidence.json,freeze.json}`，复现只读命令：

```sh
cd outputs/pe-aot-lab
/opt/homebrew/bin/python3.13 build/window-bridge/first-run-review/review.py
/opt/homebrew/bin/python3.13 -O build/window-bridge/first-run-review/review.py
```

## 通过范围与后续缺口

已证实的是：**同一自制 Windows PE 的无参入口 → 真实 User32/IAT → 原 PE WndProc → TEST_QUEUE 驱动整数状态 → 真实 DXMT Draw/Present 调用 → guest 写存档 → 释放资源并退出**，且此轮宿主为 ARM64、不依赖 Rosetta 执行 guest。

尚未证实物理键盘输入、前台焦点、compositor 可见内容、读回像素或完整画面正确性；该 PE 只保存，不包含 ReadFile 恢复；仅本次 O3、preferred base 的一个成功完整执行，未据此主张 O0/重定位矩阵、帧率、任意控制流、任意 Win32 消息、Steamworks、真实商业游戏或可搬移 App 交付。后续每一项都需要独立的新版本与实际证据。
