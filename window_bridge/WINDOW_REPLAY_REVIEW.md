# 同一窗口 PE 的 O0/O3 重放：独立只读补充复审

**两次实际运行通过，同一工作负载的确定性结果一致。** 这是同一个自制 Windows PE、同一组8个 TEST_QUEUE 事件，在 O3 与 O0 两种 native 构建下各运行一次，共2次执行、1种输入序列。独立 reviewer 没有增加 guest、Cocoa 或 GPU 执行。原单次复审与原冻结证据保持不变，见 `WINDOW_FIRST_RUN_REVIEW.md`。

| 字段 | O3 | O0 |
| --- | --- | --- |
| 原运行目录 | `window-run-pilot-01` | `window-run-pilot-o0-01` |
| child PID | 28692 | 29622 |
| native executable SHA-256 | `2ea542a520900ee985001f2eb0b363c65651f06a2eb908641808eb92be691e21` | `bd46da57f77261d945522038540c522bdfbd3b547fb4ba25aca6a46313a8a51d` |
| guest steps / exit | 1061 / 0 | 1061 / 0 |
| position / moves / draws | 4 / 3 / 5 | 4 / 3 / 5 |
| keydowns / ignored repeat / paint | 5 / 1 / 1 | 5 / 1 / 1 |
| callback calls / returns | 14 / 14 | 14 / 14 |
| guest Release 的应用对象 | 8 | 8 |
| loaded image 公告数 | 1097 | 1097 |
| host event_pumps | 24 | 22 |

两份原始 `input.exe` 都是 SHA `a9997a6e542efee64c19d8a2ac343d28e294341a187ab954b9d8e0a6a9824da1`。实际链接命令分别消费各自 main、WndProc、RET 的 `arm64.o` 与 `arm64-o0.o`。O0 指对应 ARM64 后端代码生成与 native C/C++ 构建的 `-O0`；它仍消费真实 Remill 提升后的 `arm64.ll`，不是另一套独立指令语义，也不意味着前面的提升/IR 处理完全未经优化。

## 实际比较

普通 Python 与 `-O` 下分别对两条实际记录执行 producer 的完整只读验证，再验证原 started、pilot 元数据、raw stdout、stderr、child PID、构建/PE身份和真实磁盘文件。两次 dyld 公告 PID 均与自己的 child PID 相同，均加载受验 backend-v2 库闭包，且 `proc_translated=0`。

对两个原始 result JSON 深拷贝后，只排除：

- 48B MSG 的 `[32,44)`：posted time 和 screen point，共12字节。
- `host_before_finish.event_pumps` 与 `host_after_finish.event_pumps`：事件循环实际调度次数。

**除此之外的全部 result 字段相等。** 保留了 MSG 的 HWND、message、wParam/lParam、padding；也保留每一块 guest observation 的其他字节、RAX/RSP/RIP、全部 API/资源/文件/回调计数和停止状态。没有比较未记录的完整 3504B Remill State，因此不把此结果叫完整状态差分。

两份存档均为20B，实际磁盘、宿主保存观察和 guest `window_state` 相等，解码为 `[0x31574f43,1,4,3,5]`，SHA-256 `d028262d405197c87f00be59d96f89e8eca97b147074b803b24534da0b1f794a`。两个 pilot 均在独立新建空 data 目录运行。

比较器另有1个允许 time/point/pump 改变的正控及7个必须拒绝的变化：RAX、MSG message、MSG padding、guest state、wait count、WriteFile字节数、Present次数。普通/-O全部符合预期。它们是内存比较测试，不是额外游戏输入或执行。

证据与可复现只读脚本在 `build/window-bridge/replay-review/`：

```sh
cd outputs/pe-aot-lab
/opt/homebrew/bin/python3.13 build/window-bridge/replay-review/review.py
/opt/homebrew/bin/python3.13 -O build/window-bridge/replay-review/review.py
```

## 仍未覆盖

两次都来自 TEST_QUEUE，真实 Cocoa key=0、focus transition=0、sent notification=0；前台焦点与物理键盘没有得到本次证明。没有 compositor/像素读回验收。原 PE 只保存，没有 ReadFile 恢复功能。没有新变基址执行、其他输入序列、超时/故障原 PE 集成矩阵或性能测量。库仍从工作区加载，尚非同 PE 的可搬移 App。两次重放使 O0/O3 行为一致性更可信，但不扩大为通用 Win32、Steam 或商业游戏兼容性结论。
