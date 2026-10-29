# 保存／恢复窗口 PE：版本化准备

`fixture_v2.cpp` 已经通过真实 Windows target C++ → COFF → LLD 构建，完整保存源、依赖、导入表、map、反汇编及准入失败。普通／`-O` 只读校验均通过。**此新 PE 尚未执行 Windows、AOT、Cocoa 或 GPU，也尚未完成全部 main 控制流准入。** 原保存样本、转换器、运行时和历史证据均未修改。

## 来宾行为及错误合同

无参数 `window_entry` 在创建窗口前通过真实 IAT 调用 `CreateFileA`，只读打开 `integer-tile.bin`。文件缺失仅接受 `ERROR_FILE_NOT_FOUND=2`，继续初始位置 3；其他打开错误退出码 30。这与 `OPEN_EXISTING` 的官方定义一致。[CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)

已有文件先同步读取 20 字节，再读 1 字节检查 EOF。第二次必须成功且返回字节数 0；微软明确规定同步 EOF 是 TRUE 加零字节，不能套用异步 `ERROR_HANDLE_EOF` 分支。[ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile)、[Testing for the End of a File](https://learn.microsoft.com/en-us/windows/win32/fileio/testing-for-the-end-of-a-file)

打开后各路径都尝试一次 `CloseHandle`，成功关闭后才提交恢复数据。读失败退出 31；关闭失败退出 33。读、关闭同时失败时保留读错误，另记录 `close_errors`，不声称句柄关闭成功。[CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)

格式固定为五个小端 u32：`magic=0x31574f43`、`version=1`、`position∈[0,7]`、累计 `moves`、累计 `draws`。长度不足、尾随字节、错误 magic／version／位置分别记录 `validation_error=1/2/3/4/5`，退出 32、错误值 13。失败时不创建窗口、不覆盖存档、不将候选内容部分写入 `window_state`。计数是无符号累计值，允许 u32 的定义良好回绕；此小格式没有校验和、迁移或抗篡改承诺。

完成恢复后保留原始消息、移动、Draw、保存、释放和退出业务。源差异仅新增加载观测、候选缓冲区、`restore_state` 及入口调用；实际 diff 归档在 `build/window-bridge/save-load-preparation-review/fixture-diff.patch`。真实源中的“handles are closed”注释应理解为每个打开路径均尝试关闭；关闭失败被显式记录／退出，不能据该注释推断操作成功。

## 静态映像和实际准入结果

产物目录 `build/window-bridge/prepared-save-load-v1/`：

| 项 | 实际结果 |
|---|---|
| PE SHA-256 | `0e1bcf809cb2aa56f23526f3bbd80e9ee233488a1a5b215f1f810b4bb67aa976` |
| 无参数入口／WndProc RVA | `0x1140`／`0x1000` |
| 导入 | 21 个，较旧样本仅新增 `kernel32.dll!ReadFile` |
| 完整反汇编 | 648 条，旧样本 521；不是已验证可达 CFG 计数 |
| COM 间接调用／寄存器 CALL | 24／5 个静态调用点 |
| 实际 Windows 头与源依赖 | 243 项，无 CRT／异常／RTTI／SIMD helper 导入 |
| 冻结 loader | 真拒绝：`unknown imported function: kernel32.dll!ReadFile` |
| main decoder | 真拒绝：`REJECT memory RMW outside INC RIP m32 at 5368713651` |
| WndProc decoder | 75 条解码及 flags 检查通过；没有降低到 ARM 或执行 |

首拒点是 RVA `0x11b3`、字节 `ff00`、`INC DWORD PTR [RAX]`。自然 `-O2` 编译将 missing／restored 的两个计数递增共享为一个 RMW，之前用 LEA 选择 RAX 指向哪项。原始 PE 没有为绕过该拒绝而修改。下一版本必须明确接纳这一寻址形态，并执行 CF 保留／其他定义 flags／跨页失败整条指令回滚的原始 x86 与真实 ARM 差分。

另外观察到 `JAE` 和 `MOVABS` 常量形态。RVA `0x1391` 的常量 `0x131574f43` 是合并的 magic+version，不是来宾地址。main 在第一项拒绝处停止，因此不能声称其它新形态或全部 main 已通过。`NOP` 变化含对齐字节，不直接推断执行需要。明确 IAT 槽授权的 CLI decode-only 探测没有替代冻结 loader 接受；解析用数字标签也不是运行时 API 注册。

新增可观察数据：

| 名称 | RVA | 长度／布局 |
|---|---|---|
| window_state | `0x3000` | 20 B，五个 u32 |
| window_result | `0x30c0` | 原 60 B 业务观察 |
| window_load_result | `0x30fc` | 36 B，9×u32，见下 |
| window_load_candidate | `0x3120` | 20 B 候选状态 |
| window_load_extra | `0x3134` | 1 B |
| window_load_count / extra_count | `0x3138` / `0x313c` | 各 4 B |

加载观察顺序：`attempts, restored, missing, errors, bytes_read, extra_bytes, win32_error, validation_error, close_errors`。候选是独立静态 BSS；宿主不代填来宾业务参数。

## 下一版执行验收设计（尚未执行）

1. 新版本 parser/runtime 开放已有 typed `ReadFile` 签名 6，并保持旧 profile 冻结；新指令通过独立原始字节差分后，完整提升同一新 PE 两根与 RET。
2. 第一次对新空数据目录运行。加载观察应为 `[1,0,1,0,0,0,2,0,0]`。沿既有 8 项 TEST_QUEUE 工作负载，最终位置 4、移动 3，保存磁盘状态必须逐字节等于来宾状态。Draw 次数依据实际 paint，不能靠固定帧数伪验收。
3. 第二次**相同 PE**读取第一轮原样磁盘文件。开始执行前记录该文件身份；加载候选必须等于第一轮磁盘，观察 `[1,1,0,0,20,0,0,0,0]`。同一输入下位置 5、累计移动 6；累计 draws 应为读取初值加本轮 presents，而不是直接等于本轮 presents。不得由宿主恢复到来宾状态冒充来宾读取。
4. 在独立数据目录测试 0／19 B、21 B、错误 magic、version、位置 8，按上述明确退出码、原因和无覆盖条件验收；同时核 ReadFile/CloseHandle 计数、无残留句柄、窗口／图形零创建。真实文件错误与人工 API 失败注入应分开统计。
5. 之后再增实体键盘、像素观察、可搬移 App 和性能；本次静态准备不替代这些执行证明。

复现：

```sh
# 全新输出，避免覆盖首轮证据
/opt/homebrew/bin/python3.13 window_bridge/prepare_v2.py --out build/window-bridge/prepared-save-load-reproduction
# 原始输出只读校验
/opt/homebrew/bin/python3.13 window_bridge/prepare_v2.py --verify
/opt/homebrew/bin/python3.13 -O window_bridge/prepare_v2.py --verify
```

所有外部工具实际命令、返回值和原始拒绝在产物目录 JSON 中。`evidence.json` 绑定实际头文件闭包、工具字节、已知 LLVM dylib、shader 证据、原 PE 与原始日志；没有宣称系统共享缓存哈希或实际构建进程 dyld 跟踪，也不是防敌对重写的数字签名。`verify` 不重跑 decoder，读取既有日志并核对工具／源／产物身份。

冻结身份：fixture `f2a7ef57293dc5378bf3e5390a7dfafd5f877503a1b4e010acfec2f7a2ef5c40`；prepare `6092ab89c0bb328961a3735153a740061ae2c142188351103a27f374d7d1201e`；manifest `91ba43483e4b414a1535ba71be69efdcc60bcc93c0d82aeffb71a0012a673ba5`；evidence `5a02b0a46ca316038d1fde781e556bae87fecfee782fc2e8bc7b747e47419585`。普通／`-O` 只读日志、diff 与差异摘要归档在 `build/window-bridge/save-load-preparation-review/`。
