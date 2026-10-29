# 无参数 PE 入口与 ExitProcess：样本及原始 x86 对照

`fixtures.py` 实际运行 LLVM clang、llvm-dlltool 和 LLD，生成四个普通 Windows-target PE。入口均为 `void process_entry(void)`；文件名、67 字节源数据、目的缓冲区、结果和标记都位于 PE 的静态 data/BSS 中。宿主不再代传文件名或缓冲区等业务参数。正常样本将冻结的 `file_bridge/file_roundtrip.c` 编译为 guest 内部函数并直接调用，原文件未修改。

构建用 LLD `/map` 获取观察 RVA，不新增 PE export 目录。输出位于 `build/process-bridge/fixtures`，manifest 提供入口、真实 imports、所有观察值的 RVA/尺寸、预期退出码及文件内容。

| 样本 | 原始 PE 行为 | 对照结果 |
| --- | --- | --- |
| normal | 保存并读回静态 67 字节，再调用 ExitProcess(0) | PROCESS_EXIT，7 次 API，FileResult=[8,0,67,67] |
| open_exit | 创建、写入后不 CloseHandle，ExitProcess(0x12345678) | PROCESS_EXIT，保留完整 DWORD 退出码，宿主清理 1 个残留句柄 |
| after_exit | 主入口 direct CALL noinline helper；helper 调用 ExitProcess(0x87654321) | PROCESS_EXIT；helper 后续 marker、第二次 WriteFile、调用方 marker 都不执行，清理 1 个残留句柄 |
| return_only | import-free 原始 RET | FUNCTION_RETURN，无 ExitProcess、无文件 I/O |

ExitProcess 的源码声明刻意不加编译器 `noreturn` 属性。后续 marker、第二次写入和 RET 在实际 PE 中保留，才能测试运行时确实停止，而不是把已被编译器删掉的代码当作不可达证据。`after_exit` 的两条 marker store 和第二处 WriteFile 由构建器检查原始指令确认存在。

默认优化选项确实产生了当前 lifter 不接受的尾跳转，`normal-default-tail.exe` 及其反汇编、日志保留了真实 `REJECT control category`。正式构建使用 `-fno-optimize-sibling-calls` 生成普通 CALL/RET，没有事后修改 PE 指令。四个正式 PE 的静态解码指令数为 152/40/56/1。

## 原始 x86 退出对照

```sh
/opt/homebrew/bin/python3.13 process_bridge/fixtures.py
/opt/homebrew/bin/python3.13 process_bridge/oracle_selftest.py
```

oracle 将原始 PE 映射到真实 x86_64 地址，应用 DIR64 和真实 IAT 绑定，再以 `ms_abi void (*)(void)` 调用入口。五个文件 stub 沿用冻结文件 oracle 的有界 POSIX 合同；退出 stub 仅在这个 x86 测试宿主中使用 `setjmp/longjmp` 停止 guest 控制流，随后清理残留 fd。它不是 Windows/Wine，不模拟 DLL detach、TLS 回调、其他线程或完整进程初始化/销毁。

本轮实际 x86 进程报告页大小 4096。oracle 按 PE 4 KiB 边界设置代码 RX、data/BSS RW 和其他只读页；没有沿用旧样本的整幅 RX 策略，也没有给混合页 W+X。若宿主页无法表达该分区，测试会明确拒绝。实际静态数据写入和文件读回均通过。

正式自测执行四个样本各两次，共 8 次原始无参数 PE 调用：一次让 mmap 自选地址，一次给出非固定的 `0x180000000` hint。每个样本实测得到两个不同的地址，第二次实际地址为 `0x180000000`；每次都检查 anchor 的实际重定位值、原始代码未变、静态 FileResult、完整目的缓冲区、磁盘字节、API 计数、退出类型和句柄清理。结果为 6 次 PROCESS_EXIT、2 次 FUNCTION_RETURN；另有 4 项宿主包装器拒绝，不计作额外 guest 执行。

证据是 `build/process-bridge/oracle-tests/evidence.json`。源输入、实际编译/链接工具、C 头文件依赖和执行对象均有前后身份校验。这不是完整 SDK/dyld shared-cache 签名。`ExitProcess` 的 DWORD 值写入结果字段；测试宿主自身的操作系统退出状态是另一件事，不能把 0x87654321 截成宿主退出状态的低 8 位来验证。

Python 接口为 `Oracle(pe, independent_out, metadata=fixture_record).run(base_hint=None)`。`observations` 是原始十六进制字节；`normalized_observations` 仅将映像指针 anchor 归一为 RVA，方便比较不同加载基址。opaque 文件句柄不作跨后端数值比较。

本证据证明原始 x86 输入的行为及当前 POSIX 合同参考结果；ARM AOT、独立 native host、App 包和 sanitizer 各需自己的执行记录，不能由此自动推导。
