# 保存／恢复窗口程序：独立原生构建

新 `save_load_bindings_v1.py` 已真实生成 ARM64 可执行文件，普通 Python／`-O` 静态验收均通过。**本阶段没有启动该文件、加载其图形库、运行来宾、窗口或 GPU，尚不能称同 PE 保存／恢复通过。**

构建目录 `build/window-bridge/save-load-program-v1-01`，收据 `program-build.json` SHA-256 为 `7384ae558ceb05fb6761219a629f04c14138bdade45ad7a83deb02f42d0f4391`。实际 thin ARM64 Mach-O：

```text
window-9a404deef5f0ae807d12ded1d28915f6eea5c31f4935b808dff1da1f743b2609
```

此新前端由冻结 `window_bindings.py` 明确复制成独立版本，差异保存在 `save-load-static-review-v1/consumer-diff.patch`，不通过修改旧模块全局变量来绕开准入。固定绑定新 fixture／prepare 的 SHA、PE `0e1bcf80…` 和 `window_inc_v1` 精确源集合；旧 PE、旧输出空间和伪造 metadata 明确拒绝。原保存、像素、运行时、Cocoa 与后端源未修改。

本次重新生成了原 PE main、WndProc 两根的 O3/O0 对象以及合成 C3 RET shim，最终宿主选择 O3 链接。main 568 条、WndProc 75 条，共 643 条原始可达指令；21 个导入，ReadFile 的两个真实调用点 RVA `0x1220`／`0x125f` 均绑定 IAT `0x2728`、签名 6。没有从宿主注入恢复后的游戏状态。

所有五个原生编译单元都在新目录真实重编：`window_host.c`、`window_runtime/runtime.c`、`native_backend.cpp`、`native_backend_window.cpp`、`cocoa_host.mm`。没有复用旧 `runtime.o` 或宿主对象。实际 `-M` 闭包强制宿主读取本次 `native_image.h`、运行时读取本次 `native_imports.h`；生成头、编译命令、对象、链接前后哈希和三库实际加载图均由 3059 项输入身份与 14 项构建产物绑定。静态图是可执行文件加固定后端三库；尚未实际 dyld 加载验证，也不是可搬移 App 打包结果。

新增静态观察共 14 项，包含原窗口状态，以及 `window_load_result` 36 B、`window_load_candidate` 20 B、extra/count 缓冲区。原生宿主原有通用观察循环读取这些已界定范围；来宾才负责 ReadFile、校验和恢复。新 consumer 保留通用执行端点 schema；返回 `ACTUAL_*_OBSERVED_NOT_ACCEPTED` 并不等于两进程恢复验收。

`test_save_load_build_v1.py` 在普通和 `-O` 中验证真实链接对象集合、架构、嵌入 PE／观察名称、新头依赖及四项拒绝：旧输出目录、旧保存 PE、错误加载观察尺寸、将 ReadFile 调用改绑为 WriteFile。后两种构造负例都在提升／编译前停止；记录明确为门禁测试，来宾执行为零。既有正／负记录不覆盖。

| 冻结项 | SHA-256 |
|---|---|
| save_load_bindings_v1.py | `8004785cf525d72de8f31463d5addb420ea2a005c47b741293246edbe4416aca` |
| test_save_load_build_v1.py | `24d56e8990abea3d345d90cd9c6056c03656446a99749ddf071e0e8e217e357d` |
| 普通静态验收 | `a34634b2548b3ede9ac0be8e9e5baafdded5b856936d5c0076f14514a9485e20` |
| -O 静态验收 | `d80b9e37d79758a6e4f7c68e45d75a9d4324e7f508c5655eba3f86de0464243a` |

独立 reviewer 已核新源差异、闭包、ReadFile6、新 metadata 和五单元重编路径，未发现本次范围的阻断；未新增 GUI 测试。指令层独立复核另见 `docs/WINDOW_INC_V1_REVIEW.md`，不能把其 320 个标量输入当成保存／恢复执行。

复现构建与只读校验：

```sh
# 新目录，不能覆盖现有首轮收据
/opt/homebrew/bin/python3.13 -m window_bridge.save_load_bindings_v1 --out build/window-bridge/save-load-program-reproduction
# 两条都只读现有产物，不启动程序
/opt/homebrew/bin/python3.13 -m window_bridge.save_load_bindings_v1 --out build/window-bridge/save-load-program-v1-01 --verify
/opt/homebrew/bin/python3.13 -O -m window_bridge.save_load_bindings_v1 --out build/window-bridge/save-load-program-v1-01 --verify
```

下一实际测试必须由外部监督器在第一轮前记录空目录，第二轮前记录第一轮文件原字节／哈希，并将原文件直接交来宾读取。两轮固定同一新 PE／原生文件，核 candidate 与磁盘、ReadFile20B+EOF0、每项 API 计数、完整资源清理和保存后文件。累计 draws 必须减去加载初值再和本轮 presents 比；不能照搬旧 save-only 谓词。

仅由源码推导的正常预期（尚未实测）：缺文件首轮 API4..9 为 `[2,1,0,1,1,0]`，第二轮恢复为 `[2,1,2,2,0,0]`；bytes_read 为 0／20，bytes_written 均 20。CREATE_ALWAYS 新文件／已有文件最后错误分别为 0／183，后续成功 Write/Close 保留该值。实际结果必须独立核对，不为迎合此预期更改计数。坏存档、预算、实体键盘、像素、搬移和性能仍为后续独立执行任务。
