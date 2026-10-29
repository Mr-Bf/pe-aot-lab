# 自包含窗口 App v2：静态打包验收

**实际构建、相对加载图、复制位置变化后的加载图与 ad-hoc 签名校验已经通过；没有启动 App、没有加载其库、没有 Cocoa/GPU/guest 执行。** 旧 v1 的 App 初始化失败和 LaunchServices 超时仍然成立，本批没有修复或覆盖它们。

生成的独立 App 位于 `build/native-window/probe-v2-package3/PE AOT Window Probe V2.app`；完整复制件位于同目录 `relocation with spaces/Window Relocated.app`。使用冻结 v1 `probe.cpp` / `cocoa_registry.mm/.h`，新包装器为 `native_window/probe_v2.py`。因此 `cocoa_initialization_issue_fixed=false` 和 `runtime_relocation_verified=false` 都明确保留。

## 后端与封装

后端来自独立 `native_window/build_v2.py`：固定 WSI v1 补丁与 lifetime-v2-r2 补丁组合的新原生库。后端总共产出 4 个 dylib，而 D3D11 实际静态依赖图只有 **3 个可达非系统库**；按实际图封装，不按总输出数猜测。

- `Contents/Frameworks/d3d11.dylib`
- `Contents/Frameworks/dxgi.dylib`
- `Contents/Frameworks/winemetal.dylib`

每份复制先与后端输入 SHA 比对；之后仅在 App 内的复制件执行 install-name/rpath 调整。库 ID 与非系统依赖使用 `@rpath/<name>`，每个库的搜索路径仅为 `@loader_path/`；主 executable 仅为 `@executable_path/../Frameworks`。实际解析图的所有非系统节点均在此 App 内，未指向旧 `work/`、Documents 中的外部库或旧窗口后端。系统 Frameworks/libSystem 等仍由 macOS 提供；静态图不推断未来运行中的动态插件加载。

先给 3 个库签名，再给 App 签名，最后执行系统 `codesign --verify --deep --strict`。这是**本地开发 ad-hoc 签名**，不是 Developer ID、notarization 或其他机器 Gatekeeper 接受的证明。没有加入 entitlements，没有降低系统保护设置。

完整 App 共 6 个文件、53,314,619 字节。复制到带空格的第二个目录后，全部文件字节和 mode 相同、规范化后的实际静态图相同，系统签名校验再次通过。这个结果证明静态封装关系可随路径移动；尚不能称“搬移后程序已经运行成功”。

## 身份和真实失败

正式 `evidence.json` SHA-256：

`052d636862f449c9375343bb13a18c30a233b6e1ac3a0dacd814bad0b391b47b`

包装器 SHA-256：

`0f717d3f3369b6f65a945b7f8f45a9ac7ef8ce86fa17508c8d941fce28a4dec1`

记录有 2,275 项前后输入身份、16 项构建产物身份和 14 条完整命令记录，包含原始固定宿主、真实 C/C++ `-M` 头文件集合、编译/链接/签名/改名工具、后端生产记录及库输出。另记录原 App 与搬移 App 的精确文件清单、SHA、mode 和加载图。校验器从当前文件和后端重新计算，不能仅凭顶层 PASS。此门禁用于过期/完整性检查，不是敌对宿主的数字证明。

两个实际失败准备目录保留：

1. `build/native-window/probe-v2/`：库和 App 已签名，但冻结加载图解析器不接受没有尾斜杠的裸 `@loader_path`。未改旧解析器，后续包装器使用等价且已受支持的 `@loader_path/`。
2. `build/native-window/probe-v2-package2/`：install_name_tool 拒绝同一次命令对同一 `@loader_path/` 同时 delete 与 add。之后保留已正确的路径，仅删除其他路径，在没有正确路径时才添加。失败时没有启动任何代码。

成功版本在全新 `probe-v2-package3/`，没有覆盖原失败目录。副本库的二进制变化属于明确的包装转换，并非伪称与原后端原始文件相同。

## 复验与下一步

```sh
/opt/homebrew/bin/python3.13 native_window/probe_v2.py --verify-only
/opt/homebrew/bin/python3.13 -O native_window/probe_v2.py --verify-only
/opt/homebrew/bin/python3.13 native_window/test_probe_v2.py
/opt/homebrew/bin/python3.13 -O native_window/test_probe_v2.py
```

独立门禁只在内存或临时 App 副本上修改输入：虚构已运行、丢失源/复制/签名命令身份，以及实际缺库、多库和破坏已签名 Info.plist。不会改正式 App 或启动其中代码。普通 Python 与 `-O` 各完成 1 项当前正例与 7 项拒绝，均为 `STATIC_BUNDLE_GATE_PASS`；详细记录是同目录 `gate.json` / `gate-optimized.json`。同一静态场景在两种 Python 模式重放，没有增加 App/GPU 执行计数。

下一步需单独协调本机实际启动这份封装，并记录加载的真实库路径；如果仍在 Cocoa 初始化失败，再以新版本宿主增加 activation-policy 前后诊断，不能悄悄忽略返回 false。截图、用户输入、guest 窗口 API、Draw 和完整 PE 运行均为独立验收，不由本批静态打包结果推导。
