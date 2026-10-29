# Cocoa 激活策略：同一字节裸文件与 App 对照

当前 macOS 上已实际复现：App 的策略初始为 Regular，重复设置 Regular 返回 `NO`，策略仍为 Regular。原冻结 `cocoa_registry.mm` 将 setter 返回 `NO` 无条件解释为初始化失败，因此拒绝了本已符合目标状态的 App。

这是本机两个受控进程的观察，不推断所有 macOS 版本的 setter 行为。Apple 的 [setActivationPolicy 文档](https://developer.apple.com/documentation/appkit/nsapplication/setactivationpolicy%28_%3A%29)和本地 SDK `NSApplication.h` 声明分别提供 setter 与当前策略 getter；本轮修复建议按实际目标状态判断，而不依赖重复设置的返回值。

## 实际对照

`build/native-window/activation-diagnostic/activation.mm` 只调用 `NSApplication sharedApplication`、读取策略、设置 Regular、再次读取并输出 JSON。无 NSWindow、Metal 或 DXMT 调用。ARM64 程序先构建并对 App 做 ad-hoc 签名，再将签名后的 executable 按字节复制成裸文件，保证两次执行代码内容完全相同。路径均在 `/private/tmp/PE AOT Activation Diagnostic grtqse4m/`，均从主线程运行。

| 运行形态 | 初始策略 | setter 返回 | 最终策略 | child exit |
|---|---:|---|---:|---:|
| `policy-bare` | 2（Prohibited） | true | 0（Regular） | 0 |
| `Policy.app/Contents/MacOS/policy` | 0（Regular） | false | 0（Regular） | 0 |

两次输入、签名程序字节前后相同；裸文件 bundle ID 为 null，App 为 `org.peaotlab.ActivationDiagnostic`。窗口创建与 GPU 调用均为 0。本轮没有修改冻结 v1/v2 生产源码或运行证据。

```sh
/opt/homebrew/bin/python3.13 build/native-window/activation-diagnostic/run.py build
/opt/homebrew/bin/python3.13 build/native-window/activation-diagnostic/run.py bare
/opt/homebrew/bin/python3.13 build/native-window/activation-diagnostic/run.py bundle
```

构建与两条运行记录分别为 `build.json`、`bare.json`、`bundle.json`；精确 C/SDK 传递头文件、编译/链接/签名工具及输入前后 SHA 记录在构建证据。独立 stdout/stderr 保存原始 JSON。脚本不允许覆写正式记录。准备时第一次依赖解析目标名与既有解析器要求不同，在运行前调整为 `probe`；未影响上述同字节执行对照。

## 下一版修复约束

新版本应先读取当前 policy；只有非 Regular 时请求切换，最后再次读取并要求 Regular。不能简单删除所有错误检测或无条件忽略 setter 失败。窗口创建、事件泵和图形闭环仍需在新版本里重新实际验证；本诊断不使旧 `Cocoa_application` FAIL 变为 PASS。
