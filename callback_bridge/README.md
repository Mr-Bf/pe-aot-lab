# 真实 PE 同步回调实验

本目录研究 `原始 PE → 导入 API → 本机 typed callback → 原始 PE 回调 → 本机 API → 原始调用方`。输入是自制 PE32+，没有 Windows DLL、游戏、DRM 或反作弊组件。`aotdemo.dll!NativeInvokeCallback` 是自制测试 API；它使用 Windows x64 调用约定，不能据此宣称已支持某个 Windows 系统回调 API。

## 已知签名与四个样本

导入 API 接收七个参数：`NativeInvokeCallback(callbackGuestVA, a, b, c, d, e, f)`；回调接收六个 `uint64_t` 并返回 `uint64_t`。第 5、6 个回调参数走真实 guest 栈。guest callback 地址来自原始 PE 的 RIP-relative LEA，ARM 运行时必须先按显式注册的 RVA/签名解析；它不是可直接调用的宿主指针。

四个 PE 的主入口均为 RVA `0x1000`，回调入口均为 RVA `0x1040`：

| 样本 | 回调行为 | 正常结果（模 2⁶⁴） |
| --- | --- | --- |
| `leaf` | 直接计算六参数加权和，再加 17 | `a+3b+5c+7d+11e+13f+47` |
| `import` | 回调通过原始 IAT 调用 `NativeSix`，再加 17 | 同上；正常 API 调用数为 2 |
| `direct` | 回调通过原始 direct CALL 调用 PE 内部 helper，再加 17 | 同上 |
| `nested` | `a==0` 返回加权和加 17；否则通过原始 IAT 调用自身，传 `a-1`，返回后加 17 | `3b+5c+7d+11e+13f+(a+1)*40+7` |

每层本机 API 在回调返回后加 23，最外层原始 PE 在 API 返回后加 7。`nested` 正常路径的 API 调用数、回调数与最大回调深度均为 `a+1`。原始 x86 oracle 只允许该样本的 `a≤8`；更深输入用于 ARM 运行时拒绝测试，不交给原始代码无限递归。

## 提升方式及其限制

复用冻结的 `native_bridge` Remill 工具，整段 `.text` 仍由 `--address` 指定，每个入口独立传 `--entry_address`。不修改 PE 的 `AddressOfEntryPoint` 或 `.text`。`lift_pe` 只在已加载映像的内存副本中选择根，manifest 同时记录原始入口与实际根 RVA。

每根单独产生 ARM64 对象。所有非根 `sub_<VA>` 函数按根 RVA 命名并设为 LLVM `internal`；对象导出的函数只能是 `aot_entry`、对应的 `aot_callback_<rva>` 或独立合成 RET 的 `aot_import_ret`。两根到达同一原始 helper 时，guest PC 不变，但 LLVM 私有符号隔离。真实链接测试覆盖此情况。

导入 helper 可以重入并读写同一个 State/Context，因此其声明与 callsite 不得带 `nocallback`、仅参数内存、只读/只写、`speculatable` 等错误属性；memory 属性必须缺省或为完整 `memory(readwrite)`。验收包含对实际生成 IR 的属性篡改拒绝。这些是编译器合同检查，不能代替实际运行时的上下文、权限、生命周期和返回栈测试。

原始 x86 oracle 使用相同 PE `.text`，将 IAT 正常绑定到真实 `ms_abi` C 函数，然后以 typed 六参数函数指针调用原始 PE 回调。它核对实际传到 API 的参数、调用次数和回调深度。oracle 的真实宿主函数指针仅存在于 x86 测试进程；ARM 的 IAT 仍使用 guest VA。

## 复现入口

以下从仓库根目录运行，依赖已构建的冻结 Remill/LLVM17 环境和 Apple Silicon macOS。原始 x86 oracle 需要 Rosetta 可运行 x86_64 Mach-O。

```sh
/opt/homebrew/bin/python3.13 callback_bridge/fixtures.py
/opt/homebrew/bin/python3.13 callback_bridge/test_lift.py
```

Python 接口：`lift_roots(pe, out, callback_rvas=[0x1040])`；`Oracle(pe, out).run_many(six_uint64_vectors)`。完整 ARM 运行时验收由同目录的 Program 与 sanitizer 测试提供；提升成功、oracle 成功和完整 ARM 成功必须分别引用各自的证据。

`arm64-o0.o` 表示以 O0 lower 已经过 Remill 前期优化的 LLVM IR，不是完全关闭所有前期优化。当前仅支持受限整数指令、显式白名单导入及同步单线程回调；不支持任意回调发现、异步回调、线程切换、SEH、变参、浮点/结构体签名或通用 Windows API。

manifest 记录显式生产源码、依赖的旧源码、冻结工具/语义文件、原始 PE 和实际对象哈希，并检查提升前后身份一致。这不是数字签名，且本生产器没有重新计算整个 SDK/toolchain 的传递依赖闭包；不能把其显式清单称为完整供应链证明。

## 许可来源

生成的 IR/对象含 Remill 指令语义。沿用 pinned Remill commit `56918a8c2554088e93389e97d292f4035286506c` 的 Apache 2.0 许可，原文见本目录 `LICENSE.remill`；冻结工具修改及许可说明见 `../native_bridge/NOTICE.md`。本目录新增的是项目自制样本、入口适配、测试和 oracle，并未再修改 Remill 源码。合成 `C3` 返回 shim 是兼容层代码，不是 Windows DLL 代码。LLVM、XED、macOS SDK 和测试用 compiler-rt 各保留自身许可。
