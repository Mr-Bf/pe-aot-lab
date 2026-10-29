# 版本化窗口 switch 事务运行时

本组件在既有窗口事务引擎中增加 kind 5 的有限内部 JMP，不替换 COM、IAT、同步回调、文件或 User32 实现。仅 `AOT_WINDOW_SWITCH_V1` 编译契约启用新增 Context 字段与 hooks；无宏的旧路径继续拒绝 kind 5。

## 接入要求

`runtime.h` 提供新增 API。`runtime_fields.inc` 嵌入 Context，`runtime_impl.inc` 在原 `instruction()` 后嵌入实现。原窗口事务引擎保留指令 begin/commit、预算、首次故障、pending memory write 和 CALL/RET 深度管理。

宿主先注册全部 guest mappings，然后把独立证明导出的一个 jump PC、2–32 个有序目标传入 `aot_configure_switch`，再调用 `aot_bind_switch`。绑定逐字节核对整张表、guest 页权限恰为 READ，以及每项 signed rel32 相对同一表基址计算出的有序目标。不能把用户填写的任意 target 当作证明；配置和表数据必须来自上层对原 PE 的准入结果。

绑定只能尝试一次。任何失败（包括成功后再次绑定）均禁止后续执行与追加 mappings。新版本的 begin 和 execute 都要求绑定成功；最终对外窗口 execute 同样需要门禁。成功的 kind 5 commit 要求正确 jump PC、目标属于已注册集合、RSP 不变且没有 pending write。失败沿原引擎回滚完整 State 和当前待写事务，CALL 深度不变。成功提交后 `aot_window_switch_commits` 增加一次；绑定拒绝、故障和预算停止不增加计数。

READ 是 guest 权限模型，不是宿主操作系统对 C allocation 的 `mprotect`。宿主仍须单线程可信，在绑定后保持 backing bytes 和权限数组稳定。本组件不支持自修改代码、任意 computed goto 或恶意宿主并发修改。

## 已执行的低层验证

从仓库根目录执行，输出目录必须不存在：

```sh
python3.13 -B -m window_switch_v1.run_runtime_tests \
  --out build/window-switch-runtime-v1/new-transaction-run
```

需要原生 Apple Silicon macOS、所选 Xcode SDK 和 Python 3.13。脚本不下载依赖。`runtime_test.c` 直接包含真实窗口 `transaction_v1.c` 及其新宏挂点，使用小型 C 函数模拟指令效果；COM/IAT dispatch 是明确拒绝的 stub。

本机最终记录 `build/window-switch-runtime-v1/transaction-03/result.json` 的 SHA-256 为 `7c208de718a8576c4c0675828628a6447ae212422fc50bd506b18cfd02bd1d43`。新/旧契约各在 O0、O3、ASan＋UBSan 下实际运行，共 6 个 native 测试进程。旧契约每轮 9 项检查，新契约每轮 406 项检查，包括：

- 旧版本 kind 5 拒绝及正常 RET；新版本同一 Context 内 CALL → switch → RET 的深度、栈和成功计数。
- 14 种错误绑定、首次故障保留、禁止修复重绑/追加 mapping、缺失绑定时零 guest 步。
- 2、8、31、32 项表、重复目标、有正负号的 rel32，以及跨两个相邻 guest mappings 的完整表绑定。
- 非法目标、RSP 变化、pending write、错误 jump PC 与 miss 的完整当前指令回滚；预算停止不会伪增成功计数。

这些结果仅验证事务组件：没有执行翻译后的 PE、窗口 App、COM/IAT dispatch 或 GPU，没有性能结论。完整 App 的真实输入路径是否到达 switch，必须由新产物单独运行，并检查成功计数、状态、存档和退出结果。早先两轮保留为覆盖较窄的原始结果，没有覆盖或改写。
