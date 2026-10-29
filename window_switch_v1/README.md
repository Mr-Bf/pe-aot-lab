# 有限 switch 接入正式窗口 App

本模块将只读 rel32 跳转表接入版本化的 profile、CPU provider、完整 AOT、Windows API/COM 运行时及 macOS App。`migration_v6` 是本轮入口；`migration_v5` 和原 scalar switch 接口保留各自能力边界。

本机已经完成自产窗口 PE 的整链构建及两轮真实 Cocoa 系统事件运行。原路径执行 Right/Right/Left/Escape，搬移副本恢复同一存档后执行 Right/Escape；guest 分别完成 2/1 次 switch 提交及正常保存退出。这些是自动化发出的系统事件，不是物理键盘或 TEST_QUEUE。图形复用已验证的固定 DXMT provider，本轮未重建图形工具链。

独立真实 WndProc 对象还在两个 PE 基址、O0/O3、8 个位置上执行了 32 个用例，完整 State、映像、栈和提交轨迹在同基址的优化模式间一致。该探针以拒绝 COM/IAT 的 stub 链接，RIGHT 路径不调用 API；它不代替上述真实 App/Cocoa/图形验收，也不是新的原 x86 差分或性能测试。

## 明确的新契约

- Profile：schema 2，`runtime_contract=win32-d3d11-tile-switch-v1`，增加整数 `switch_leaf_rva`。不能声明 targets/table 来授予执行能力。
- Provider：`WINDOW_SWITCH_PROVIDER_BUILT_NOT_GUEST_EXECUTED`，精确 capability `window-rel32-v1`。这是依赖原 CPU provider 的 driver/source overlay，不能冒充独立、可任意搬移的完整工具链。
- 每个 main/callback 根先产生完整候选记录；原 PE 字节重新证明无导入、无写操作的 scalar leaf。所有根合并后，只有 DIRECT CALL 可以进入 leaf 根；禁止外部边或 callback/root 进入 leaf 内部任一指令。全程序审查通过后才生成 IR。
- 表项数 2..32，当前实际窗口输入为 8 项。限制一个表、一个显式 leaf、一个不含 DIR64 的非 `.reloc` READ 数据节，输入范围最多 64 KiB；代码范围最多 32 KiB。
- 运行时保留窗口、IAT、COM、回调及同一 Context 的真实 CALL/RET。所有映射注册后绑定原表字节、exact READ 权限与逐项目标；失败永久禁止执行。kind 5 不改变调用深度，每条指令继续使用 begin/commit 事务。
- LLVM switch 在分派前按当前 trace 的实际入口与 preferred 入口之差规范化地址；事务和故障仍使用真实 PC。已实际覆盖 preferred 和另一 PE 基址。

可信单线程宿主必须在绑定后保持 backing 和权限稳定。此契约不支持任意间接跳转、多表、动态代码、恶意宿主并发改写或一般 Windows 游戏。

## 构建和验证

需要 Apple Silicon macOS、Python 3.13、所选 Xcode/SDK，及已验证的普通 CPU 和 DXMT 图形 provider。先使用根 README 的固定依赖入口构建普通 provider，再执行以下命令。所有 prefix/out 必须是不存在的新目录；不要覆盖历史成功或失败。

```sh
export CPU_BASE="/absolute/path/to/cpu-provider"
export GRAPHICS_PROVIDER="/absolute/path/to/graphics-provider"
export SWITCH_PROVIDER="$PWD/.local/window-switch-driver-01"

python3.13 -B -m window_switch_v1.provider \
  --provider "$CPU_BASE" --prefix "$SWITCH_PROVIDER" \
  --out "$PWD/.evidence/window-switch-provider-01" --jobs 2

python3.13 -B -m migration_v6 analyze examples/window-switch/switch_tile.exe \
  --profile examples/window-switch/profile.json
python3.13 -B -m migration_v6 build examples/window-switch/switch_tile.exe \
  --profile examples/window-switch/profile.json \
  --identifier org.peaotlab.switch.example.v1 \
  --cpu-prefix "$SWITCH_PROVIDER" --backend-prefix "$GRAPHICS_PROVIDER" \
  --out "$PWD/.evidence/window-switch-app-01"
python3.13 -B -m migration_v6 verify "$PWD/.evidence/window-switch-app-01"
```

静态 build/verify 不会运行 App。真实运行监督与独立复核见 [migration_run_v3](../migration_run_v3/README.md)；callback 两基址探针入口为 `python3.13 -B -m window_switch_v1.callback_probe --help`。真实窗口操作与探针分别保存证据。测试均不能据以声称 FPS 或快于 Wine＋Rosetta。

不依赖 native 工具链的门禁测试：

```sh
PE_AOT_SWITCH_INPUTS=examples/switch python3.13 -B -m unittest \
  window_switch_v1.test_admission window_switch_v1.test_profile \
  window_switch_v1.test_lift window_switch_v1.test_headers \
  switch_aot_v1.test_admission switch_aot_v1.harness_test \
  migration_run_v3.test_run migration_run_v3.test_review
```

再加 `-O` 复核同一组门禁。原始 C++→PE 重建另外需要显式 LLD 与 Windows/DirectX headers，参见 `switch_window_fixture_v1/README.md`；提供已登记自产 PE 不等于第二台干净机器已完整复现。

原创部分遵循根 MIT；Remill 衍生补丁与源码继续保留 Apache-2.0，见 `integration_stage3/LICENSE.remill`。App 资源保留原 provider 与新增 driver patch/header 的归属和变更文件。
