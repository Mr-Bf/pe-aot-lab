# 原始 PE 的 shader/Draw 扩展

当前使用 `bindings_v2.py` 与独立 lifetime-v2-r2 后端，原始 PE 的 ARM64/DXMT Draw 已完成受限验收：O3/O0、两个基址及五个预算前缀共九条运行记录通过。每次正常链检查全部 1,024 像素，退出 0；实际 LLVM/C 插桩每模式 23 个场景、10,997 项断言通过。旧后端存在已保留的提前清理崩溃反例，`bindings.py` 仅用于旧历史核验。见[集成报告](../docs/DRAW_BRIDGE.md)、[实际矩阵](../build/draw-bridge/program-tests-v2/README.md)和[独立复核](../docs/DRAW_BRIDGE_REVIEW.md)。

当前只读开发入口：

```sh
/opt/homebrew/bin/python3.13 graphics_stage5/lifetime_v2/build.py --verify
/opt/homebrew/bin/python3.13 build/draw-bridge/program-tests-v2/verify_matrix.py
/opt/homebrew/bin/python3.13 draw_bridge/test_sanitizers.py --verify
```

这些命令不重跑 GPU。重新构建应用时使用 `draw_bridge.bindings_v2.Program`，输出根必须是 `build/draw-bridge/` 下新的 `*-v2` 目录；真实运行再调用 `Program.run`，失败返回不能当作成功像素验收。下一开发模块为[同一 PE 窗口与输入](../docs/WINDOW_BRIDGE_DESIGN.md)。

以下保留早期样本准备记录，**准备证据本身的 guest、Windows 实机和 GPU 执行次数仍均为 0**，不会改写为后续运行数。原生宿主的独立 Draw 结果见 [native 探针](../build/graphics-stage5/d3d11-draw-v1/README.md)，也不计作这里的 PE 执行。

样本使用原版 DirectX 头，普通 Clang/LLD 输出无参数 x86-64 PE。自制 MIT HLSL 经固定 native vkd3d 1.17 编成 VS/PS DXBC，再作为只读数据嵌入原 PE；宿主没有重编应用逻辑。shader 来源与许可记录见 [shader 构建说明](../graphics_stage5/shaders/README.md)。

PE 为 `build/draw-bridge/fixtures/draw-readback.exe`，SHA256 `a9529dd1f036dbaed49c993c9aac02186c6c1702457e6a927150a914d1a41195`。实际反汇编 378 条静态指令、26 处 vtable CALL、2 处 IAT CALL；不是已执行步骤。VS 728 字节位于 RVA `0x20d0`，PS 428 字节位于 `0x23b0`，均逐字节等于已核验的 DXBC。COFF 未定义符号仅有 D3D11CreateDevice 和 ExitProcess，不包含 CRT 或浮点 helper。

预期流程为：创建 device/context、32×32 RGBA8 target/RTV/staging、VS/PS/rasterizer；先清为品红，再设置 render target、viewport、CULL_NONE、TRIANGLELIST 和 VS/PS，调用 Draw(3,0)。随后 Copy/Map，由原 PE 循环检查所有像素是否为绿色，Unmap、释放 8 份应用引用并 ExitProcess。尚未执行，因此这些是样本合同，不是渲染结论。

新方法包括 Device 的 CreateVertexShader/PixelShader/RasterizerState，以及 Context 的 OMSetRenderTargets、RSSetState、RSSetViewports、IASetPrimitiveTopology、VSSetShader、PSSetShader 和 Draw。**槽 9 同时用于 Device::CreateRenderTargetView 和 Context::PSSetShader；槽 15 同时用于 Device::CreatePixelShader 和 Context::Unmap。** 准入与 runtime 必须按实际接口类型和目标解析签名。准备清单的接口名称只是源程序顺序注释，不能作为任意 vtable CALL 的授权。

冻结的旧 D3D11 producer 实际返回 `REJECT virtual call outside D3D11 slot-shape profile`。该拒绝证明没有静默放开新范围，也不说明后续全部指令已经通过准入。下一步使用独立 producer/runtime/host，继续保存旧版本及其成功证据。

新增方法会使原来的“每个 C3 thunk 一个 region”超过 16-region 上限。新宿主应将稀疏 thunk 合并到受限 arena，只有实际注册页允许 R/X，其余页权限为 0；仍只登记准确 C3 指令地址和受控方法目标，不能通过整段映射放开任意跳转。

复现（依赖固定 LLVM/LLD、旧 lifter 与已冻结 shader 生产者）：

```sh
/opt/homebrew/bin/python3.13 draw_bridge/fixtures.py
/opt/homebrew/bin/python3.13 draw_bridge/fixtures.py --verify-only
/opt/homebrew/bin/python3.13 -O draw_bridge/fixtures.py --verify-only
```

构建记录 `build/draw-bridge/fixtures/evidence.json` 包含实际 C/C++ 头依赖、shader 证据、工具、PE/COFF/反汇编、重定位与旧 profile 拒绝。准备阶段没有 ARM lowering、guest 运行、性能或 Windows 图形 oracle 的结论。
