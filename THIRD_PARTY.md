# 许可证与第三方归属

项目自编源码由根目录 `LICENSE` 按 MIT 发布。该许可不替代下列第三方或衍生部分的许可。此导出包含第一方源码/补丁和明确登记的自产 PE 样例，不包含已安装的 LLVM、DXMT 动态库、macOS SDK、Steam SDK 或游戏资源。

| 组件 | 固定版本/用途 | 许可与保留说明 |
| --- | --- | --- |
| Remill | `56918a8c2554088e93389e97d292f4035286506c`；XED 解码、LLVM lifting 与本地 driver 补丁 | Apache-2.0；`licenses/Remill-Apache-2.0.txt`、`integration_stage3/NOTICE.lifter.md` 及各模块 `NOTICE` / `LICENSE.remill`。补丁及由 Remill 产生的语义 IR/对象中的衍生部分保留原许可。 |
| DXMT | `d162ea44a31fbf9089ea09977337f0beb30bd082`；原生 D3D11→Metal backend 的修改 | LGPL-2.1-or-later；原文 `licenses/DXMT-LICENSE` 与 `DXMT-COPYING.LIB`。本地修改为 Metal module-cache、native WSI、lifetime v2 patches 和 `native_window/native_wsi.{h,c}`。此固定提交不适用早期版本的 MIT 许可。 |
| LLVM | CPU 的固定 LLVM17 工具包；graphics 的固定 LLVM15 源码子树 | Apache-2.0 WITH LLVM-exception；随原始依赖保留许可，另保留 graphics 原文 `licenses/LLVM15-LICENSE.TXT`。此仓库没有捆绑 LLVM 二进制。 |
| DXBCParser / Windows 与 DirectX 头 | backend 构建依赖 | Microsoft MIT 文本在 `portable_graphics_v1/licenses/DXBCParser-MIT.txt`；MinGW/DirectX 头的原始归属由固定依赖和构建出的 licenses 目录保留，不能统一改标项目 MIT。 |
| 自制 shader 与历史编译工具 | `graphics_stage5/shaders/` | 自制 HLSL/DXBC header 为 MIT；保留该目录 LICENSE 和 licenses 中的 vkd3d、SPIR-V、Vulkan 头归属。历史 vkd3d compiler 是 LGPL 工具，未随此源码导出发布。 |
| 其他构建依赖 | XED、mbuild、gflags、glog、GoogleTest、CMake、Ninja、zstd、Meson | 固定身份见 cache-lock / sources.py。分别保留官方包自带 Apache/BSD 等原文和组件归属；本导出不包含这些安装包。 |

本地 Remill 修改包括 XED-only 构建选择、事务 begin/commit、受限 AOT profile、显式 import/vtable/window calls、INC 支持与显式 semantics 位置。`portable_lifter_v1/build.py:PATCHES` 列出实际应用的补丁。独立 switch 实验的 `switch_aot_v1/driver.patch` 与 `SwitchProfile.h` 扩展 Remill 的有限 rel32 表候选发现、显式 switch lowering 和事务默认拒绝；相关 Remill 衍生内容仍按 Apache-2.0 保留。独立 runtime、准入证明与自制输入属于项目原创部分。

Apple SDK/Xcode/系统库由用户本机提供；项目不授予重分发它们的权利。若另行发行 App 或第三方二进制，需要分别处理原许可要求的对应源、修改说明、替换/重链接等义务；这份源码归属清单不是该二进制发行已验收的声明。


## window-switch-v1追加

window_switch_v1/window-driver.patch修改Remill的Lift.cpp及TraceLifter.cpp，继承其Apache-2.0许可与声明；SwitchProfile.h随driver作为本轮变更保存。新App资源纳入原CPU补丁及新增driver.patch/window-driver.patch/header，不能以根MIT覆盖Remill衍生修改。原创运行时include、Python流程及自产窗口样本按根MIT；DXMT及其其他固定依赖许可不变。本源码更新不发布预构建App或第三方工具链。
