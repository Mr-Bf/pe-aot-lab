# 可从 HLSL 重建的 DXBC 输入

这里提供两个项目自制着色器，供独立 native D3D11 Draw 探针使用。它们由 **Apple Silicon 上实际构建、实际运行的 vkd3d 1.17 编译器**生成 Shader Model 5 DXBC/TPF，并再次编译核对相同字节。没有提取商业游戏资产，没有用宿主 Metal shader 替代 DXBC，也没有手写 DXBC token 冒充编译结果。

本目录的能力状态只是 `SHADERS_CURRENT_NOT_EXECUTED`：这里的编译/反汇编不启动 GPU，不执行 guest，不证明 DXMT 已能绘制。真正 CreateVertexShader/CreatePixelShader/Draw/readback 由另一个探针记录。

## 接口和期望

- `triangle_vs.hlsl`：`vs_5_0`，入口 `main(uint : SV_VertexID)`；3 个位置为 `(-1,-1,0,1)`、`(3,-1,0,1)`、`(-1,3,0,1)`，覆盖 viewport 的全部像素中心。无输入顶点缓冲、常量缓冲和 input layout。
- `triangle_ps.hlsl`：`ps_5_0`，入口 `main()`，输出固定 `(0,1,0,1)`，RGBA8 期望 `(0,255,0,255)`。
- `draw_shaders.h`：由实际 DXBC 生成的 `kTriangleVsDxbc[]` / `kTrianglePsDxbc[]`，长度使用 `sizeof`。它是数据，不含 Windows 或 Metal API 实现。
- 消费者须设置 `TRIANGLELIST`、`CULL_NONE`、32×32 viewport，清屏设为品红 `(255,0,255,255)`，Draw(3,0) 后逐像素读回。设置显式剔除状态，避免依赖绕序默认值。跳过 Draw 应保留品红，是消费者的必要负对照。

`graphics_stage5.build_shaders.verify_shaders()` 只读返回 `inputs`、`artifacts`、编译器记录 SHA、shader 记录 SHA 和两阶段 DXBC 元数据。消费者可将这些实际文件身份合并进自己的输入图，在执行前后校验。正式记录是 `build/graphics-stage5/shaders/evidence.json`；工具记录为同目录 `compiler.json`。

## 来源与许可

本项目 HLSL/生成的数据头沿用仓库 MIT 许可（本目录 LICENSE）。没有复制上游 shader 实现。编译器选用官方 [vkd3d 1.17 release](https://www.winehq.org/news/2025082101)，固定归档 [vkd3d-1.17.tar.xz](https://dl.winehq.org/vkd3d/source/vkd3d-1.17.tar.xz)，SHA-256 `bc61cb9e84d5045cbcaffbdd707940d399d8bf62874663dfe5809a0bfb87e9b6`。这是固定实验工具版本，未宣称最新版本或完整 HLSL 实现。

上游 `COPYING` 声明 vkd3d 为 LGPL 2.1 或以后版本，原文与完整 LGPL 2.1 已保存在 `licenses/`。工具在 `work/` 内静态链接 libvkd3d-shader/common；如果分发该工具二进制，需要按其上游许可处理对应源码和修改/重链接要求，不能当成 MIT 工具。当前 App 消费的只有我们自制的 shader 数据，vkd3d 编译器不被加入 App 运行依赖。GNU Bison/Make 为工具依赖，源归档及其许可保留在工作目录；Khronos SPIR-V/Vulkan 头文件许可证也在 `licenses/` 留存。这里不把“编译工具许可”机械扩张为我们自制输入的许可，也不替代完整产品分发前的许可审核。

[Microsoft DXC 官方说明](https://github.com/microsoft/DirectXShaderCompiler#features-and-goals)说明其命令行目标为 SM6+ / DXIL；因此本批没有将 DXC 输出误称为 D3D11 SM5 DXBC。上游 vkd3d 的 HLSL→DXBC/TPF 能力在当前固定源码/API 和实际本机生成结果中得到核对。

全部下载经官方 HTTPS 来源取得并固定所观察的 SHA；本批没有执行上游发布者 GPG 签名验证。SHA 用于本项目的重复性与过期误用门禁，不是新建的发布者信任根。

## 实际构建及边界

本机最初没有 fxc、dxc、Wine 或 vkd3d-compiler。GNU Bison 3.8.2、GNU Make 4.4.1、Vulkan-Headers v1.3.290、SPIRV-Headers vulkan-sdk-1.3.290.0 均在工作目录内准备，没有系统安装。原始 vkd3d 源文件未修改；正式构建为独立 out-of-tree 目录。

仅构建 `vkd3d-compiler` / `vkd3d-dxbc` 两个命令及静态 shader/common 库，未构建 vkd3d Vulkan renderer。配置显式给出 `SONAME_LIBVULKAN=libvulkan.dylib`，这是上游支持的跳过动态库探测变量；该名称没有在此次工具中成为运行依赖。实际薄 ARM64 Mach-O 和 `otool -L` 均记录，工具只依赖系统 `libSystem.B.dylib`。不依赖 Wine/Rosetta、Vulkan 或 Metal runtime。

记录包含全部固定 vkd3d/两套头文件源文件、真实 compiler/parser/make 工具、Bison 数据文件的前后身份，以及本次构建实际 `.Po` C 传递头文件集合。生成配置、静态库、工具和日志也记录 SHA。GNU Bison/Make 的首次构建在准备阶段完成；其源归档、已执行工具身份和构建日志可以追溯，但不能把这份记录说成整个 macOS、shell 子进程或全部系统库的可复现证明。

实际准备失败保留在 `work/shader-source-research/`：最初缺 Vulkan 动态库的探测失败；`--without-metal` 触发上游 automake 条件变量缺失，改用默认探测；直接只构建 compiler 目标遗漏生成 version header，之后显式先生成该 header。正式证据采集还发现 configure 会为未构建 tests/demos 创建空 `.Po` 占位，解析器现只允许这两类明确未构建目标的空占位，其它空依赖拒绝。没有删除这些失败来伪报第一次成功。

## 复现

在仓库根目录、保留当前工作工具的环境：

```sh
/opt/homebrew/bin/python3.13 graphics_stage5/build_shaders.py --verify-only
/opt/homebrew/bin/python3.13 -O graphics_stage5/build_shaders.py --verify-only
# 重新生成两份 shader/header，不执行 GPU：
/opt/homebrew/bin/python3.13 graphics_stage5/build_shaders.py
```

全新机器先按 `build_shaders.py` 的 `ARCHIVES` 固定 URL/SHA 将 5 个归档下载到 `work/shader-source-research/downloads/`；该路径是工作区根目录下的 work，非仓库内 build。使用 Python 模块的 `archive_files(name)` 校验并安全解包；所有归档必须是原文件，路径逃逸、链接和特殊文件拒绝。

在 `work/shader-source-research/build-bison/` 执行 `../bison-3.8.2/configure --prefix="$PWD/install" --disable-nls`，然后系统 `make -j2` 与 `make install`。在 `build-make/` 同样执行 `../make-4.4.1/configure --prefix="$PWD/install" --disable-nls` 后构建和安装到自己的 `install/`。这些是工作目录工具，不使用 sudo，也不写系统前缀。

随后在仓库根目录运行 `python3.13 graphics_stage5/build_shaders.py --prepare-tool`，生成完整工具记录后再运行不带参数的 shader 编译命令。若已有 `compiler.json`，准备命令明确拒绝覆盖；旧证据应先另行归档，不能把新的构建冒充原来那次。
