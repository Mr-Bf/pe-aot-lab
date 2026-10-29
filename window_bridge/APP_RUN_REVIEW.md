# 搬移 App 实际运行：独立只读复审

结论：`window-run-app-relocated-v1` 的既有一次运行通过复审。普通 Python 与 `-O` 都调用真实 `window_app_launch_v1.verify` 并补充核对原始日志、实际加载路径、代码段与磁盘字节。复审没有启动 App、PE、Cocoa 或 GPU，未新增输入矩阵。

实际子进程 PID **31874**，从 `/private/tmp/pe-aot-original-window-ufh_7fs_/relocation with spaces/PE AOT Integer Tile V1.app` 的包内可执行文件直接启动，环境 `PATH=/nonexistent`。退出码 0，无内外超时；`proc_translated=0` 且查询无错误。原始 stdout 与保存结果完全相同，stderr 的所有 dyld PID 都等于该子进程 PID。

核对结果：

- 1097 项累计加载映像中，非系统映像恰为包内 ARM64 可执行文件和 `d3d11.dylib`、`dxgi.dylib`、`winemetal.dylib`。没有回退到工作目录的图形库。该日志证明本次加载身份，不证明每个映像均被执行。
- 原始 PE SHA-256 为 `a9997a6e542efee64c19d8a2ac343d28e294341a187ab954b9d8e0a6a9824da1`。修改 Mach-O 路径及签名后，实际搬移副本与原生构建源的所有代码／常量／数据 section 身份一致：exe 28 项，D3D11 15 项，DXGI 12 项，WineMetal 29 项；其中包含零初始化 section 的布局。此检查不覆盖无 section 的 linkedit 表及签名，另结合原打包器的命令、工具、源闭包和真实签名核验。
- 同一保存负载：1061 步，位置 4，移动 3 次，Draw/Present 各 5 次，5 个 keydown、1 个 repeat 被忽略、1 个 paint，8 项来宾对象引用释放。8 个事件明确来自 `TEST_QUEUE`，实际键盘事件数 0。
- 数据目录仅有 `integer-tile.bin`，20 字节为 `434f573101000000040000000300000005000000`，等于来宾状态和宿主读取记录。SHA-256 `d028262d405197c87f00be59d96f89e8eca97b147074b803b24534da0b1f794a`；五个小端整数是 magic、version=1、position=4、moves=3、draws=5。

范围为带明确 CLI 参数的开发 App 一次直接运行。外部 Python 用于监督／验收；包内原生执行路径不依赖 Python 或 Rosetta。仍未验证 Finder／LaunchServices 无参数启动、实体键盘、合成器画面、像素、读取旧存档或性能。临时签名不是 Developer ID／公证；开发工作区保留完整后端对应源，不能把本包称为已完成发布分发合规。

复现只读检查（脚本使用排他写入，既有证据不得覆盖；要再次运行应保留原记录并复制脚本到另一个审查输出目录，或直接调用生产 `verify`）：

```sh
/opt/homebrew/bin/python3.13 -m window_bridge.window_app_launch_v1 --out build/window-bridge/window-run-app-relocated-v1
/opt/homebrew/bin/python3.13 -O -m window_bridge.window_app_launch_v1 --out build/window-bridge/window-run-app-relocated-v1
```

独立脚本及证据保存在 `build/window-bridge/app-run-review/`：

| 文件 | SHA-256 |
|---|---|
| review.py | `619577d3ecded2481103a4856ac03bc4fe393a810b4c5e06399835dd21b601b6` |
| ordinary-evidence.json | `a5006bf9b15c5938b6713ba9524310737064a935f02b31023fc706c597a9e2e4` |
| optimized-evidence.json | `46abe437f10393d38e3a8f27d6ec9c8a3a8628bb52fdd6aea05797275525a19b` |

身份门禁用于检测输入变化、过期或错误混用，不是数字签名或敌对篡改防护。
