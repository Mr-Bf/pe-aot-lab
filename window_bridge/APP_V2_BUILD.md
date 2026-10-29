# 保存／恢复 PE 的可搬移 App：v2 静态交付

本轮生成 `build/window-bridge/app-v2-01/PE AOT Integer Tile V2.app`，普通及 Python `-O` 只读验收均通过。状态为 `SAVE_LOAD_APP_STATICALLY_VERIFIED_NOT_EXECUTED`：本报告不增加 App、来宾、窗口或 GPU 执行次数。原样本的两进程存档恢复是另一份实际运行证据，不能代替此包的搬移运行验收。

## 固定输入与转换

新入口为 `window_bridge/app_v2.py`，基于冻结 `app_v1.py` 的打包算法。仅替换保存／恢复程序的来源、固定身份、目录、App 标识与说明，保留原打包器不变。实际依赖 `save_load_bindings_v1.Program.from_build()` 重新核对新 PE、主入口和 WndProc 的提升物、宿主与运行时对象、工具及头文件身份。

| 对象 | SHA-256 |
|---|---|
| 原始 Windows PE | `0e1bcf809cb2aa56f23526f3bbd80e9ee233488a1a5b215f1f810b4bb67aa976` |
| `save-load-program-v1-01/program-build.json` | `7384ae558ceb05fb6761219a629f04c14138bdade45ad7a83deb02f42d0f4391` |
| 打包前 ARM64 可执行文件 | `9a404deef5f0ae807d12ded1d28915f6eea5c31f4935b808dff1da1f743b2609` |
| 新打包器 | `f847bb2d0ccd8b1e526c51020851454099389271110376b3326aa18aa52950b2` |
| 包内 ARM64 可执行文件 | `c71088ea50c4d73e77df275ec633f65a5f6cea873d9d0d0cd1fbbfb74297e61e` |
| 静态打包 receipt | `73dd1529c3895b0f7d86dcda2920640dc1d4bbb92860c3a860768453b9cd2d0e` |

打包复制已有 ARM64 程序及三个 DXMT 库，调整 Mach-O 依赖名和搜索路径，再作本地 ad-hoc 签名；不重新编译 Windows PE，不改写业务规则。`d3d11.dylib`、`dxgi.dylib`、`winemetal.dylib` 全部放入 `Contents/Frameworks`。所有非系统依赖均解析到 App 内，程序使用 `@executable_path/../Frameworks`，库使用 `@loader_path/`。

## 已核对的证据

- 3,068 项输入在打包前后逐项一致，精确绑定源程序、提升结果、工具、头文件和许可材料。
- 两个路径的包各含 16 个文件；`relocation with spaces/Relocated Integer Tile V2.app` 与原包的每文件字节和模式一致。两包实际依赖图均为一个程序和三个包内库。
- 实际比较全部 Mach-O section 的内容与虚拟布局：程序 28 项、D3D11 15 项、DXGI 12 项、WineMetal 29 项。代码、常量、嵌入 PE、数据及零初始化区域布局均保持一致。
- `install_name_tool`、签名及验签的 10 条真实命令和退出码单独留档；普通与 `-O` 验收再次读取依赖图，并对两包实际执行严格验签。
- `build/window-bridge/app-v2-static-review/` 保存普通／`-O` 命令与完整输出、原／新打包器差异和审查 receipt。其 `evidence.json` SHA-256 为 `58d01e14a510411b80b9da5d7cd106c8f0e7f5e9642cc02411f8a582fdcad9b9`。

section 比较不覆盖没有 section 的 link-edit 表和签名字节；这些必要变动由受信任工具的实际命令链、最终完整文件哈希及严格验签约束。此门禁用于防止版本混用和证据过期，不是针对恶意证据作者的数字签名体系。

## 复现与下一步

从项目根目录执行只读验收：

```sh
/opt/homebrew/bin/python3.13 -m window_bridge.app_v2 --verify-only
/opt/homebrew/bin/python3.13 -O -m window_bridge.app_v2 --verify-only
```

重新打包需要新的 `build/window-bridge/app-v2-*` 输出目录，不能覆盖已有 receipt：

```sh
/opt/homebrew/bin/python3.13 -m window_bridge.app_v2 \
  --out build/window-bridge/app-v2-rebuild-01
```

下一验收应将整个签名 App 再复制到 `/private/tmp` 下带空格的新目录，独立记录原包与副本身份，在外部 60 秒监督下用显式 `--data-dir`、预算、超时和测试事件参数启动两次。第二次必须读取第一次来宾写出的同一磁盘文件，宿主不得改写或注入恢复状态；每次保留启动身份、原始输出、dyld 图、退出码和磁盘前后快照，再由保存／恢复专用语义验收器判断。

当前不支持 Finder 无参启动，也没有本包 LaunchServices、真实键盘、像素读回或性能结论。测试事件为 `TEST_QUEUE`；不能据此宣称真实键鼠已验证。签名仅供本地开发，未做 Developer ID／公证；完整后端对应源码及构建证据仍保留在工作区，不把此包称为已完成发布合规的发行版。
