# 自制 integer-tile PE 示例

`integer_tile.exe` 是项目自制的 8 KiB Windows x86-64 PE，按 MIT 发布；没有商业游戏或 Steam SDK 内容。`profile.json` 是与它绑定的窄 Win32/D3D11 窗口契约。

`source.cpp` 原样保留真实原始 `window_bridge/fixture_v2.cpp`。当前 PE 是该原始 PE 的等长存档文件名变体：`integer-tile.bin` 改为 `profile-save.bin`，仅改变数据字符串，指令字节不变。`provenance.json` 记录原 PE、当前 PE、源码、profile 的 SHA256 与精确文件偏移；现有派生逻辑位于 `window_profile_v1/test_build.py`。

公开示例用于从这个合法 PE 重现迁移构建。历史 C++→PE 生成仍使用旧工具链/头文件与证据，不是本导出已验证的独立生成步骤。没有在导出阶段重新编译或运行 PE，也不能把静态 profile 分析视作成功 AOT 或运行验证。

在源码根目录可执行只读分析：

```sh
python3.13 -B -m migration_v5 analyze examples/integer-tile/integer_tile.exe --profile examples/integer-tile/profile.json
```
