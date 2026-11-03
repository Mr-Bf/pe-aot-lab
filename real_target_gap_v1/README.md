# 真实 PE 与当前 v7 的静态缺口

开发入口：Python 3.13+，从仓库根目录执行。只读取合法获得的 Windows x64 PE 文件或目录；不运行 PE、DLL、Windows loader 或游戏，不生成 AOT。依赖仓库内 `real_pe_inventory_v1` 和冻结的 v7 loader 源码，无新增 Python 第三方包。

```sh
mkdir -p /tmp/my-pe-gap-01
python3.13 -B -m real_target_gap_v1 /absolute/path/to/pe-directory \
  --entry game.exe \
  --json-out /tmp/my-pe-gap-01/gap.json \
  --markdown-out /tmp/my-pe-gap-01/gap.md
python3.13 -B -m unittest real_target_gap_v1.test_report -v
python3.13 -B -O -m unittest real_target_gap_v1.test_report -v
```

`--entry` 必须精确匹配库存中的相对路径；输出必须是输入树外的新文件，现有文件不会覆盖。输入修改、symlink、受审 v7 源码摘要变化会明确拒绝。源码门禁固定 11 个已审核文件；以后改 loader/profile/runtime 时需要新审查和有意识地更新合同，不能盲目刷新摘要。

退出 0 只表示产生了 `GAP_INVENTORY_ONLY` 报告，**不是成功迁移或通过 v7 准入**。报告直接重新读取原 PE，不接受外来库存 JSON 当作事实。原始库存可能 `INCOMPLETE`；每个文件实际经过 v7 的 Python data-image loader 试读，记录首个拒绝。这个 loader 仅生成 Python 字节数据，不创建可执行宿主内存。它通过时也只能称 `loader_admitted_not_decoded`。

报告同时保存原始库存、每个 PE 的 SHA、受审源码身份、当前不准入的目录、代码区大小门禁、导入名表及缺失显式 profile。21 个标签来自 `window_inc_v1.loader.SIGNATURES`，同名只标 `runtime_arguments_unproven`；不等于参数、ABI 或 Windows API 语义已支持。正常和延迟导入中未解析的描述符单独保留，包括存在 DLL 名但没有符号列表的描述符。

此工具没有完成指令解码、控制流发现、DLL 初始化、CRT/TLS/SEH、图形、游戏功能或性能验证。DLL basename 匹配不是系统 loader 解析；文件目录未声明也不证明运行机制不存在。详见 [实际目标报告](../docs/REAL_TARGET_INVENTORY_V1.md) 和 [选型依据](../docs/REAL_TARGET_SELECTION_V1.md)。
