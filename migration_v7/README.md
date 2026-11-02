# 版本化 inline lookup App 构建入口

`migration_v7` 接受现有 `window-switch-v6` 使用的 schema2 PE profile，输出产品类型 `window-lookup-v7`。CPU 与图形 provider 必须显式给定并通过原有验证；本入口复用 provider，重新提升 PE 根、编译六个宿主单元、链接和打包 App。构建不自动执行 guest、GPU 或窗口。

```sh
python3.13 -B -m migration_v7 analyze examples/window-switch/switch_tile.exe \
  --profile examples/window-switch/profile.json
python3.13 -B -m migration_v7 build examples/window-switch/switch_tile.exe \
  --profile examples/window-switch/profile.json \
  --identifier org.peaotlab.lookupfixture.v1 \
  --cpu-prefix /absolute/verified/switch-provider \
  --backend-prefix /absolute/verified/graphics-provider \
  --out /absolute/fresh/product
python3.13 -B -m migration_v7 verify /absolute/fresh/product
```

路径与 identifier 应按本次实际构建选择；不得覆盖历史产物。`window_lookup_v1` 将固定版本 `runtime.c` 原样复制到新输出目录，只替换相邻 `transaction_v1.c` 的 `instruction()` 函数。`native/runtime-source/runtime.json` 记录固定模板、候选实现和生成文件身份；产品与 producer 的 `runtime_lookup` 字段绑定该回执和编译路径。依赖记录必须选择生成的两个 C 文件，排除原 transaction 文件。

本版本没有实验策略选择器，没有更改 Context、权限、指令快照、预算、CALL/RET、switch 或外层 ABI。复用原打包器；原版本和原回执不修改。实际 App、回调、存取档、搬移运行和性能需分别验证，不能从静态构建推断通过。

纯 Python 源码与拒绝门禁测试，不执行 native：

```sh
python3.13 -B -m unittest window_lookup_v1.test_runtime migration_v7.test_build -v
python3.13 -B -O -m unittest window_lookup_v1.test_runtime migration_v7.test_build -v
```
