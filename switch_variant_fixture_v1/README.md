# 历史自制 switch 输入生成工具

该目录保留原 C 源码与 C→COFF/PE 实验脚本，源码字节未改。`switch_supported_fixture_v1` 和 `switch_variant_fixture_v1` 的 C 文件也是实验 runtime harness 的参考输入；两个构建脚本复用 `switch_fixture_v1` 的 helper。

已有小型 PE 和 decode packet 位于 [`examples/switch`](../examples/switch/README.md)。原构建脚本仍依赖固定 provider / 旧 LLD 的工具闭包与私有准备记录，未宣称在新 clone 后独立重建相同 PE。公开默认准入测试直接使用已登记的自产 PE。完整私有 COFF/relocation/命令日志不随源码发布。
