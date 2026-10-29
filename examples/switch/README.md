# 两份自制 finite-switch PE

本目录只提供项目自产的小型测试输入与解码候选 packet，没有游戏数据或原始运行日志。

| 输入 | C 源码 | 候选 packet |
| --- | --- | --- |
| `switch8.exe` | `switch_supported_fixture_v1/switch8.c` | `supported.packet.json` |
| `switch8_variant.exe` | `switch_variant_fixture_v1/switch8_variant.c` | `variant.packet.json` |

两份输入由真实 Clang 生成 COFF 并由 LLD 链接成 PE。它们具有 8 项只读 rel32 跳转表；变体改变 C 参数顺序、运算及寄存器分配。`provenance.json` 记录原私有实验的相对来源与每个文件 SHA256。没有为了准入手写或改写编译出的跳转表。

保存的 packet 状态仍是 `CANDIDATE_CLOSURE_NOT_PROVEN_NOT_LIFTED`；它只是解码器发现的候选。准入模块必须结合对应原 PE 证明表内容、guard、目标边界和完整控制流，不能把 packet 本身当可信允许列表。ARM runtime/差分通过范围见主 README；这些输入不代表任意间接跳转、函数指针、虚表或实际游戏被支持。

参数化准入测试使用 `PE_AOT_SWITCH_INPUTS="$PWD/examples/switch"`。生成相同 PE 的历史 fixture 脚本仍有固定工具准备前提；本目录首先提供可直接复核的已登记测试字节。
