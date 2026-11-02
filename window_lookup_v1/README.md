# 生产运行时指令查找优化

本模块为固定窗口PE契约提供版本化runtime源码生成、producer、静态独立reader和新产物callback检查。`runtime.py`只替换旧transaction中的一个instruction查找函数；`migration_v7`负责App构建，`migration_run_v4`负责真实窗口监督及存档复核。

已验证：新App构建、32份正常callback输出和1456份完整预算记录、原路径及搬移两轮实际Cocoa运行。完整证据、失败、命令与边界见 [本轮报告](../docs/WINDOW_LOOKUP_V1.md)。没有App/FPS性能结论。

`probe`使用新产品实际生成的transaction和新提升对象，复用冻结单策略CPU harness；`--accepted`必须指向按前批步骤在本机生成的受验准备目录。公开源码不包含原始大体积构建产物，不能只clone就直接引用本机路径。

```sh
python3.13 -B -m window_lookup_v1.review --help
python3.13 -B -m window_lookup_v1.probe --help
python3.13 -B -m window_lookup_v1.probe_review --help
```

源码／构建／正确性／受限集成已验；完整外层ABI性能、代表性应用性能、长期稳定性及真实游戏仍待验。
