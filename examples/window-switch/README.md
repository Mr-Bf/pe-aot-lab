# 真实窗口路径的 switch 样例

`switch_tile.exe` 是本项目自产 Windows x86-64 GUI PE，来源见 `provenance.json` 和 `switch_window_fixture_v1/`。其 RIGHT 按键回调实际调用带 8 项只读 signed-rel32 跳转表的独立函数，返回值改变位置，随后绘制并保存。没有 CRT、商业游戏、DRM 或反作弊组件。

`profile.json` 使用 schema 2／`win32-d3d11-tile-switch-v1`。配置只声明 leaf 入口，不授权表地址或跳转目标；转换器必须从原始 PE 重新证明。旧 `migration_v5` 和普通 CPU provider 会拒绝该能力。

开发与构建入口见 [window_switch_v1](../../window_switch_v1/README.md)。这是受限工程样本，不表示一般 Windows 游戏可迁移；性能尚未验收。
