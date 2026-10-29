# 实际窗口路径中的有限 switch 输入

本目录是自制 Windows x86-64 PE 编译输入，沿用 `window_bridge/fixture_v2.cpp` 的窗口、D3D11、20B 存取档与按键契约。`switch8.c` 与已验标量切片的自制 C 源逐字节相同，在单独 COFF 对象中编译，保持真实 8 项 signed-rel32 只读跳转表。Windows 窗口主体继续禁用 jump table，不扩大消息分派器的间接跳转范围。

新样本不是附加一个未调用函数：`WM_KEYDOWN/VK_RIGHT` 的真实 callback 路径调用 `switch8`，返回值经 `&7` 实际写入 `window_state.position`，随后用于绘制与保存。两个 COFF 对象分开编译且不使用 LTO，防止窗口编译器把调用与表常量折叠。

调用参数中的只读 seeds 为 `[2,3,1,0x20000000,0,5,0,7]`。selector 是当前 position，结果为 `[1,2,3,4,5,6,7,7]`，保持 RIGHT 的原有饱和移动逻辑。position=7 的 RIGHT 也调用 switch，以便第七项能由真实窗口输入触发；结果仍为7，比较相等后跳过 position/moves/dirty 的写入。它会多执行 CPU 指令和消耗预算，不声称与旧 PE 步数相同。

样例使用 `switch-tile.bin`，窗口类名为 `PeAotSwitchTileV1`。LEFT、重复按键、Esc、关闭、渲染和文件格式沿用原契约。位置在初始值和读档验证中限制0..7，不把越界 position 当作合法游戏状态。

## 本轮实际证据

`build/switch-window-fixture-v1/pe-02/` 已使用 Homebrew LLVM/Clang17.0.6 与 LLD17.0.6 实际构建，15条外部命令均退出0。原始 MinGW/DirectX header 依赖逐项保存摘要，未加入 CRT 或额外 API。该样本当前仅完成源到PE准备和静态/旧路径拒绝验证，不能据此声称新 App 已运行。

| 项目 | 实际值 |
| --- | --- |
| PE SHA-256 | `39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8` |
| callback／entry RVA | `0x1000`／`0x1140` |
| 实际 direct CALL RVA | `0x111c` → `0x1c30` |
| switch leaf | RVA `0x1c30`，67B，25条指令 |
| 跳转表 | RVA `0x2610`，32B，8个互异叶函数指令目标 |
| `.rdata` | RVA `0x2000`，virtual_size2456，raw_size2560，exact READ，无DIR64重定位 |
| `.data` DIR64 | 仅 `0x3078`、`0x30b0`，均不交叠跳转表 |
| 实际返回值消费 | `0x1121` AND EAX,7；`0x1124` 与旧position比较；`0x1128` 写 `window_state+8`；变化时才INC moves |
| imports | 原21个已登记 Win32/D3D11 API，无新增 CRT/helper |

COFF的1个表基址与8个目标重定位均对实际链接结果重新计算并比对。`review-02` 从PE原始节头独立检查 file-backed/只读范围、实际 seeds 参数传递、CALL目标和返回值消费；callback的77个静态CFG边界包含该调用。静态可达性不等于某次运行已经走过此路径。

旧CPU provider 的真实 callback decode 已执行，退出1并记录 `REJECT control category`，没有生成 accepted manifest、IR或ARM对象。这只证明旧路径明确拒绝，不把它当作已支持 kind5。旧provider的manifest和工具摘要不变。

`pe-01` 保留第一次编译后验证脚本把 relocation字典当整数处理的失败。修复脚本后，新目录 `pe-02` 通过；旧失败未覆盖。原C叶函数和当前窗口PE的完整执行验收属于后续正式App集成。

## 重现输入准备

从仓库根目录运行。参数必须指向已保留且版本固定的工具和原始头文件；本脚本不下载依赖，不启动Windows、App、guest或GPU。输出目录必须不存在。

```sh
python3.13 -B -m switch_window_fixture_v1.build_fixture \
  --provider "$CPU_PROVIDER" --linker "$LLD_LINK" \
  --headers "$MINGW_INCLUDE" --dxheaders "$DIRECTX_HEADERS" \
  --out build/switch-window-fixture-v1/pe-new

python3.13 -B -m switch_window_fixture_v1.review_fixture \
  --fixture build/switch-window-fixture-v1/pe-new \
  --provider "$OLD_CPU_PROVIDER" \
  --out build/switch-window-fixture-v1/review-new
```

`profile-base-v1.json` 仅保存与该PE绑定的原窗口ABI、根、导入和只读观察元数据。它不是 switch 能力授权；旧 profile/Session 仍应拒绝实际 switch 代码。正式集成应在版本化新profile与provider下独立发现并证明表，而非信任这里的 manifest 目标列表。

源码为项目第一方研究样例，许可见仓库根 LICENSE。构建用第三方工具与头文件不包含在本目录；其各自许可不变。本输入不含商业游戏、Steam SDK、DRM或反作弊处理。
