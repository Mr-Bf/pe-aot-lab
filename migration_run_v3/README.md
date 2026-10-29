# window-switch-v6 原生 App 运行与独立复核

本模块复制并版本化适配 `migration_run_v2` 的单进程监督流程，只接受 `migration_v6` 生成的 `window-switch-v6` 成功产品，以及 schema2／`win32-d3d11-tile-switch-v1`／`switch_leaf_rva` 新profile。旧v2路径、产品、契约和证据不变。

运行监督仍直接启动包内 `Contents/MacOS/pe-aot-window`，argc=1。它不调用UI工具、不提供TEST_QUEUE、不清空或注入默认Data、不启动第二个实例。进程枚举保守检查任何路径下的项目launcher；有额外实例即失败。超时仅终止自己持有的 `Popen` 子进程句柄，不按进程名或任意PID清理。

与v2相比，正常观察还必须满足原始host JSON中的 `switch_commits` 为正整数且不超过guest steps、实际Cocoa键事件为正。构建成功、配置中声明leaf或未触发switch的Left/Esc运行都不能满足该条件。

## 运行命令

从仓库根目录执行，选择全新证据目录。超时范围30–600秒；600秒用于容纳桌面工具观察延迟，并非性能目标。

```sh
python3.13 -B -m migration_run_v3 \
  --product build/window-switch-v1/app-04 \
  --out build/migration-run-v3/original-01 --timeout 600

python3.13 -B -m migration_run_v3 \
  --product build/window-switch-v1/app-04 \
  --out build/migration-run-v3/relocated-01 --relocate --timeout 600
```

第二条命令应在第一轮正常结束、已保存证据后执行。搬移副本保持同一identifier和默认Data，独立reader检查第二轮冻结输入是否逐字节等于第一轮保存结果。所有重试使用新目录，旧失败不覆盖。

出现 `LIVE_NATIVE_APP_PROCESS` 后，外部控制者用实际PID和完整路径绑定已经启动的App一次，再提供真实Cocoa系统事件。至少一次Right后使用Esc或关闭窗口正常退出。最终退出动作之后，只允许等待该监督进程及不激活应用的listApps／ps检查，不再getApp、AX或截图。监督器不会替操作者执行这些操作。

`ACTUAL_SWITCH_V6_APP_EXECUTION_OBSERVED_NOT_ACCEPTED` 只表示观察条件通过，还需独立复核。

## 独立冻结文件复核

`review.py` 仅用标准库读取产品、App和冻结证据，不导入生产validator、不运行subprocess、UI、native、GPU或SDK扫描，不读实时AppData。调用方必须显式提供本次产品 `result.json` 的SHA256，并以全新JSON文件作为输出。

```sh
python3.13 -B -m migration_run_v3.review \
  --product build/window-switch-v1/app-04 \
  --product-receipt-sha <实际result.json的64位SHA256> \
  --run build/migration-run-v3/original-01 \
  --run build/migration-run-v3/relocated-01 \
  --out build/migration-run-v3/roundtrip-review-01.json
```

一个 `--run` 可复核单次运行；两个 `--run` 要求先原路径、后搬移副本，两个独立PID、时间先后、源码身份和存档/wrapper历史连续。reader从原始stdout重新解析结果，并重算产品/App摘要、Mach-O ARM64 UUID和dyld路径、PID/argv、wrapper默认路径、正常退出、资源释放、TEST_QUEUE=0以及冻结文件。真实switch counter必须等于记录的Right次数且大于0，不从构建推断执行。

每次运行完成后，在对应证据目录保存 `cua-actions.json`，记录实际工具观测，不能预造操作成功。最小格式为：

```json
{
  "kind": "TRANSCRIBED_ACTUAL_CUA_TOOL_ACTIONS_NOT_RAW_OS_TRACE",
  "pid": 12345,
  "app": "/absolute/path/PE AOT Converted.app",
  "events": ["right", "right", "left", "escape"],
  "physical_keyboard": false,
  "actions": [
    {"operation": "实际执行的工具操作", "reported_wall_seconds": 0.1}
  ],
  "post_exit_policy": "No getApp/AX/screenshot after final exit action; wait supervisor then non-activating listApps only."
}
```

上述PID、路径、操作及耗时都是格式示例，必须替换成实际记录。`events` 是显式小写动作序列：前面只允许left/right，最后只有一个escape或close，必须包含right。reader依据冻结输入存档或PE初始状态重算position/moves，并用实际Present计数复核持久化draws；还核对guest观察的keydowns、重复键、关闭、保存及恢复计数。该动作转录不是独立OS输入trace或物理键盘证明，实际Cocoa/guest计数及保存结果提供交叉证据。

## 验证范围

14项纯Python测试已在普通／`-O`模式分别通过，证据为 `build/migration-run-v3/unit-01/result.json`。覆盖零/布尔/错误switch计数、无Right、错误存档/重复键、旧v5拒绝、PID/dyld/wrapper、冻结数据、超时仅清理拥有的子句柄，以及独立reader无生产/执行模块依赖。

```sh
python3.13 -B -m unittest migration_run_v3.test_run migration_run_v3.test_review -v
python3.13 -B -O -m unittest migration_run_v3.test_run migration_run_v3.test_review -v
```

这些测试均未启动App，不能替代实际窗口验收。本模块不提供像素等价、性能优势、Finder/LaunchServices、另一台干净机器、真实游戏或一般Windows兼容性结论。所有真实运行成功与失败均由各自的新目录记录。
