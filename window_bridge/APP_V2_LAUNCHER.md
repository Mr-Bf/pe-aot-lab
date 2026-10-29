# App v2：两进程保存／恢复监督器

`window_app_launch_v2.py` 已实现，普通与 Python `-O` 语法检查通过。默认只读验收，只有显式 `--run` 才启动程序。本文件记录的是监督器准备状态；截至该准备检查，没有新增 App、来宾或 GPU 执行。

## 固定执行合同

监督器先验证 `app_v2` 的静态包及新保存／恢复 PE 身份，将整个签名 App 复制到 `/private/tmp/pe-aot-save-load-v2-*/relocation with spaces/PE AOT Integer Tile V2.app`。原程序及全部三个非系统库均由包内路径解析。每轮前后读取完整包文件的字节和模式，并比较原程序／库的所有 Mach-O section 身份；签名检查不加载 App 代码。

两次启动使用同一 App 副本、同一新建 `data` 目录、同一组八个 `TEST_QUEUE` 事件，环境 `PATH=/nonexistent`。每次预算为 1,000,000 步、宿主超时 45 秒，外部监督在 60 秒到期时终止自己的子进程，必要时在 3 秒后强制结束，再等待最多 3 秒收集输出。超时永远不计为成功退出。

第一次执行前数据目录必须为空；第二次执行前原磁盘文件必须逐字节等于第一次的实际存档。监督器仅将历史字节复制到独立 `phase-*` 证据目录，从不写回共享存档，也不向来宾内存注入恢复状态。第二次只在第一次完整身份、原始输出和语义检查通过后启动。

## 验收与留档

- 每个 phase 的 `run.started.json`、原始 stdout／stderr、`before.json`、历史存档和 `run.json` 都独立创建，不覆盖旧文件。因此不需要模拟旧程序生产端覆盖记录时使用的 `history` 目录。
- 实际子进程 PID 必须与 dyld 公告 PID 一致；解析后的累计映像身份必须准确对应搬移后的程序及三个包内非系统库。
- 先由冻结新 `Program.validate_execution()` 核对字段、入口、PE、AOT 状态与清理合同，再调用 `save_load_acceptance_v1.semantic_acceptance(record, before_bytes, after_bytes)`。后者核对真实 ReadFile、EOF、20 字节格式、候选数据、移动／重复键、累计帧数、LastError 0／183、八个来宾对象释放和窗口退出。
- 第二轮历史输入必须等于首轮历史输出，最终活文件必须等于第二轮输出；两条记录必须来自不同 PID。固定工作负载应从位置 3／移动 0 经 4／3 到 5／6，绘制次数允许实际 paint 变化。
- `observed.json` 先保存完整观察，再执行全链只读 `verify()`；全部通过才写 `PASS_RELOCATED_APP_TWO_PROCESS_SAVE_RESTORE`。失败保存原始流、阶段状态和已产生文件的哈希，不修改既有成功记录。

完整性检查绑定实际源文件、工具、头文件、提升物、原程序、包文件和记录。它用于拒绝过期证据／版本混用，不是对抗恶意本地并发修改或伪造证据作者的安全沙箱。

## 准备检查与命令

`build/window-bridge/app-v2-launcher-review/` 保存普通与 `-O` 各 14 项纯组件检查：普通文件／上限、符号链接、FIFO 不阻塞拒绝、目录拒绝、空数据目录、真实文件只读、额外文件拒绝、输出路径限制、缺失证据的默认只读路径不启动子进程或创建输出，以及固定环境／事件／缺失快照元数据。完整只读验收允许调用验签、Mach-O 检查等工具，不运行 App。这些不是实际 PE 执行测试，不增加来宾运行计数。

实际启动命令由主任务在独立监督下执行：

```sh
/opt/homebrew/bin/python3.13 -m window_bridge.window_app_launch_v2 \
  --out build/window-bridge/window-run-app-v2-roundtrip-01 --run
```

完成后只读复核同一记录：

```sh
/opt/homebrew/bin/python3.13 -m window_bridge.window_app_launch_v2 \
  --out build/window-bridge/window-run-app-v2-roundtrip-01
/opt/homebrew/bin/python3.13 -O -m window_bridge.window_app_launch_v2 \
  --out build/window-bridge/window-run-app-v2-roundtrip-01
```

输出目录必须全新，禁止覆盖历史证据。当前只支持显式 CLI 参数直接启动；不增加 Finder／LaunchServices、真实键盘、像素或性能结论。Python 是外部监督／验收工具，不属于包内运行依赖。
