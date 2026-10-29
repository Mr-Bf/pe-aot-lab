# v6 离线安装与失败恢复

本入口从两份固定缓存串联 `CPU base → switch overlay → graphics → v6 App → verify`。沿用 schema2／`win32-d3d11-tile-switch-v1` 的受限窗口契约，不扩大 PE、Windows API 或图形兼容范围。安装器只构建和静态验证；实际 App 交互由独立运行监督验收。

## 新安装

需要 Apple Silicon macOS、Python 3.13、包含 Metal 工具的所选 Xcode/SDK，以及已核对的 CPU/图形离线缓存。缓存准备仍使用根 README 的固定版本入口。work-root 与 out 必须不存在、彼此及缓存分离；work-root 放置工具链和产品，out 放置本次协调/构建证据。

```sh
python3.13 -B -m migration_install_v2 plan \
  --cpu-cache "$CPU_CACHE" --graphics-cache "$GRAPHICS_CACHE" \
  --pe examples/window-switch/switch_tile.exe \
  --profile examples/window-switch/profile.json \
  --identifier org.peaotlab.install.switch.example.v1 \
  --work-root "$PWD/.local/install-v2-01" \
  --out "$PWD/.evidence/install-v2-01" --jobs 2
```

`plan` 只读核对输入、缓存、Apple 工具/SDK、空间及实现身份；不会创建上述输出或证明指令可翻译。检查结果后，以相同参数把 `plan` 改为 `install` 执行。jobs限制1..2；磁盘预算是保守预留，不是实测峰值保证，失败尝试会继续占用空间。

完整成功状态为 `OFFLINE_V6_APP_BUILT_VERIFIED_NOT_EXECUTED`；实际产品路径取最终结果的 `product`/`app`。CPU base、overlay 和 graphics 使用不同角色及收据验证，不能互相替换。overlay依赖base的原绝对路径，成功阶段不可重命名或单独搬移；生成的App另有搬移运行验收。

## 恢复

```sh
python3.13 -B -m migration_install_v2 resume \
  --installation "$PWD/.evidence/install-v2-01" \
  --out "$PWD/.evidence/install-v2-resume-01"
```

每次恢复使用新的out，首次installation保存不可覆盖的plan、输入、源码与会话索引。成功阶段须重新验证实际provider/source/receipt、父角色关联、规范化profile字节及完整App文件；状态索引和 `accepted.json` 只是候选定位信息。未正式接受的旧attempt保留，重试分配新序号prefix与builder目录，原失败记录不会覆盖。

输入原字节、原始profile文本、冻结后的canonical profile字节、缓存、SDK/工具或实际构建实现变更会拒绝复用。此恢复合同要求使用同一安装位置与实现；跨版本升级或任意目录迁移应建立新安装。

协调器取得安装级排他锁，各stage worker创建独立session/PGID并继承同一锁FD，先原子持久注册身份再调用builder。父协调器退出只关闭自身FD；worker仍活时锁继续存在。恢复还必须实际观察历史进程组消失；活进程、权限不足、缺失/替换锁inode或不明未注册产物均拒绝重试。当前合同不支持会daemonize或逃离所属组的builder。

这依赖 [Apple flock语义](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/flock.2.html)以及 [Python subprocess 的session/FD传递接口](https://docs.python.org/3.13/library/subprocess.html)。恢复不根据一个超时或状态文件推断子进程已结束。

## 独立读验与运行

```sh
python3.13 -B -m migration_install_v2.review \
  --installation "$PWD/.evidence/install-v2-01" \
  --session "$PWD/.evidence/install-v2-resume-01" \
  --out "$PWD/.evidence/install-v2-review-01.json"
```

reader从各原始receipt和文件重新核对角色、源码/patch重放、产物/ABI/IR/proof/header、阶段失败与复用，不启动builder或App。普通模式及 `-O` 应分别使用新输出路径。随后使用 `migration_run_v3` 对这次实际生成的v6产品做独立App启动、真实Cocoa输入和存档恢复；旧App的正常运行不能代替新产品验收。

## 开发与故障实验

```sh
python3.13 -B -m unittest migration_install_v2.test_install migration_install_v2.test_review
```

安装器27项测试主要使用合成stage，仅继承锁测试启动受控短Python子进程；它们不是完整native安装。独立reader反例另列测试数量。旧v1入口保持原合同，使用其单独测试验回归。

`recovery_probe` 是显式集成实验：只为自己新建的安装，在核对实际worker/PGID/父子关系/job/prefix及编译命令后向图形构建组发SIGTERM；保留失败，恢复作为单独命令执行。若观察器失去权限或终止，先核对实际现有进程；`recovery_attach` 可接管已登记实验，不新建安装。此类观察需要OS允许查询进程列表；不能把观察失败算成builder终止。实际原始失败和接管记录须分开保存。

当前实现与本机实际验收状态见 [验收记录](../docs/MIGRATION_INSTALL_V2.md)；单一M2环境、本项目自产PE和既定图形合同不代表干净机器、真实游戏或性能优势。
