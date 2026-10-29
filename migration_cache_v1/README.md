# CPU 固定缓存的公开获取入口

`prepare-cpu` 从公开来源获取九个固定输入，输出原有 `portable_lifter_v1` 构建器可以读取的离线缓存。只下载归档或导出固定 Git 提交，不解包、运行下载内容或编译 C++。图形缓存不在本版本范围内。

截至本批开发测试，普通与 `-O` 的测试均为合成响应、模拟 Git 和临时文件；**尚未执行九包真实公网获取**。测试不能证明端点当前可用，也不是完整安装、干净机器、App 或性能验收。

## 使用

在仓库根目录运行，Python 3.13+ 和 `/usr/bin/git` 是外部前提。`--cache` 和 `--out` 必须是不存在、彼此分离、没有符号链接经过的新目录。实际缓存约 424 MB，Git 对象及证据另计。

```sh
PYTHONDONTWRITEBYTECODE=1 /opt/homebrew/bin/python3.13 -B -m migration_cache_v1 prepare-cpu \
  --cache /ABS/NEW_CPU_CACHE \
  --out build/migration-cache-v1/NEW_PUBLIC_ATTEMPT
```

成功状态为 `CPU_PUBLIC_CACHE_READY_NOT_BUILT`。随后的离线 CPU 构建仍使用原入口，需另选新输出目录；此处不自动执行：

```sh
PYTHONDONTWRITEBYTECODE=1 /opt/homebrew/bin/python3.13 -B -m portable_lifter_v1 build \
  --cache /ABS/NEW_CPU_CACHE --prefix /ABS/NEW_CPU_PROVIDER \
  --out build/portable-lifter-v1/NEW_BUILD --jobs 2
```

失败保留 `.partial`、每次下载状态、Git 命令与原始 stdout/stderr、整体 `failure.json`。不覆盖已有文件，不自动重试，不从本机旧 `work/` 复制文件充作公网结果。重新尝试需要新目录；失败现场自行保留。

## 来源与身份

实际下载位置在 `sources.py`，所有 SHA-256 仍以未修改的 `portable_lifter_v1/cache-lock.json` 和既有消费者常量相互核对。新入口不会更新锁文件。

| 输入 | 来源 | 身份校验 |
|---|---|---|
| LLVM 17.0.6 bottle | GHCR `homebrew/core/llvm/17` | 锁定 blob digest；仅选定 ARM64 包 |
| CMake 4.4.4 bottle | GHCR `homebrew/core/cmake` | 锁定 blob digest |
| Ninja 1.13.2 bottle | GHCR `homebrew/core/ninja` | 锁定 blob digest |
| Remill | [lifting-bits/remill 固定提交](https://github.com/lifting-bits/remill/tree/56918a8c2554088e93389e97d292f4035286506c)的 codeload 归档 | 既有原始归档 SHA-256 |
| zstd 1.5.7 | [facebook/zstd v1.5.7](https://github.com/facebook/zstd/tree/v1.5.7)的 codeload 归档 | 既有原始归档 SHA-256；标签变化也不能绕过 hash |
| gflags / glog | `gflags/gflags` / `google/glog` | 固定 commit、tree 及旧 `.tar` SHA-256 |
| XED / mbuild | `intelxed/xed` / `intelxed/mbuild` | 固定 commit、tree 及旧 `.tar` SHA-256 |

前三个包的历史来源和匿名拉取方式位于 `remill_stage2/bootstrap.py:11`、`:39`；该旧脚本没有被执行或修改。[GitHub 官方文档](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)说明公共容器可匿名读取。此实现只请求公开仓库的临时 pull token，不请求用户凭据；token 不写入证据。HTTPS 跨来源重定向移除 Authorization，拒绝降级到 HTTP。下载器不继承环境代理配置。

四个 Git 上游来自固定 Remill 的 [CMakeLists.txt](https://github.com/lifting-bits/remill/blob/56918a8c2554088e93389e97d292f4035286506c/dependencies/CMakeLists.txt) 与 [xed.cmake](https://github.com/lifting-bits/remill/blob/56918a8c2554088e93389e97d292f4035286506c/dependencies/xed.cmake)。取到精确 commit/tree 后，使用历史相同的 `git archive --format=tar --prefix=NAME/ COMMIT`，固定 `tar.umask=0002`，不 checkout 源码，不使用 GitHub tarball 替代旧 `.tar`。Git 版本、导出属性等如果造成不同字节，必须失败；不会放宽原 SHA。[Git 官方文档](https://git-scm.com/docs/git-archive)说明 commit 导出记录提交时间、提交标识及归档属性规则。

Git 子进程使用最小环境、禁用全局/系统 Git 配置、凭据 helper、交互提示及 hooks。每条命令以独占的新进程组执行；300 秒超时或中断时只清理该组，包括 remote helper。单个下载的套接字等待为 30 秒、总体上限为 1,200 秒、最大 1 GiB；不自动续传。失败响应不把带签名参数的重定向 URL 或响应正文写进错误摘要。

## 验证范围

成功前调用原 `tools.check_cache`（四个包）、`deps.sources`（四个 Git 归档），另核对原 `REMILL_ARCHIVE_SHA`（一个包）。`cache.json` 的实际来源与日志是本轮新记录，不拷贝旧机器的 provenance。

```sh
PYTHONDONTWRITEBYTECODE=1 /opt/homebrew/bin/python3.13 -B -m unittest migration_cache_v1.test_prepare
PYTHONDONTWRITEBYTECODE=1 /opt/homebrew/bin/python3.13 -B -O -m unittest migration_cache_v1.test_prepare
```

合成测试覆盖消费者兼容、搬移路径、错误哈希与 Git 身份、中断/超时、大小限制、不覆盖、凭据日志与重定向边界。测试中的 `DOWNLOAD` / `FETCH` 行来自模拟流程，不是网络活动。真实获取后仍需要单独保留消费者搬移/损坏拒绝证据；取得相同缓存不要求再次做无修改的 C++ 重编译。

图形侧仍需独立处理 `origins.json` 的旧路径绑定、LLVM 导出权限/行尾与 Meson 公开来源。这些不通过改变现有图形 lock 或解包语义解决。
