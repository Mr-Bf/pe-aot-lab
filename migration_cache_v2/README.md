# CPU 缓存 v2：有界 Range 与显式失败续传

第一次真实公开获取在 LLVM bottle 下载阶段遇到提前 EOF：保留 356,515,840 字节 `.partial`，没有通过完整 SHA-256，也没有发布成功缓存。v1 实现、测试与失败现场保持冻结。

v2 为 GHCR 的 LLVM/CMake/Ninja 三个 bottle 增加 16 MiB 分段请求。两个小 codeload 包、四个 Git 提交获取和最终九包消费者验证仍复用 v1。没有 C++ 编译或 App 改动。

截至本版本纯边界测试，**尚未执行 v2 真实网络续传**。测试里的 RANGE 行来自合成字节，不能算公网结果。

## 执行入口

输出必须为彼此分离的新目录，与旧缓存和旧证据也必须分离。新获取可以省略 `--resume-from`；显式恢复目前只支持 v1 第一包 LLVM 下载失败。

```sh
PYTHONDONTWRITEBYTECODE=1 /opt/homebrew/bin/python3.13 -B -m migration_cache_v2 prepare-cpu \
  --cache /ABS/NEW_CPU_CACHE \
  --out /ABS/NEW_ACQUISITION_EVIDENCE \
  --resume-from /ABS/FAILED_V1_ACQUISITION_EVIDENCE
```

`--resume-from` 接收失败证据目录，不能直接传一个旧 `.partial`。程序核对旧总 started/failure、LLVM started/failure、完整 acquisition plan、v1 实现快照及原始 partial 的绝对路径、长度和 SHA。仅接受旧缓存内只有该失败前缀的情况，拒绝把其他旧缓存混入本轮。

绑定后复制前缀到新缓存，复制前后复查旧文件身份，并保存 `resume-copy.json`。原文件保持不变；这次结果若成功，必须明确记录旧公开下载前缀的复用，不能叫作重新下载了完整九包。

## 分段规则与证据

每段均要求 HTTP 206、精确连续的 Content-Range 起止位置、正数总长度以及后续不变的总长度。总长度最多 1 GiB，Content-Length 必须等于段长度，拒绝内容编码。最后一段按 total 截短。服务器忽略 Range、返回未知 total、错误范围或不支持 Range 时明确失败，不自动降级全量下载，不更换包或 hash。

单段完整数据先在最多 16 MiB 的缓冲区中验证，再追加到新 `.partial`。短包、额外字节或中断不把该段加入已接受前缀。只有全部字节完成且原 lock 的完整 SHA-256 一致，才调用 v1 的不覆盖发布。旧 partial 的 hash 只证明复制了已记录前缀，不代替最终完整包验证。

每段保存 requested range、响应 status 和 Content-Range/Length/Encoding、追加数据 SHA 与长度、成功或失败。响应头每字段最多记录 1,024 字符，超长标记并拒绝。匿名 token、其他响应头及带签名参数的重定向 URL 不写日志。旧 v1 的 HTTPS 重定向规则、Git 独占进程组清理和下载总体时间上限继续适用。

```sh
PYTHONDONTWRITEBYTECODE=1 /opt/homebrew/bin/python3.13 -B -m unittest migration_cache_v2.test_prepare migration_cache_v2.test_review
PYTHONDONTWRITEBYTECODE=1 /opt/homebrew/bin/python3.13 -B -O -m unittest migration_cache_v2.test_prepare migration_cache_v2.test_review
```

此版本是有界网络恢复能力。图形缓存、自助完整安装、另一台干净机器复现、应用性能均不由这些测试证明。现有 provider/App 无需因为此网络层改动重新编译。
