# 同地址窗口 ABI 重放诊断

这个版本在真实 PE main 的正常 DispatchMessageA 边界，针对 RIGHT 与 RIGHT-UP 各执行两次诊断调用，然后恢复原始 guest 边界并执行一次正常 continuation。所有调用仍经过原 dispatcher、WndProc、真实 DefWindowProcA（仅 RIGHT-UP）和 import RET；不改生产源码或替换 API。

两次诊断只在执行前固定 MSG.time／pt 的12B（偏移32…43）：time为0x12345678，坐标为100／200，对应字节7856341264000000c8000000。原始输入另存，continuation恢复完整原始 State、Context和guest backing到同一地址；权限表严格要求未变，保持原地址而不写入可能只读的权限表。D3D／File／User32／callback宿主会话不回滚，真实统计持续累加。每轮Context的steps／switch增量与外部累计账本分别验。

这是无计时、固定样例和首选基址的正常路径诊断。两次同进程诊断的完整guest输出可逐字节核对；不宣称跨进程全字节等价，也不以重放相等代替独立语义oracle。其余RSP以下栈写仍没有完整独立语义oracle。完整预算、ABI破坏、默认API拒绝、ExitProcess与其他终止路径属于后续矩阵。

从仓库根目录执行，PRODUCT必须是同一源码根目录下已生成且可独立复核的v7产品。公开仓库不包含本机产品或工具链，可先按[安装入口](../migration_install_v3/README.md)生成自己的产品。输出必须使用全新目录，build/run只能直接位于build/window-outer-replay-v1下。

```sh
python3.13 -B -m window_outer_replay_v1 build \
  --product "$PRODUCT" --out build/window-outer-replay-v1/build-new
python3.13 -B -m window_outer_replay_v1 run \
  --build build/window-outer-replay-v1/build-new \
  --out build/window-outer-replay-v1/run-new --timeout 60
python3.13 -B -m window_outer_replay_v1.review \
  --build build/window-outer-replay-v1/build-new \
  --run build/window-outer-replay-v1/run-new \
  --out build/window-outer-replay-v1/review-new.json
```

构建显式复用已验提升main／WndProc／RET与后端对象，只新编带参数host及重放runtime，生成reference／inline × guest O0／O3四个原生程序。run会串行创建实际Cocoa／Metal窗口，使用TEST_QUEUE输入right,right-up,escape；每进程独立空Data，最终真实保存退出。这不属于新的生产App或系统键盘验证。任何异常保持失败目录，不能清除fault或exit latch后继续重放。

独立reader只读记录，不执行native或producer验证器。检查真实编译来源、原始边界、12B输入白名单、同地址恢复、两诊断轮完整guest输入／输出一致、原输入continuation及宿主累计账本。成功runner回执不是独立验收结论。

FileSession、next_handle和files_ready的完整不变关系由C运行时内部检查；reader独立核验的文件证据为已导出的LastError、9项API计数及读写字节数。它不构成完整文件TLS或内核文件描述符状态的独立快照证明。

```sh
python3.13 -B -m unittest window_outer_replay_v1.test_generate \
  window_outer_replay_v1.test_tools window_outer_replay_v1.test_review -v
python3.13 -B -O -m unittest window_outer_replay_v1.test_generate \
  window_outer_replay_v1.test_tools window_outer_replay_v1.test_review -v
```

实际构建、执行、失败和复核状态在本轮实验报告中单独记录；命令实现与设计范围不等于所有矩阵已验。
