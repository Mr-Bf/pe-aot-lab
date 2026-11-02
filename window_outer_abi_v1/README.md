# 完整窗口 ABI 的单次路径诊断

本模块观察真实 Windows PE main → DispatchMessageA → WndProc → import RET。RIGHT-UP 还必须实际进入 DefWindowProcA。它复用已验 v7 产品的提升对象和三个后端对象，重新编译诊断 runtime 与带参数 host，链接四个原生可执行文件：reference／inline lookup × guest O0／O3。运行时统一 O3、无 LTO。

这是无计时、无重放的诊断程序。输入使用明确标记的 `TEST_QUEUE`，不是系统键盘事件或新的无参数生产 App。旧生产代码和原 PE 保持不变；观察器不改写 MSG，也不回滚宿主 session，原生产路径仍正常更新会话。只生成新的源码 overlay，记录同一次真实调用的前后状态。每轮使用独立空 Data，执行 `right,right-up,escape` 后由 guest 保存退出。

当前支持一个固定自产 PE、一个基址和两个选定消息。正常 DispatchMessage 调用点是 RVA5839／R12，RVA6051／RDI 的退出清理路径明确拒绝；首次静态定位错误及两次实际拒绝保留在[实验报告](../docs/WINDOW_OUTER_ABI_V1.md)。不是通用 Windows API、完整预算／ABI 负例矩阵或性能验收。

从仓库根目录运行，`PRODUCT` 必须是同一源码根目录下已经生成且可独立复核的 v7 产品。公开源码仓库不包含私有工具链或实验产品；应先按 [v7安装入口](../migration_install_v3/README.md)产生自己的产品。所有输出都是全新目录，build/run目录必须直接位于 `build/window-outer-abi-v1` 下。

```sh
python3.13 -B -m window_outer_abi_v1 build \
  --product "$PRODUCT" --out build/window-outer-abi-v1/build-new

python3.13 -B -m window_outer_abi_v1 run \
  --build build/window-outer-abi-v1/build-new \
  --out build/window-outer-abi-v1/run-new --timeout 60

python3.13 -B -m window_outer_abi_v1.review \
  --build build/window-outer-abi-v1/build-new \
  --run build/window-outer-abi-v1/run-new \
  --out build/window-outer-abi-v1/review-new.json
```

`build` 不执行 guest／GPU；`run` 将创建实际 Cocoa／Metal 窗口，串行执行四种配置，拒绝与其他项目 App／诊断实例同时运行。超时或启动记录写入失败，只清理自己持有的子进程。拒绝和异常保持原目录，重试换新目录。运行状态只是观测成功，必须再通过独立 reader。

reader 只读文件，不运行编译器、App、GPU或生产 validator。它验证固定源码变换、实际编译与链接输入、原生对象／IR，以及真实 callback 的完整3504B State恢复和5792B Context恢复（steps／switch两个精确计数槽另行核验）。guest映像有独立语义 oracle；映射权限、其他区域、outer RSP及以上栈保持不变；返回 marker／shadow另查。其余 RSP以下临时栈写保留全部原始字节，但没有完整独立逐字节 oracle。没有跨进程全字节等价结论。

```sh
python3.13 -B -m unittest window_outer_abi_v1.test_generate \
  window_outer_abi_v1.test_tools window_outer_abi_v1.test_review -v
python3.13 -B -O -m unittest window_outer_abi_v1.test_generate \
  window_outer_abi_v1.test_tools window_outer_abi_v1.test_review -v
```

源模板缺失、篡改、错误选择器、记录截断及状态污染应明确拒绝。实际轨迹变异检查只修改内存副本，不是执行了新的 guest ABI 负例。完整确定性重放、更多输入／基址、逐预算与终止路径、可信计时和生产优化继续按[分阶段设计](../docs/WINDOW_OUTER_ABI_NEXT_V1.md)推进。
