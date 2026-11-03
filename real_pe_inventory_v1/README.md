# 真实 Windows x64 PE 静态库存

本工具只读取可信 AMD64 PE32+ 文件，输出可核对的结构事实与未解析清单。它不执行 PE、不调用生产 loader/lifter、不解包下载、不扫描指令，也不判断程序可迁移或性能达标。旧转换 profile 的有限 API 表不用于这里的兼容判断。

从项目根目录运行；输入可以是单文件，或递归扫描 `.exe`／`.dll` 的目录。输出必须是新文件，父目录已存在，且不在被扫描的目录内：

```sh
python3.13 -B -m real_pe_inventory_v1 /absolute/path/to/release \
  --json-out /absolute/path/to/new-results/inventory.json \
  --markdown-out /absolute/path/to/new-results/inventory.md
python3.13 -B -m unittest real_pe_inventory_v1.test_inventory -v
python3.13 -B -O -m unittest real_pe_inventory_v1.test_inventory -v
```

没有 `--json-out` 时，JSON 写到 stdout。退出0仅表示本工具实现的元数据均已解析；退出2表示 `INCOMPLETE`、拒绝输入或输出错误。真实程序通常包含本工具尚未解释的资源、unwind、load-config 等内容，因此生成有用库存后仍会返回2。两者都不代表可执行或可迁移。局部目录解析失败会保留文件头和其他可读目录，明确记录 `invalid`，文件及总体状态为 `INCOMPLETE`；文件头损坏则该文件为 `REJECTED`，目录库存继续其他文件。

JSON schema 为1。路径按输入目录相对路径排序，不写入运行时间，内容相同且分析器相同的输入可生成稳定JSON。报告还包含分析器源码摘要。主要字段：

| 字段 | 含义 |
|---|---|
| `files[].path/sha256/bytes/status` | 相对文件名、实际读取字节身份与库存状态 |
| `headers`、`sections` | PE/COFF和optional header；节的虚拟/原始范围与R/W/X声明 |
| `directories[]` | 全部声明目录以及标准16项缺席记录；address、size、address_kind、presence、parse_status |
| `imports[]` | normal/delay DLL描述符；符号名或ordinal、hint、IAT RVA；未解码表显式保留原因 |
| `directories[].detail` | 该类已读取的原始结构、头字段、记录或未解释项 |
| `findings[]` | error、analysis_gap或observed_requirement，不是运行失败预测 |
| `dependency_edges[]` | DLL basename候选，唯一/歧义/未在库存发现；Windows loader解析未执行 |

目录状态为 `not_declared`、`parsed`、`partial`、`unparsed` 或 `invalid`。`not_declared` **不证明**动态DLL加载、动态TLS、异常注册、JIT、线程、图形或其他机制不存在。DLL系统名/API-set分类只是名称提示，不证明系统实际提供它；`not_in_inventory`不称为“缺DLL”。同basename的文件也只是候选，不模拟Windows搜索顺序、转发导出或API-set解析。

最小结构示例（省略号表示省略字段，不是完整输出）：

```json
{
  "schema": 1,
  "tool": "real-pe-inventory-v1",
  "status": "INCOMPLETE",
  "guest_executions": 0,
  "files": [{
    "path": "example.exe",
    "status": "INCOMPLETE",
    "metadata_complete": false,
    "directories": [{"index": 3, "name": "exception", "address_kind": "rva", "parse_status": "partial"}],
    "imports": [{"dll": "SDL2.dll", "kind": "normal", "status": "parsed", "symbols": [{"name": "SDL_Init", "ordinal": null, "hint": 0, "iat_rva": 8192}]}]
  }],
  "dependency_edges": [{"source": "example.exe", "dll": "SDL2.dll", "import_kind": "normal", "candidates": [], "match_status": "not_in_inventory", "loader_resolution": "not_performed", "missing_dependency_claim": false}]
}
```

当前解析范围及限制：

- 正常import和RVA格式delay import读取描述符、名字/ordinal和thunk；bound IAT缺失原lookup、未知delay属性及旧VA delay thunk编码不猜测。delay的module handle、bound/unload IAT先验映像范围；后两张表的内容仍标记未解析。
- relocation记录块与类型；AMD64 DIR64目标检查映像范围，其他类型保留原始值并标记未解释。HIGHADJ配对字保留，不能误当成第二次重定位。
- exception读取RUNTIME_FUNCTION范围、UNWIND_INFO头和原始code槽；unwind操作语义、语言专用handler数据、chained unwind和新版本均不完整解析，不能视为完整SEH/C++异常支持。真实文件出现的零长度范围保留原值并标 `empty_range_unparsed`，不计作已验证代码范围；反向范围拒绝。
- TLS读取VA字段、静态模板范围和callbacks；VA先减ImageBase并验范围。允许index位于已映射BSS，不把virtual-only内存当作文件字节；TEB、初始化顺序及动态TLS没有分析。
- load-config只读取已覆盖的前缀字段，包括cookie、SEH/CFG/EH continuation相关声明；版本专用表和扩展尾部明确未解析。
- security目录地址按**文件偏移**读取WIN_CERTIFICATE记录，检查边界及对齐；不验签、不判断发行者可信度。debug读取目录与RSDS CodeView元数据，绝不跟随PDB路径。
- exports、resources、IAT目录本体、bound imports、CLR及其他目录目前只记录存在性和存储边界，payload标记未解析。

格式参考：[Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)。范围检查拒绝截断、重叠映射、整数越界、缺失终止项和超出限额；这是可信输入的工程库存工具，不宣称完成恶意PE安全审计。输入限额为每文件256 MiB、合计1 GiB、1024个候选、每PE 262144个元数据条目、4 MiB累计名称字节及64 MiB不透明debug/certificate payload，整个目录最多1048576个元数据条目与32 MiB名称字节。预算在批量解析／复制之前检查，范围检查本身不复制整个目录。符号字符串最长4096B；符号链接和非普通文件拒绝。没有把任何目录缺席转化成运行机制不存在的结论。
