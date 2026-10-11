# 当前客户端静态协议恢复

恢复入口为 `v5_server/tools/static_protocol/cli.py`。它读取固定 SHA-256 的 scripts 制品，静态解析 UnityFS、SerializedFile、TextAsset 和 LuaJIT 声明字节码；不会启动游戏、监听端口或执行 Lua，也不导入旧服务入口。用户提供的方法和脚本归档用于核对格式，归档中的脚本没有直接执行。

在仓库根目录运行，参数全部使用绝对路径。输出目录必须尚不存在，父目录已经存在，且位于受保护客户端根目录之外。命令拒绝路径中的符号链接或 reparse point，不覆盖已有结果。

```powershell
& 'E:\Program Files\AetherGazer_Server\runtime\python\python.exe' -B -m v5_server.tools.static_protocol.cli `
    --source-root 'D:\AetherGazerStarter\AetherGazer' `
    --bundle 'D:\AetherGazerStarter\AetherGazer\AetherGazer_Data\StreamingAssets\Windows\f\9\f9468cd00564c3c98e4f819210760be1.ys' `
    --sha256 'd39fcc02eb38d4966d3732d9008d75cb41913194942a4800ad5a7585104a0019' `
    --output-directory '<客户端根目录之外的新绝对目录>'
```

解析全部成功之后，一次发布三个文件：`schema.json`、`schema.sha256`、`extraction-report.json`。schema 保留每条消息和字段的默认值、原始 descriptor 属性、完整命名空间、引用目标与源定位；报告记录输入及协议资产 SHA-256、工具源文件 SHA-256、运行时版本、限额与实际用量。所有输出使用固定排序和 UTF-8 JSON；不写入生成时间、客户端绝对路径或原始字节码。重复生成结果可以逐文件比较。

提取限额包括输入 128 MiB、metadata 1 MiB、压缩加解压累计 512 MiB、LZMA dictionary 64 MiB、压缩比 64。当前样本需要解压一个约 476 MiB 的 block，检查预算后才分配；运行时须留出额外内存。UnityPy 只提供 Unity 的公共字符串表，不调用其完整 bundle 加载器再次解压。未知容器布局、指令、外部引用、未归属声明或预算超限都会明确失败。

字段与消息声明要求分别归属、导出一次。生成器的构造查表辅助对象另作数据流核验：非空查表键须实际读取，其 FieldDescriptor 必须恰好被一个消息消费；完全空且未曾写入或读取的辅助表单独记录为未使用的空构造对象。辅助表不会增加 schema 消息或生成兼容别名，未知对象也不会因此得到豁免。

当前声明中的 1,608 个重复字段默认值是源代码中的纯空 Lua table。IR 用 `{ "kind": "lua_table", "entries": [] }` 保留这个原始字面量，并记录创建偏移和空写入/读取历史；它不等于已经认定的业务默认列表。原始 `has_default_value` 保持不变。非空、曾写入后擦除、外来或非重复字段的 table 默认值均拒绝。

## 当前结果

固定的当前 scripts 制品已实际运行两次 CLI，三个输出文件逐字节一致。候选位于 `v5_server/artifacts/app307-resource321-static/`：

| 产物 / 核验 | 结果 |
| --- | --- |
| schema.json | 26,504,729 字节；SHA-256 `917010c2bc0cf4e4bfb21dfdf66c77128cff61d9a47c848a30f0a1c1d4a842b0`。 |
| extraction-report.json | 7,815,768 字节；SHA-256 `885dd172e020c039f65d73a0ea3733e7aff87a9c02800e34cd071b83a5fec895`。 |
| 声明闭包 | 92 个协议资产、3,061 条消息、6,889 个字段、1,368 个消息引用全部解析。 |
| 构造辅助对象 | 92 个容器、2,955 个非空字段查表、106 个未使用的空查表；6,889 个字段 alias 分别对应已归属声明。 |
| 桌面互操作 | 真实 `loadSchemaRegistry` 加载通过，消息/字段/引用数一致，所有消息为限定名，无额外 bare alias。 |
| 历史对照 | 92 个协议资产的 namespace 集合与逐项 SHA-256 全部与用户提供的历史 extraction-validation 相同；当前整个 scripts bundle SHA 与历史不同，不能把局部结果外推。 |
| 自动化边界 | 静态协议测试 44 项通过；实际解压 charged-I/O 534,959,458 / 536,870,912 字节。 |

这些产物只证明静态声明恢复。`runtime_test_performed` 和 `compatibility_admitted` 均为 false；不可把它们当成完整运行 bundle 或大厅通过记录。桌面注册表当前消费核心字段结构与引用闭包，完整来源和默认值仍保存在 schema 文件中。

测试入口：

```powershell
& 'E:\Program Files\AetherGazer_Server\runtime\python\python.exe' -B -m unittest discover -s tests/static_protocol -v
```

测试使用小型字节码和容器夹具验证边界、确定性、引用、声明归属与明确拒绝；真实客户端提取和抓包匹配另外留存结果。后续大厅契约见 [hall-contract.md](hall-contract.md)。
