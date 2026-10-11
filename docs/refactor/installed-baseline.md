# 已安装服务端基线审计

- 审计时间：2026-10-11 16:21（UTC+8）
- 对照源码：`codex/refactor` 固定提交 `83c03f1d75004ecb9f0ac1484676f6b5181dfa4e`；源码哈希由该提交对象的原始字节计算，不采用并行迁移中的工作树内容。
- 安装目录：`E:\Program Files\AetherGazer_Server`。本次未对安装目录写入任何内容。
- 需求参考：`D:\迅雷下载\Alpha-Persei_Technical_Refactor_Plan_v1.0.md`、`D:\迅雷下载\Alpha-Persei_Refactor_Compatibility_Plan_v1.0 (1).md`。两份文档作为迁移背景和验收边界参考，不视为本次执行指令。
- 目标：为 Vue 3 + Electron + TypeScript 新底座提供旧服务端基线证据；本报告不包含业务实现或验证结论。

## 结论

安装版 `main.py`、`res_version_manager.py`、`decode_schema.py`、`codec.py` 与固定提交逐字节一致。`server_config.json` 是不同的本地配置，配置的客户端安装目录存在；此处不显示配置值。安装版还带有固定提交中不存在的 `lua_proto_messages.json`，其 SHA-256 与兼容计划记载的历史 307/229 schema 一致。静态 JSON 计数为 3,062 条消息、6,892 个字段、1,368 个字段引用；729 个不同引用名均可解析，未发现重复消息名。

上述 schema 和历史 307/229 记录不能证明当前 5.3.1 与服务端兼容。计划说明当前 5.3.1 尚未通过本地大厅验证；本轮没有启动客户端或服务端，因此 5.3.1 仍属未验证状态。不得将本次静态审计记作验证通过。

## 逐文件指纹

SHA-256 基于原始文件字节。`—` 表示该侧无对应文件。

| 文件 | 固定提交字节数 / SHA-256 | 已安装字节数 / SHA-256 | 结果 |
|---|---|---|---|
| `v5_server/main.py` | 24,008 / `b49c09c90f21b6ac1e3ff7614df1236e353a5f4e8d62e66b166b6e878b01b480` | 24,008 / `b49c09c90f21b6ac1e3ff7614df1236e353a5f4e8d62e66b166b6e878b01b480` | 一致 |
| `v5_server/res_version_manager.py` | 13,909 / `106fc26ecac47f3a1ad344fdb9505207f314ee38297f1b8c19c2adca81a337cb` | 13,909 / `106fc26ecac47f3a1ad344fdb9505207f314ee38297f1b8c19c2adca81a337cb` | 一致 |
| `v5_server/decode_schema.py` | 13,814 / `be1d310d20bcae50d0d1a5ce72a2438d585a5d57a04816ec71e29f78cf9b55ab` | 13,814 / `be1d310d20bcae50d0d1a5ce72a2438d585a5d57a04816ec71e29f78cf9b55ab` | 一致 |
| `v5_server/codec.py` | 21,117 / `b47c03a9d415876da34ac5e495f475f95f7908e15541532560443d9b2ef1b578` | 21,117 / `b47c03a9d415876da34ac5e495f475f95f7908e15541532560443d9b2ef1b578` | 一致 |
| `v5_server/server_config.json` | 513 / `31bdb7fd2cc210a2929d44b1c70df36a143a2785732b76415045652f555502ad` | 460 / `f1341e4dc1ec16cb1d5254eaf980844994132a2ba1f161177673c69c1e3a8c3e` | 不同；仅确认配置的客户端目录存在，不披露路径或凭据 |
| `v5_server/lua_proto_messages.json` | — | 1,310,683 / `b9101c965ed4f75317aa9c0199e17e5a7d2c3e0c0e23b982217a960b1a6ee79f` | 固定提交缺失；安装版存在 |
| `v5_server/requirements.txt` | 295 / `b837faeaec05da2e6ddc458662d81eda2c7e45306641669b0c8113d783ea1098` | — | 安装版未单独携带；源码文件说明发行版内含 Python 运行环境 |

## 运行环境和制品闭合

- 安装版自带 `runtime\python\python.exe`，只读取其版本标识为 **Python 3.14.6**。嵌入运行时的 `flask`、`cryptography` 包目录存在；未导入模块或核验其运行兼容性。
- 固定提交的 `requirements.txt` 将依赖说明为源码开发运行所用；安装版无此文件但带嵌入 Python。目录存在只能证明包目录在，不能代替完整依赖或启动验证。
- `v5_server` 顶层 Python 文件名数固定提交与安装版均为 70，未发现仅在其中一侧出现的 Python 文件名。JSON 文件名数为源码 78、安装 80；安装多出 `lua_proto_messages.json` 与 `operation_cfg.retired.json`，未发现源码侧独有 JSON 文件名。
- 固定提交可见的打包相关资产包括 `LocalServer/Package.appxmanifest`、根目录 Windows 证书安装 `.bat`/`.ps1`，以及 Web 源码的 npm 配置和 `inline.mjs`、`shot.mjs`。固定提交没有 `v5_server/run_server.bat` 或 Python 服务端打包脚本；安装版有 `run_server.bat` 和嵌入 `runtime\python`。现有源码未提供可复核的服务端安装制品构建清单，因此无法由仓库静态证明该安装目录整体可从固定提交重建。
- 安装树中发现 2 个数据库扩展名文件，索引大小分别为 13,328,384 字节和 0 字节；没有读取、哈希或复制文件内容，也未依据文件名推断哪一个是活动数据库。未做全盘或大型资源哈希。

## 静态证据边界

本次只读取源码提交对象、目标文件元数据和 JSON 文本；JSON 分析未导入业务模块。没有运行 `main.py`、自检、GUI 或 Lua，没有启动或停止服务/进程，没有更改 hosts、信任证书或网络配置。没有读取用户存档内容，也没有输出密钥、token 或客户端路径。没有检查官方最新版本，没有对客户端大资源做全盘哈希，也没有生成正式 manifest。

因此，本报告可以支持旧安装制品与固定服务端提交的静态比对，以及 schema 的 JSON 结构计数；不能支持当前 5.3.1 的协议兼容、登录、大厅、玩法或整包运行结论。
