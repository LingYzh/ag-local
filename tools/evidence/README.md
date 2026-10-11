# 离线协议证据工具

`current_schema_match.py` 有界加载显式 schema，检查 protobuf wire 结构、字段和 required 存在性。`analyze_official_startup.py` 离线读取 PCAPNG，识别已映射的协议前缀，重组目标 TCP 流并输出白名单摘要。两者使用 Python 标准库，不连接服务器或导入游戏业务入口。

从仓库根目录使用 [已核验的独立 Python 环境](../python/README.md)，明确提供本地输入和预期哈希。下例中的路径是变量，按实际材料填写；输出目录必须尚不存在：

```powershell
$pythonExe = Join-Path (Get-Location).Path 'qa/python-environment-local/venv/Scripts/python.exe'
$capturePath = '<本地 PCAPNG 绝对路径>'
$captureSha256 = '<PCAPNG 的 64 位 SHA-256>'
$schemaPath = 'v5_server/artifacts/app307-resource321-static/schema.json'
$schemaSha256 = '917010c2bc0cf4e4bfb21dfdf66c77128cff61d9a47c848a30f0a1c1d4a842b0'
& $pythonExe -I -B tools/evidence/analyze_official_startup.py --input $capturePath --input-sha256 $captureSha256 --schema $schemaPath --schema-sha256 $schemaSha256 --output-dir qa/capture-analysis-new
if ($LASTEXITCODE -ne 0) { throw 'Capture evidence is rejected or incomplete; inspect the report if produced.' }
```

输入不匹配或参数错误时不开始分析。完整的目标协议前缀验证通过返回 0；分析已执行但证据不完整返回 2，并保存拒绝原因。输出不会覆盖旧目录，拒绝含 symlink / junction 的输出路径。输入、schema 和实际工具源码在分析前后校验；报告绑定运行时、锁文件、关键安装包 metadata 版本和三份实际执行源码哈希。分析命令不执行依赖安装校验；完整环境校验由 H02 的脚本和环境测试单独完成。

## 方法与限额

- PCAPNG 文件上限 512 MiB，单块上限 16 MiB；interface ID 按 section 隔离。
- 最多登记 100,000 条 TCP 流。协议识别只检查每方向最多 8 段、每段 64 字节、连续前缀最多 512 字节；不把所有未知 TCP 流解释为游戏消息。
- 单目标流重组上限 32 MiB，聚合上限 64 MiB。已识别的目标候选因预算未重组、目标流冲突、缺口、截断、碎片或残帧都阻断通过。
- 跨接口重复包仅在限定时间窗、相同流方向、序号、确认号、flags、载荷长度及 digest 下去重；同接口重传由 TCP 重组检查。帧级去重计数与多采集视角原始计数分开。
- 下行 flag 0 使用原始 body，flag 1 要求有界完整 zlib 解压，未知 flag 不选择 schema 输入。上行使用原始 body；zlib 头特征只提供诊断，不能选择解压结果。
- protobuf、字段数、递归深度、解压大小与比例均有上限，精确值写入每次报告。匹配只说明消息结构，不证明字段业务语义。

`passed` / `complete` 只针对已选择的目标协议观测前缀及其解析所需的文件完整性，不表示整份抓包、所有服务或长连接生命周期均已完整。辅助 HTTP 的重组问题单独登记；TLS 只计数，不解密。目标流证据不完整时，原始匹配计数可以保留作诊断，`trusted_wire_match_events` 必须为 0。

## 隐私与测试

`analysis.json` 只输出计数、状态、哈希、方法、限额及拒绝原因，不输出 IP、域名、HTTP 正文、协议字段值、原始包或输入绝对路径。原始 PCAP、密钥、存档和未经审查的运行日志继续留本地；不要取消 `qa/` 的忽略规则。公开真实样本摘要见 [P0 验证记录](../../docs/refactor/p0-validation.md)。

合成输入从零构造，测试位于 `tests/evidence/`。单独运行证据组，或省略 `--group` 完成全部 Python 套件：

```powershell
& $pythonExe -I -B tools/validation/run_python_tests.py --group evidence --output qa/evidence-tests-new.json
```

子集验证报告列出未执行组。合成测试不替代真实 PCAP 复跑，抓包复跑也不替代真实客户端大厅验收。
