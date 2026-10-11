# P0 执行与验证记录

执行日期：2026-10-11（UTC+8）。审查及回归基线：`7aea8f08f82b2853156ced43db9831f561e0caf0`。本轮仅实施 [大厅推进计划](../plan/AG-Local_531_Hall_Execution_Plan_v1.0.md) 的 H01、H02、H03；G0 / G1 仍未通过。

**P0 H01—H03 已完成验收并提交推送。** 初次交付为 `e7f7077`，CI 路径断言修正为 `0129d88`；[该修正提交的实际 GitHub Actions](https://github.com/LingYzh/ag-local/actions/runs/38146368259) 全部通过。后续记录提交只补充验证材料，不扩大业务范围。

## H01：实例故障保持

TS 监督器现在保存实例首次故障。关闭已确认但退出超时后，迟到的退出事件仅释放该实例所有权，保留 `FAILED / WORKER_EXIT_TIMEOUT`；重复关闭仍返回原故障。显式启动新实例后才重置状态，旧回调不能覆盖新实例。原有及时确认并正常退出仍得到 STOPPED，未增加按 PID、进程名或端口结束进程的路径。

在独立 checkout 中先加入新增测试、保留基线监督器，12 项生命周期测试中 3 项失败；应用修复后，类型检查通过，完整 Vitest 55 项运行、54 项通过、1 项跳过。跳过项是当前 Windows 权限下不能创建符号链接的 bundle 边界检查，未计为通过。

- [基线失败记录](validation/p0/h01-red.json)：新增测试与基线监督器哈希、失败用例。
- [修复后桌面测试](validation/p0/desktop-tests.json)：初次 P0 提交的测试名称、结果及实际被测源码清单。
- [CI 路径断言修正后的桌面复跑](validation/p0/desktop-tests-canonical-path.json)：55 项运行、54 通过、1 跳过，类型检查通过。

## H02：独立 Python 工具环境

固定验证组合为 Windows x64、标准 GIL 的 CPython 3.14.6、pip 26.1.2、UnityPy 1.25.2、lz4 4.4.5。锁文件包含 12 个依赖分发文件的精确版本与 SHA-256；控制入口、framing、证据解析及 unittest 使用标准库。其他平台、架构和 Python 版本尚未验证。

运行时来自 Python 官方 Windows 发行 ZIP。安装脚本在解包前校验 ZIP 哈希，再核验版本、架构、GIL、内置 pip wheel 和依赖锁；创建全新的 venv，使用隔离的 pip 与 `--require-hashes`，拒绝已有目标目录。离线 wheelhouse 要逐项匹配锁文件且不能多出 wheel。工具和测试入口要求 `-I`，仓库导入边界由入口位置确定，不依赖当前目录、用户 site-packages 或 `PYTHONPATH`。

实际在 Windows PowerShell 5.1 下完成新运行时及新环境安装，随后通过已核验的 wheelhouse 完成另一份环境安装。将一个 wheel 翻转一字节后，脚本退出失败，并且没有创建目标环境。

| 证据 | 结果与绑定 |
| --- | --- |
| [独立环境](validation/p0/python-environment.json) | 官方发行来源及 ZIP、安装脚本、依赖锁、解释器、实际包版本和环境测试源码的哈希 |
| [wheelhouse 环境](validation/p0/python-wheelhouse-environment.json) | 显式 wheelhouse 的文件校验及安装结果 |
| [损坏 wheel 拒绝](validation/p0/python-wheelhouse-rejection.json) | 原始与损坏哈希、非零退出、目标未创建 |
| [真实静态提取](validation/p0/static-extraction.json) | 固定环境中两次提取，三个输出逐字节相同 |

真实提取使用本地只读 scripts 输入，SHA-256 为 `d39fcc02eb38d4966d3732d9008d75cb41913194942a4800ad5a7585104a0019`。两次结果保持既有 schema 哈希 `917010c2bc0cf4e4bfb21dfdf66c77128cff61d9a47c848a30f0a1c1d4a842b0`，仍为 92 个协议资产、3,061 条消息、6,889 个字段、1,368 个闭合引用。报告仍明确 `runtime_test_performed=false`、`compatibility_admitted=false`，不将静态提取解释为运行准入。

复现步骤及发行哈希见 [Python 工具环境说明](../../tools/python/README.md)。原安装目录没有被用作该验证组合的隐含依赖。

## H03A：可复核工具与本地证据

matcher、PCAPNG analyzer 和从零构造的合成测试已迁入 `tools/evidence/`、`tests/evidence/`。保留既有 15 项 matcher 测试，并增加 PCAPNG 结构、跨 section 的 interface ID、TCP 分片和重传、冲突重叠、截断、序列缺口、协议头跨包、UTF-8、压缩预算及尾随数据等拒绝边界。上行没有已观测的显式压缩标志，按原始字节匹配；zlib 特征仅作诊断。下行按实际 flag 选择 raw 或有界完整解压。

CLI 要求显式输入、schema、双方预期 SHA-256 和新输出目录，拒绝覆盖旧结果。公开报告仅包含计数、状态、哈希、限额和拒绝原因；不包含原始包、IP、域名、HTTP 正文、协议字段值、凭据或个人绝对路径。原始 PCAP、测试产物、环境、wheelhouse 和包文件继续被 Git 忽略。

真实 PCAP 复跑及合成套件的最终结果在下表记录；捕获分析本身不会执行测试，二者分别绑定实际执行源码和输入。

| 验证 | 当前记录 |
| --- | --- |
| 合成 Python 套件 | [112 项运行、111 通过、1 跳过](validation/p0/python-tests.json)，0 failure / error；源码前后不变 |
| 本地官方抓包 | [主代理独立复跑](validation/p0/official-startup-analysis.json)：目标协议观测前缀通过，去重 238 帧全部可信匹配 |
| Electron source smoke | [19 项检查通过](validation/p0/electron-source-smoke.json) |
| Electron package smoke | [19 项检查通过](validation/p0/electron-package-smoke.json)，同时绑定 ASAR SHA-256 |

桌面测试和两项 smoke 使用从基线新建的独立 checkout，以 `npm ci --ignore-scripts` 安装锁定依赖，再应用本轮 H01 修复。报告绑定该 checkout 的实际源码，而不是推测主目录与打包结果一致。历史 [16 项 source 报告](validation/electron-source-smoke.json) 和 [16 项 package 报告](validation/electron-package-smoke.json) 保持原样，不改写历史检查数。

最终本地 Python 套件同样在独立 checkout 中执行，使用 H02 新运行时及环境；86 项被记录源码及构建输入的哈希逐项与初次 P0 提交 `e7f7077` 一致。五组分别为控制入口 13、framing 15、静态恢复 44、证据工具 33、环境契约 7。唯一跳过项是当前 Windows 权限下的目录 symlink 检查，保留明确原因。之后的 CI 修正只改变客户端识别测试的路径断言；本地报告保留实际运行时的源码身份，远端结果另列。

原始 PCAP 为 131,622,688 字节，SHA-256 为 `e1218b5dcff6d89578fcc7f8d47df0932f3c02f37d207fb0a6a43b3d0f8449db`，本轮前后哈希一致。去重后为上行 18、下行 220，共 238 帧；对应既有网关 2 帧与游戏 236 帧范围。未知字段、wire 冲突、required 缺失和 incomplete 均为 0；9 个 flag-1 下行全部有界解压成功。多采集视角的 714 次原始匹配及 27 次压缩观察另列，不能计作新增协议帧。

目标流无序列缺口、冲突、截断、预算丢弃或残帧。新的严格工具也发现 4 个冲突字节，分别属于 4 条辅助 HTTP 流，已从目标协议完整性中分开登记，并用从零构造的混合流回归验证；不声称这些 HTTP 流完整。160 条 TLS 流只计数，未解密；目标流中 6 个采集方向未观察到关闭，也不声称验证了整个长连接生命周期。该报告的 `passed` / `complete` 范围仅为目标协议观测前缀，不代表全捕获、SDK 或大厅通过。

证据工具用法见 [离线证据说明](../../tools/evidence/README.md)；合成测试与 smoke 报告绑定方法见 [验证入口说明](../../tools/validation/README.md)。报告记录生成时基线及源码哈希，不要求包含最终承载报告自身的提交哈希。

源码遵循仓库既有 LF 换行策略，最终复跑使用与待提交源码相同的字节。P0 JSON 报告通过 Git 属性保留实际生成字节，避免 Windows 换行转换破坏报告之间的 SHA 关联。

## H03B：GitHub Actions

[P0 工作流](../../.github/workflows/p0-validation.yml) 在 Windows runner 上检查 Node / npm 版本、安装锁定桌面依赖、运行类型检查和 Vitest，然后调用与本地相同的 Python 环境脚本，运行全部合成 Python 套件。官方 Actions 固定到完整提交 SHA。测试与环境报告作为运行附件保存 14 天。

真实客户端、私人 PCAP 和本地桌面 smoke 不进入公共 CI。[首次实际运行](validation/p0/ci-initial-failure.json) 在既有客户端识别测试中失败：runner 的 TEMP 使用 Windows 短路径，生产代码返回正确的真实路径，测试以 `path.resolve` 比较导致误判。已将断言改为文件系统 `realpath` 并完成本地全套桌面复跑；Python 步骤在该次 CI 中未执行，不计为通过。

修正提交 `0129d88fa6143db123628aa68cf395d26b2332e7` 的 [第二次实际 CI](https://github.com/LingYzh/ag-local/actions/runs/38146368259) 全部通过，步骤状态和制品摘要保存于 [ci-run.json](validation/p0/ci-run.json)。下载附件后核对 ZIP SHA-256，并逐项核对 86 项源码 / 构建输入哈希与本地提交一致。该 runner 能创建测试 symlink，因此两套测试没有跳过项。

| 远端验收 | 持久化结果 |
| --- | --- |
| 桌面类型检查及 Vitest | [55 项全部通过](validation/p0/ci-desktop-tests.json)，从原始报告提取测试名称和状态 |
| 独立 Python 环境 | [官方发行与依赖锁核验通过](validation/p0/ci-python-environment.json)，实际使用 Windows PowerShell 5.1 安装 |
| 全部合成 Python 套件 | [112 项全部通过](validation/p0/ci-python-tests.json)，工作区干净、执行前后源码不变 |

远端附件摘要为 `ec325775b47c737b632db3e13bb774c155199291bc140e91403708ccc20c3401`，保留至 2026-10-25。上述白名单报告另保存在仓库，附件到期不会删除已提交的验收记录；未发布原始 job 日志或含绝对 runner 路径的原始 Vitest JSON。

## 验收边界与下一步

本轮未启动游戏、开放业务端口、创建客户端副本、改写存档或实现 SDK / 网关 / 大厅处理器。启动按钮仍管理 TS 诊断服务，受控 Python 入口仍为 `businessReady=false`。H08 要求的实际入口、依赖模块及环境在监听前校验，继续作为后续真实业务接入的约束。

P0 的合成测试、静态提取和离线结构匹配只证明对应工具及生命周期行为。下一步仍按计划开展 H04—H08；每次阶段试验只校验实际执行的工具、处理器和数据，后续能力明确禁用，不以占位 LoginPlan 或种子绕过预检。
