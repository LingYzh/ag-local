# 业务接入准备进度

截至 2026-10-11（UTC+8）。

重构工程已整体迁入 `D:\ag-local`，原 Alpha-Persei-Cluster 的 `codex/refactor` 工作区恢复到分支创建时的 `83c03f1`。代码、计划、候选 schema 与本地 QA 材料已保留；迁移核验见 [目录迁移说明](directory-migration.md)。下文既有记录中的采样时间及来源路径保持历史含义。

对 `7aea8f0` 的独立复核已形成 [5.3.1 大厅推进计划](../plan/AG-Local_531_Hall_Execution_Plan_v1.0.md)。P0 H01—H03 已完成本地及远端验收：修复 TS 监督器迟到退出清掉故障的问题，建立独立且锁定的 Python 工具环境，将离线匹配工具与合成测试迁入源码，并核验实际 CI 成功。结果、源码绑定和 CI 记录统一见 [P0 验证记录](p0-validation.md)。G0 / G1 仍未通过。

## 当前路线与结论

已选路线是由新的 Vue / Electron / TypeScript 桌面壳管理隔离的 Python 兼容服务，先让当前客户端通过大厅 G1，再逐步把业务服务迁移到 TypeScript。两份原计划仍提供版本身份、取证和 G1 验收标准；本路线记录用户之后明确选定的实施顺序。

截至本记录，未判定 G0 完成，也没有 G1 通过结论。当前完成的是桌面底座、只读客户端识别、受控 Python 进程控制、当前脚本的静态 schema 恢复及纯 Python TCP 分帧。官方登录轨迹的全部 238 帧已逐帧匹配；这些结果尚不代表本地服务端业务可用。

## 已有证据

| 范围 | 当前证据 | 边界 |
| --- | --- | --- |
| 当前客户端候选 | 只读 inventory 检查了 D:\AetherGazerStarter\AetherGazer。AssetHash_Info 记录 appVersion=307、buildCode=321、channel=0、versionName=v5.3.1；索引有 65,494 项，index SHA-256 为 35bc1339644d9940d10e22edf24cd6dd0e5208de917162b27e1e3ba0749eddda。 | 这是本机当前材料识别结果；官方最新状态、完整资源闭包和 5.3.1 运行组合仍未独立确认。buildCode 保留原字段含义，不据此改写其他版本轴。 |
| 脚本制品 | scripts MD5 为 f9468cd00564c3c98e4f819210760be1，SHA-256 为 d39fcc02eb38d4966d3732d9008d75cb41913194942a4800ad5a7585104a0019。 | 只核验了关键文件指纹，不是全客户端或全资源闭包。尚无隔离客户端克隆，也未用当前客户端实际登录。 |
| 客户端识别 | Electron 界面提供选择客户端及识别材料功能；命令行 inventory 只读目标目录，并将完整报告写到用户指定的新文件。 | 输出是 observed 观察材料，不是兼容准入或 G0 通过报告。 |
| Python 生命周期 | 主进程中的监督器校验 Python 绝对路径及 SHA-256、完整准入 bundle，直接创建私有子进程，以随机 UUID 和私有 JSONL 管道核对 READY、独立 status、shutdown 确认与退出码。 | 不按 PID 或进程名结束进程。这个监督器尚未接入桌面按钮，也不是游戏业务服务。 |
| 受控 Python 入口 | v5_server/bootstrap/controlled_service.py 仅使用标准库；不导入旧 main、不监听网络、不读写存档。READY 和 status 明确返回 businessReady=false。 | 只执行制品预检和控制协议；不能响应真实游戏客户端。 |
| 229 schema 候选 | Alpha-Persei-app307-resource229-schema-candidate 的源版本是 app 307 / resource 229 / v5.2.1。原始客户端协议定义 3,061 条、6,889 个字段；增加一个有源码依据的三字段兼容别名后，候选有 3,062 个消息键、6,892 个字段。schema SHA-256 为 b9101c965ed4f75317aa9c0199e17e5a7d2c3e0c0e23b982217a960b1a6ee79f。 | 仅为 229 静态证据，不能代替当前 321 的恢复结果，也不作为运行回退。静态复核报告明确 runtime_test_performed=false。 |
| 当前静态 schema | 当前 scripts 的 92 个协议资产恢复为 3,061 条限定名消息、6,889 个字段，1,368 个消息引用全部闭合。schema SHA-256 为 917010c2bc0cf4e4bfb21dfdf66c77128cff61d9a47c848a30f0a1c1d4a842b0；保存于 `v5_server/artifacts/app307-resource321-static/`。 | 当前 92 个协议资产的名称与逐项 SHA 均与历史记录一致，证明这部分静态字节一致，不外推到整个 scripts、内容、SDK 或大厅行为。无额外兼容别名，未执行 Lua，未做运行准入。 |
| 官方正常登录抓包 | 用户提供本机 `official-startup-01.pcapng`，131,622,688 字节，SHA-256 为 e1218b5dcff6d89578fcc7f8d47df0932f3c02f37d207fb0a6a43b3d0f8449db；实际采样为 2026-10-10 21:41:36–21:43:12（UTC+8），61,616 个包。去重后的网关 10038→10039 与游戏 17 上行、219 下行已分帧；登录帧声明 client_vs=307 / resource_vs=321。 | 用户确认只登录并停在大厅。目标流观测前缀闭合且无重组冲突；不声称未采样的长连接结束。没有 TLS 密钥，SDK 正文未知；用户选择先完成协议和 TCP 契约。尚无本地大厅运行记录，不能标记 G1。 |
| 复制前资源盘点 | 当前目录共 70,800 文件、61,012,486,046 字节，无 reparse entry 或遍历错误；D 盘足够容纳完整副本。索引 65,494 条引用去重为 65,493 个 hash，65,417 个对应文件存在且大小匹配。 | 76 个 hash 缺失，约 0.92 GiB；22 个声音条目处于 pending catalog、13 个视频、41 个其他资源，不能仅凭类别假设可忽略。尚未完整哈希、复制或证明必需资源闭包。 |

当前客户端识别使用：

    npm run inventory:client -- --client <客户端绝对路径> --output <新报告绝对路径>

受控 Python 准入探针要求固定运行时哈希、controlled_service.py 和完整的已准入制品目录：

    npm run preflight:python -- --python <python.exe绝对路径> --python-sha256 <python.exe的SHA-256> --entry <controlled_service.py绝对路径> --bundle <完整准入制品目录> --output <新报告绝对路径>

另有只使用合成十类制品 fixture 的 Python 双启停 smoke 命令。两个独立 Python 生命周期测试均使用不同 UUID；这项验证只覆盖控制面。当前静态恢复入口、预算与输出说明见 [static-protocol-recovery.md](static-protocol-recovery.md)。

## 桌面与控制面状态

桌面 bridge 有八个语义方法：getEnvironment、getStatus、startService、stopService、chooseBundle、inspectBundle、chooseClient、inspectClient。现有界面的 startService/stopService 管理的是独立 TypeScript 诊断服务。Python 监督器已实现并由 CLI 探针使用，但没有接入游戏业务界面。

当前受控 Python 入口和 TS 诊断服务的 READY 都只表示控制或诊断通道可用。它们不能被解释成游戏网络端口已经开放、SDK 登录已完成或业务就绪；businessReady 始终为 false。

## 迁移基线的历史验证记录

以下是迁移前及 `7aea8f0` 阶段的记录，检查数与原路径保持历史含义。当前 P0 结果使用 [新报告](p0-validation.md)，不改写历史 16 项 smoke 报告或将旧 QA 文字当作本轮可复核证据。

- npm check 通过。
- Vitest：5 个文件，51 项通过、1 项跳过；包括关闭超时后迟到退出不得抹掉故障、所有权释放前拒绝重启、READY 复核超时与迟到消息处理。
- Python unittest：13 项运行，12 项通过；1 项因 Windows 当前权限不允许创建目录符号链接而跳过。
- Electron 开发版 smoke：19 项通过，覆盖真实桌面按钮、worker 和合成客户端识别，含浅色与深色主题。
- npm run package 生成 portable-Xhbo0T；真实便携包 smoke:package 的 19 项检查通过。
- 当前客户端识别报告截图 client-inventory.png 与 client-inventory-dark.png 已由主代理在 1280×900 浅色、深色主题下完成视觉验收。
- inventory producer 与 IPC validator 的互操作断言通过。
- 真实客户端两次只读识别的 6 项关键文件指纹一致，报告为 `desktop/qa/business/client-inventory-first.json` 与 `client-inventory-final.json`；该核验仍不等于完整资源保全或 G0 通过。
- Python synthetic smoke：使用十类合成制品完成两次启停，实例 UUID 不同；报告另存于 fixture 之外的新文件，只证明生命周期控制。最新报告为 `desktop/qa/python-synthetic-6aOGE5-report.json`。
- 静态协议 unittest：44 项通过；包含 UnityFS/SerializedFile 范围与解压预算、LuaJIT 常量编码、查表数据流、声明归属、完整命名空间、默认值来源、引用闭合与拒绝边界。
- 当前制品两次实际 CLI 发布的三个文件逐字节一致；schema 26,504,729 字节，报告 7,815,768 字节，均低于 32 MiB 上限。桌面真实 schema loader 接受此 IR，核对 3,061 消息、6,889 字段和 1,368 引用；92 个历史资产 SHA 全部匹配。报告仍明确 runtime_test_performed=false / compatibility_admitted=false。
- 生产 Python framing：15 项测试通过，真实 238 帧按碎片和粘包解码再编码逐字节一致，无残帧。当前实现只处理已观测头部和 opaque body，不监听业务端口。
- 当前 schema 抓包匹配：15 项边界测试通过；去重后的 238 帧全部映射、wire 匹配通过，未知字段、线类型冲突、required 缺失和 incomplete 均为 0。9 个压缩下行均有界解压。机器观察材料为 [login-observation-307-321.json](login-observation-307-321.json)，不是可执行 LoginPlan。
- 本轮结束前重新核验 PCAP SHA 与客户端 6 项关键文件指纹，均未变化；这仍不等于全客户端保全或 G0。
- 上述自动化、截图和打包证据均未覆盖当前游戏客户端的登录或大厅。

## 仍待完成

1. 根据已匹配的 238 帧逐项恢复必要性、数据来源和失败语义；229 候选只保留作历史参考。
2. 为当前目标补齐版本来源、EXE / SDK / 资源索引 / 必需资源及服务端 bundle 的完整指纹；inventory 的关键文件哈希不等于完整资源闭包。
3. 将已核验的纯 Python TCP 分帧与后续用例/会话处理连接。已有抓包无需因文件较大重新采样；[采样说明](hall-capture.md) 保留作后续补充指引。SDK TLS 正文暂缺，按用户决定先完成协议/TCP 部分。
4. 据同版本静态 schema、可观察请求顺序和实际响应，整理 LoginPlan、SDK 契约、网关阶段、动态字段及大厅必需数据；未知项继续标未知。
5. 建立独立客户端克隆、隔离服务端目录和测试存档，确认副本指纹与来源一致，再实际完成大厅进入、退出重登和服务重启后复测。
6. 只有达到 G1 后，才把真实业务功能按已验证接口迁移到 TypeScript。

计划文档中的 G1 门槛要求版本来源与运行组合可追溯、使用目标客户端克隆和独立测试存档实际进入大厅并能重登、受保护文件哈希不变、请求和错误可关联、服务重启后行为可复现。当前材料还没有满足这些运行条件；逐项证据缺口见 [当前大厅契约](hall-contract.md)。
