# Alpha Persei 桌面底座

本工程已迁入独立的 `ag-local` 仓库，采用 Vue 3 + Electron + TypeScript。首轮交付包含桌面壳、Vuetify 组件预览、独立 TS 诊断服务和只读制品检查；另有当前客户端只读识别，以及受控 Python 兼容进程的命令行探针。登录、大厅、存档和游戏网络业务尚未接入。

当前路线是先由新桌面壳管理隔离的 Python 兼容服务，通过当前客户端的大厅 G1 后再迁移 TS 业务服务。现有界面的启动按钮仍启动 TS 诊断服务；Python 控制入口尚未接到界面，也不是游戏服务。当前没有 G0/G1 通过结论，细节见 [业务准备进度](../docs/refactor/business-progress.md) 和 [大厅契约证据](../docs/refactor/hall-contract.md)。

当前 scripts 的静态恢复已生成 3,061 条限定名消息、6,889 个字段和 1,368 个闭合消息引用；两次结果一致，桌面 schema loader 验证通过。恢复方法、候选路径与边界见 [静态协议恢复](../docs/refactor/static-protocol-recovery.md)。官方登录抓包已留在本机离线分析，原始 payload 不进入仓库。

## 启动

使用 Node.js 24.19.x–24.x、npm 11。命令在 `D:\ag-local\desktop` 执行：

```powershell
npm ci
npm run runtime:install
npm run dev
```

`runtime:install` 显式下载锁定的 Electron；不能依赖本机 npm 的生命周期脚本许可配置。`dev` 先执行类型检查并构建，再打开实际 Electron 窗口；界面修改后重新运行此命令。单独调整组件时使用 `npm run dev:ui`，浏览器预览默认显示组件 demo。

界面沿用 Vuetify 原生 light/dark 主题、颜色和组件外观。公共组件及样式先在 `src/renderer/ui` 与 `demo` 修改和验收，再供功能界面使用。

## 验证与打包

```powershell
npm run check
npm test
npm run smoke:ui
npm run smoke
npm run package
npm run smoke:package
```

- `check`：Vue 与 Node 两侧 strict TypeScript 检查。
- `test`：协议、清单、路径边界与服务生命周期单测。
- `smoke:ui`：真实构建产物的 Chrome 检查，覆盖 1280 / 960 / 390 宽度、浅深主题、输入、页签和键盘焦点。测试直接从磁盘响应浏览器请求，不经过本机杀毒软件改写的 HTTP 传输。
- `smoke`：隐藏 Electron 窗口中的端到端验证，使用独立的 QA profile、离屏渲染、只读 fixture 与自己创建的服务实例。崩溃注入仅在两次私有响应验证实例身份后执行。
- `package`：创建 Windows x64 便携目录、ASAR 和许可证副本；不制作安装器、不签名、不发布。每次使用新的 `out/portable-*`，实际路径和 ASAR SHA-256 写入 `out/latest-package.json`。
- `smoke:package`：启动最新便携包，从仓库根目录工作目录验证，确认不依赖 npm 开发环境或当前目录寻找制品。
- `inventory:client`：只读识别指定客户端目录。完整报告只写入明确指定、位于客户端目录之外且尚不存在的绝对路径。
- `preflight:python`：核对 Python 可执行文件 SHA-256 和完整准入制品包，再两次启动受控 Python 兼容进程，检查私有身份、状态、关闭确认和正常退出；报告写到制品目录之外的新文件。
- `smoke:python`：使用合成的十类制品 fixture 验证两次 Python 启停及不同实例身份，不连接真实游戏。

示例参数须替换为实际绝对路径；不要覆盖既有报告：

    npm run inventory:client -- --client <客户端绝对路径> --output <新报告绝对路径>
    npm run preflight:python -- --python <python.exe绝对路径> --python-sha256 <python.exe的SHA-256> --entry <controlled_service.py绝对路径> --bundle <完整准入制品目录> --output <新报告绝对路径>
    npm run smoke:python -- --python <python.exe绝对路径>

临时 QA 输出在 `qa/`，打包产物在 `out/`，两者均被 Git 忽略。已记录的视觉与验证结果在 `../docs/refactor/`。

## 模块边界

| 模块 | 职责 |
| --- | --- |
| `src/renderer` | Vue 界面，通过八个语义 bridge 方法访问底座 |
| `src/renderer/ui`、`demo` | Vuetify 薄包装、间距尺寸 tokens、真实组件预览 |
| `src/preload` | sandbox 下的窄 `contextBridge`，不暴露通用 IPC 或文件 API |
| `src/main` | 窗口、调用来源校验、原生目录选择、TS 诊断服务所有权；另含 Python 兼容进程监督器 |
| `src/shared` | 请求、响应、错误和状态的 TS 契约与入参校验 |
| `src/service` | utility process 中的独立诊断服务与纯 TS 校验器 |

Electron 窗口启用 context isolation、sandbox、web security，关闭 Node integration；拒绝外部资源、导航、弹窗、webview 和权限请求。界面只能调用 `getEnvironment / getStatus / startService / stopService / chooseBundle / inspectBundle / chooseClient / inspectClient`，目录由主进程选择。

服务每次创建使用新的 UUID 和私有父子通道，完成版本与身份握手才进入 READY。关闭等待启动结束，再排空检查、确认关闭并观察退出；超时保留所有权并明确失败。不会按 PID、进程名或端口扫描终止程序。READY 表示诊断通道可用，`businessReady` 本阶段始终为 `false`。

Python 兼容监督器通过私有标准输入/输出管道直接启动受控入口，要求显式 Python SHA-256 和完整准入制品包。它只验证兼容制品与进程生命周期；受控入口不导入旧游戏服务、不监听游戏端口、不读写存档。界面当前没有 Python 启动按钮，`startService` 仍指向 TS 诊断服务。

## 制品检查输入

选择的目录需包含 `manifest.json`，服务器制品位于 `server/`、客户端制品位于 `client/`。示例结构：

```json
{
    "manifest_version": 1,
    "tuple_id": "candidate-5.3.1-unverified",
    "state": "observed",
    "identity": {
        "platform": "unknown",
        "channel": "unknown",
        "architecture": "unknown",
        "app_version": "unknown",
        "resource_version": "unknown"
    },
    "capabilities": { "hall": "unverified" },
    "artifacts": []
}
```

清单状态支持 `observed / imported / static_passed / hall_passed / flows_passed / quarantined`。observed 允许未知身份并返回待补齐项；其他状态拒绝 `unknown` 等占位身份。artifact 结构为 `{ "role": "schema", "root": "server", "path": "schema.json", "sha256": "64 位十六进制摘要" }`；不得使用绝对路径、父目录、ADS、设备名或指向目录外的链接。

齐全判定要求十种 role：`schema / protocol_overlay / runtime_lock / content / seed / login_plan / client_exe / client_sdk / client_index / client_scripts`。每项均流式核验 SHA-256；schema 还校验 JSON 重复键、规范消息全名冲突、字段编号/名称冲突、字段类型、label 和 message 引用闭包，保留限定消息名及字段的 enum 类型/ref，并冻结注册表。当前注册表尚不承载完整来源映射、默认值或枚举取值范围；这些原始元数据应保存在 schema 制品中。全量哈希通过也只说明清单齐全；`declaredHallPassed` 仅反映清单声明，不能替代实际业务测试。

纯 Python 的当前观测 TCP 分帧已实现并离线核验；桌面服务尚未接入该游戏网络模块，protobuf 业务编解码、数据库内容语义检查及存档迁移仍待实现。清单最大 1 MiB、schema 最大 32 MiB；服务单次请求默认 5 秒超时。检查是文件系统的只读快照，导入期间应保持制品不变；后续运行制品的固定与事务发布属于下一阶段。

## 锁定版本

Vue 3.5.43、Vuetify 4.2.4、Electron 44.7.0、TypeScript 5.9.3、Vite 8.3.4。依赖使用精确版本和 `package-lock.json`。构建机 Node 版本与 Electron 内置 Node 版本分开；界面展示运行进程的实际版本。

原安装与旧项目仅作基线参考。详细边界见 `../docs/refactor/foundation-scope.md`，安装目录审计见 `installed-baseline.md`。更新 Vue/Vuetify 版本时同步更新 `THIRD_PARTY_NOTICES.txt`；Electron 自带许可证随便携包保留。
