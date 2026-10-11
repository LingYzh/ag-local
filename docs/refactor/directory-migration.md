# 重构工程目录迁移

2026-10-11（UTC+8），按用户要求将重构工作区由 `D:\Alpha-Persei-Cluster` 迁至 `D:\ag-local`。目标已有独立 Git 仓库及 `origin=https://github.com/LingYzh/ag-local.git`；其 Git 配置和 IDE 文件保留。迁移不创建提交或推送。

## 范围

- `desktop/`：桌面源码、锁文件、组件 demo、依赖、构建、便携包和 QA 证据。
- `docs/plan/`、`docs/refactor/`：实施计划、原始参考、当前进度和验证记录。
- `tests/`、`v5_server/bootstrap/`、`v5_server/network/`、`v5_server/tools/`、`v5_server/artifacts/`：新增 Python 模块、测试、静态恢复工具和当前 schema。
- `Alpha-Persei-app307-resource229-schema-candidate/`：用户提供的历史 schema 与恢复方法。
- 根目录的空 QA 子目录，以及单独封存的旧 Python 字节码缓存；根 LICENSE 复制，重构忽略规则转入新仓库。

旧 `LocalServer/` 和旧服务实现保留在 Alpha-Persei-Cluster。游戏客户端、官方原始抓包、安装目录和存档未迁移。

## 校验与路径

主迁移共 6,901 个文件、3,070,592,049 字节；迁移前后逐项 SHA-256 与大小一致，目标 Git 配置哈希一致。本机详细清单及迁移日志保存在忽略目录 `qa/migration/`。

活动使用说明、三个 QA 脚本与最新便携包路径指针已更新。既有报告里的旧绝对路径、构建时间及固定提交来源链接保留，表示历史采样或构建位置；不据迁移改写历史证据。静态 schema 及提取报告原字节保留。

原 `codex/refactor` 在迁移前没有新增提交，因此“初始状态”对应分支创建时的 `83c03f1d75004ecb9f0ac1484676f6b5181dfa4e`，恢复其索引和已跟踪文件后核验工作区清洁。原仓库已有 IDE 文件保持不变。

## 迁移后验证

- `npm run check` 通过；Vitest 51 项通过、1 项跳过。
- Python framing、静态恢复、受控入口和抓包 matcher 合计 86 项通过、1 项跳过。
- 当前 schema 的真实桌面 loader 互操作、两份静态制品字节一致性和 92 个历史协议资产 SHA 核对通过。
- 迁移后的既有便携包 `smoke:package` 19 项检查通过；原 ASAR SHA 不变。
- `smoke:python` 使用新目录中的受控入口与新合成 fixture 完成两次启停，实例 UUID 不同，最终 STOPPED，`businessReady=false`。
- 原仓库 `codex/refactor` 保持基准提交，`git status --porcelain` 为空；新仓库仍为无提交的 main，origin 配置未改。

本机检查汇总为 `qa/migration/validation.json`；Python 双启停报告为 `desktop/qa/python-synthetic-Pq6UrH-report.json`。迁移不改变业务验收结论：当前 G0 / G1 尚未通过。
