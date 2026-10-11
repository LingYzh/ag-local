# ag-local

从 Alpha-Persei-Cluster 分离的本地服务重构工程。当前包含 Vue 3 / Electron / TypeScript 桌面底座、隔离 Python 控制入口、当前客户端静态协议恢复工具和 TCP 分帧；游戏登录、大厅及存档业务尚未接通，G0 / G1 尚未通过。

实施依据保存在 [docs/plan](docs/plan/)，当前状态见 [业务准备进度](docs/refactor/business-progress.md) 和 [大厅契约](docs/refactor/hall-contract.md)。路线是先由桌面壳管理隔离的 Python 服务，通过大厅门槛后逐用例迁移到 TypeScript。

## 开发

在 `D:\ag-local\desktop` 使用 Node.js 24.19.x–24.x、npm 11：

```powershell
npm run check
npm test
npm run dev
```

迁移保留了本机已有依赖；其他环境先执行 `npm ci` 和 `npm run runtime:install`。桌面、Python 控制面及打包命令详见 [desktop/README.md](desktop/README.md)。

Python 工具及测试从仓库根目录运行，以保留 `v5_server` 的导入路径。例如：

```powershell
python -B -m unittest discover -s tests/network -p 'test_*.py'
python -B -m unittest discover -s tests/static_protocol -p 'test_*.py'
python -B -m unittest discover -s tests/controlled_service -p 'test_*.py'
```

## 迁移来源

重构材料原位于 `D:\Alpha-Persei-Cluster` 的 `codex/refactor` 工作区，分支基准为 `83c03f1d75004ecb9f0ac1484676f6b5181dfa4e`。旧服务源码仍在原仓库；本工程不包含旧启动入口。迁移记录见 [目录迁移说明](docs/refactor/directory-migration.md)，许可见 [LICENSE](LICENSE)。
