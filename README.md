# ag-local

从 Alpha-Persei-Cluster 分离的本地服务重构工程。当前包含 Vue 3 / Electron / TypeScript 桌面底座、隔离 Python 控制入口、当前客户端静态协议恢复工具和 TCP 分帧；游戏登录、大厅及存档业务尚未接通，G0 / G1 尚未通过。

实施依据保存在 [docs/plan](docs/plan/)，当前状态见 [业务准备进度](docs/refactor/business-progress.md) 和 [大厅契约](docs/refactor/hall-contract.md)。路线是先由桌面壳管理隔离的 Python 服务，通过大厅门槛后逐用例迁移到 TypeScript。

按 [5.3.1 大厅推进计划](docs/plan/AG-Local_531_Hall_Execution_Plan_v1.0.md) 执行。P0 的修复与可复现验证记录见 [P0 验收报告](docs/refactor/p0-validation.md)，后续按真实客户端阶段推进最小大厅链路。

## 开发

在 `D:\ag-local\desktop` 使用 Node.js 24.19.x–24.x、npm 11：

```powershell
npm ci --ignore-scripts --no-audit --no-fund
npm run runtime:install
npm run check
npm test
npm run dev
```

桌面、Python 控制面及打包命令详见 [desktop/README.md](desktop/README.md)。

Python 静态工具使用固定的 CPython 3.14.6 Windows x64 运行时和带 wheel 哈希的依赖锁。先从仓库根目录建立新环境，再运行隔离的合成测试：

```powershell
$environmentDir = Join-Path (Get-Location).Path 'qa/python-environment-local'
$systemPowerShell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
& $systemPowerShell -NoProfile -EP Bypass -File tools/python/verify-environment.ps1 -TargetDirectory $environmentDir
if ($LASTEXITCODE -ne 0) { throw 'Python environment verification failed.' }
$pythonExe = Join-Path $environmentDir 'venv/Scripts/python.exe'
& $pythonExe -I -B tools/validation/run_python_tests.py --output qa/python-tests-new.json
```

环境目录与报告文件必须尚不存在。发行包、依赖、离线 wheelhouse 和隔离边界见 [Python 环境说明](tools/python/README.md)；证据工具见 [tools/evidence](tools/evidence/README.md)，报告绑定及 CI 范围见 [验证工具说明](tools/validation/README.md)。原始 PCAP 与客户端制品继续留在本地。

## 迁移来源

重构材料原位于 `D:\Alpha-Persei-Cluster` 的 `codex/refactor` 工作区，分支基准为 `83c03f1d75004ecb9f0ac1484676f6b5181dfa4e`。旧服务源码仍在原仓库；本工程不包含旧启动入口。迁移记录见 [目录迁移说明](docs/refactor/directory-migration.md)，许可见 [LICENSE](LICENSE)。
