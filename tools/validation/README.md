# 可复核验证记录

这些工具只运行合成测试或绑定已有 smoke 结果，不启动游戏服务，也不把控制面成功解释为大厅通过。

## Python 合成测试

先按 [Python 环境说明](../python/README.md) 建立锁定环境，再从仓库根目录执行。下例使用新的 `qa/python-environment-local` 环境：

```powershell
$pythonExe = Join-Path (Get-Location).Path 'qa/python-environment-local/venv/Scripts/python.exe'
& $pythonExe -I -B tools/validation/run_python_tests.py --output qa/python-tests-new.json
```

输出文件必须不存在。运行器显式加入自身所在仓库的导入路径，执行各组 `unittest`，记录逐项结果、跳过原因、源码 SHA-256、基线提交和环境摘要；测试前后源码变化时整次验证失败。它不依赖当前目录或 `PYTHONPATH` 来导入业务模块。原始控制、分帧和静态恢复测试，以及迁入的证据工具测试均由同一入口发现。

默认要求五组测试目录都存在且非空；要单独复核标准库控制面或静态恢复，可使用 `--group controlled_service`、`--group network` 或 `--group static_protocol`。子集报告明确列出未执行的组，不能算作全量通过。`python_environment` 组会核对锁定的 Windows x64 虚拟环境，因此全量验收须使用上面的固定环境。

## Electron source / package smoke

在构建前保存源码快照，随后运行已有的 source 与 package smoke，最后绑定结果。下例中的运行时须来自已核验环境；每次使用新的快照和公开报告路径：

```powershell
& $pythonExe -I -B tools/validation/bind_desktop_report.py --snapshot qa/desktop-source-snapshot-new.json
Push-Location desktop
npm run smoke
Pop-Location
& $pythonExe -I -B tools/validation/bind_desktop_report.py --snapshot qa/desktop-source-snapshot-new.json --smoke desktop/qa/electron/electron-smoke.json --output qa/source-smoke-bound-new.json
```

package 检查同样在 `npm run package` 前保存快照，运行 `npm run smoke:package` 后绑定：

```powershell
$packageInfo = Get-Content -LiteralPath desktop/out/latest-package.json -Raw -Encoding UTF8 | ConvertFrom-Json
$asarPath = Join-Path $packageInfo.directory 'resources/app.asar'
& $pythonExe -I -B tools/validation/bind_desktop_report.py --snapshot qa/desktop-package-snapshot-new.json --smoke desktop/qa/packaged/electron-smoke.json --asar $asarPath --output qa/package-smoke-bound-new.json
```

绑定器拒绝源码与构建前快照不一致的结果。公开结果仅保留检查名称、成功状态、运行时摘要、实例 UUID、实际原始 smoke 报告哈希及源码清单；package 结果另绑定实际 ASAR 哈希。不会复制 fixture 路径或整个 bundle 报告。旧的 16 项报告保留历史含义；当前证据使用独立的新报告。

## CI 边界

[P0 工作流](../../.github/workflows/p0-validation.yml) 在 Windows x64 上执行 `npm ci`、类型检查、Vitest，以及独立虚拟环境中的锁定 Python 合成测试，上传逐项测试记录。GitHub Actions 使用固定 action 提交；Python、Node、npm 使用明确版本。

Electron smoke 保留本地可复核入口。真实客户端、私人 PCAP、密钥、数据库和原始日志不进入公共 CI。工作流存在不代表已运行成功，只有实际运行结果才作为 CI 通过依据。
