# 当前客户端大厅采样

目标是保存 app307 / resource321 / v5.3.1 的一次正常登录，以核对网关消息和大厅初始化顺序。普通游戏日志不保证包含这些消息；本机检查时 `LocalLow/yongshi/AetherGazer` 没有 `Player.log`。先开采样，再登录，登录完成后立即停止。

以下步骤由用户在本机操作。代理没有启动采样、登录账号或修改客户端、hosts、证书、代理设置。使用 Windows 自带 Packet Monitor，无须安装 Wireshark。命令依据 [Microsoft pktmon start](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start) 与 [etl2pcap](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-etl2pcap)，并已核对本机命令帮助。

## 1. 登录前

先关闭无关下载和联网程序，确保游戏资源已更新完毕。右键开始菜单，打开 **终端（管理员）**，选择 PowerShell。

先执行以下只读检查：

```powershell
& 'C:\Windows\System32\pktmon.exe' status
& 'C:\Windows\System32\pktmon.exe' filter list
```

仅在状态显示未运行、且没有已有筛选器时继续。若正在采样或有筛选器，把输出告诉代理；不要停止别人的采样或清空已有配置。

在同一个 PowerShell 窗口执行：

```powershell
$captureDir = 'D:\ag-local\desktop\qa\hall-capture-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
if (Test-Path -LiteralPath $captureDir) { throw 'Capture directory already exists' }
New-Item -ItemType Directory -Path $captureDir -ErrorAction Stop | Out-Null
Get-Date -Format o | Set-Content -LiteralPath (Join-Path $captureDir 'start-time.txt') -Encoding UTF8
& 'C:\Windows\System32\pktmon.exe' start --capture --comp nics --pkt-size 0 --file-size 512 --log-mode circular --file-name (Join-Path $captureDir 'login.etl')
if ($LASTEXITCODE -ne 0) { throw 'Capture did not start. Do not proceed with the stop command.' }
& 'C:\Windows\System32\pktmon.exe' status
$captureDir
```

确认采样已启动，状态中的日志文件是刚创建的 `login.etl`，记住输出目录。保持这个终端打开。

## 2. 正常登录

通过你平常使用的启动器启动游戏并登录。若启动器要求下载新的更新，先不要继续这次采样，告知代理重新登记版本。进入大厅后等待约 15 秒，记录进入大厅的时间。第一份样本只做登录；不需要进入战斗或领取奖励。登录失败也可以保留样本，记录停在哪一步。

采样尽量控制在 2–3 分钟内；环形文件达到上限会覆盖最早的数据。截图可另外保存至同一目录，避免包含账号信息。不要把原始包或令牌贴进聊天。

## 3. 停止与保存

仅在你刚才确实成功开启采样、且没有其他人替换采样会话的情况下，在原来的管理员 PowerShell 窗口执行：

```powershell
& 'C:\Windows\System32\pktmon.exe' status
```

再次确认状态中的日志路径仍然是 `$captureDir` 下的 `login.etl`，再执行：

```powershell
Get-Date -Format o | Set-Content -LiteralPath (Join-Path $captureDir 'stop-time.txt') -Encoding UTF8
& 'C:\Windows\System32\pktmon.exe' stop
if ($LASTEXITCODE -ne 0) { throw 'Capture stop failed. Keep the ETL and report the error.' }
& 'C:\Windows\System32\pktmon.exe' etl2pcap (Join-Path $captureDir 'login.etl') --out (Join-Path $captureDir 'login.pcapng')
if ($LASTEXITCODE -ne 0) { throw 'Conversion failed. Keep the ETL and report the error.' }
Get-ChildItem -LiteralPath $captureDir -File | Select-Object Name,Length
$captureDir
```

随后告诉代理 **这个本地目录路径、登录是否成功、进入大厅的大致时间**。目录在被 Git 忽略的 `desktop/qa` 内；原始文件留在本机。代理按本次授权仅提取与游戏相关的记录，生成脱敏的消息编号、方向、顺序及字段结构证据。

## 证据限制

- 网卡采样记录 TCP 数据，不保证能解读加密内容；HTTPS SDK 的请求/响应正文通常仍然加密。不能把网络连通误判成 SDK 契约已恢复。
- `--comp nics` 针对正常远端登录。若走 VPN、虚拟网卡或本地回环且样本不全，需要据实际连接调整采样点。
- 当前没有证据表明 321 沿用旧协议帧格式；分析时需先核验分帧与 schema，不能直接套用旧版规则。
- 原始流量可能含会话凭据以及其他联网程序的数据，避免上传或提交。脱敏输出不保留可用凭据或完整原始载荷。
- 本次正常登录样本只补充 SP03，不能替代隔离 Python 服务下的大厅、退出及重登验收。
- 分析前再次核验客户端索引及 scripts64 哈希；如果正常登录期间资源发生变化，按新组合重新关联，不能把样本挂到旧的 321 制品上。

如果只需要辅助错误日志，Unity 支持通过 `-logFile` 指定日志位置，见 [Unity 2022.3 文档](https://docs.unity3d.com/cn/2022.3/Manual/PlayerCommandLineArguments.html)。但目前尚未核验该游戏启动器是否传递此参数，也未确认发行客户端会打印协议信息，因此不能把它作为本次完整轨迹的采样方案。
