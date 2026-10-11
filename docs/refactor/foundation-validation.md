# 新底座验收记录

分支：`codex/refactor`。基线提交：`83c03f1d75004ecb9f0ac1484676f6b5181dfa4e`。

范围采用用户明确要求：Vue 3 + Electron + TypeScript 新底座、最新稳定 Vuetify 原生外观、经济型执行子代理；两份计划作为背景参考。公共 UI 先完成主代理视觉检查并记录，之后才实现桌面与系统底座，顺序证据见 `ui-acceptance.md`。

## 已验收

- Vue/Node 两侧 strict 类型检查和生产构建通过。
- Vitest 31 项通过、1 项跳过。跳过项是本机权限不允许创建文件符号链接；目录 junction 逃逸、父目录、UNC、盘符、ADS、设备名、哈希不匹配与协议冲突拒绝检查均已通过。
- Chrome 组件检查通过：1280 / 960 / 390 宽度无横向溢出，浅深主题、输入、页签、键盘焦点均正常，renderer 无错误。预览直接响应磁盘中的生产构建产物，避免本机 Kaspersky 对 HTTP CSP 的注入影响测试。
- Electron 源码构建与 Windows x64 ASAR 便携包各通过 16 项端到端检查：Node 全局隔离、六方法 bridge、生产 CSP、实际运行版本、主进程目录选择、服务身份握手、observed 未验证状态、关闭确认及退出、全新实例重启、已验证自有实例崩溃识别与恢复、真实按钮检查结果、操作锁释放及深色文字语义。
- 便携包从仓库根目录作为工作目录运行，制品路径仍正确。测试 profile 和缓存位于各自 QA 目录，避免不同验证实例争用常用应用缓存。
- 主代理检查真实 Electron 底座的浅色、深色截图：使用 Vuetify 默认组件、颜色与排版工具类，没有新增组件外观覆盖。
- QA 使用 Electron 离屏渲染与明确的隐藏截图选项，避免普通隐藏窗口的合成缓存产生部分更新截图；生产窗口保持正常渲染。主题切换完成后再截图，不把过渡帧视为最终视觉结果。
- 旧安装 schema 只读解析通过：3062 条消息、6892 个字段，SHA-256 `b9101c965ed4f75317aa9c0199e17e5a7d2c3e0c0e23b982217a960b1a6ee79f`。安装目录不写入。

## 交付边界

业务能力未接入；新 READY 只代表诊断服务可用，`businessReady` 始终为 false。5.3.1 fixture 是 observed 占位清单，没有伪造资源哈希或版本兼容结论。旧 Python / WinUI / React 管理面板的跟踪源码未修改。

便携包未签名，也未制作安装器。manifest 校验不替代业务测试、协议编解码、数据库语义检查或制品发布事务。本轮只用自己的 QA 实例执行故障注入，普通运行没有强制终止 RPC。

可复现命令与接口说明见 `../../desktop/README.md`。原始 JSON 测试记录保存在 `desktop/qa`，便携路径和 ASAR 摘要保存在 `desktop/out/latest-package.json`；最终证据副本在本目录 `validation/` 和 `visual-qa/`。
