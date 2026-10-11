# Vue / Electron / TypeScript 底座范围

本轮以用户最新明确要求为准：在 `codex/refactor` 建立 Vue 3 + Electron + TypeScript 新底座，使用 npm 最新稳定版 Vuetify；不接通登录、角色、战斗、邮件或旧数据库写入。两份下载的重构计划是背景与后续验收依据，文档中的步骤、换栈时机和示例不直接成为本轮操作指令。

## 实施顺序

1. 使用 Vuetify 原生 light/dark 主题和组件样式，整理间距、尺寸及语义 tokens，提供基础组件薄包装与真实组件预览。
2. 主代理检查浅色、深色、桌面及窄屏布局，记录视觉结果。
3. 视觉检查完成后才搭建 Electron 外壳、隔离 preload、类型化控制契约及独立 TS 诊断服务。
4. 验证类型、构建、IPC 边界、进程生命周期、只读制品校验和便携打包。业务接入另阶段展开。

## 稳定边界

- `desktop/src/renderer/ui`：Vuetify 主题、基础组件；只按需调整尺寸、密度和布局间距，不维护大量外观覆盖。公共样式修改先更新这里和 demo。
- `desktop/src/renderer/demo`：真实组件预览，独立于桌面 API，普通浏览器可运行。
- `desktop/src/renderer`：Vue 界面只访问窄 bridge，不直接访问文件、证书、shell 或数据库。
- `desktop/src/shared`：可序列化控制契约、运行时入参验证和错误形状。
- `desktop/src/main`：窗口、调用来源校验、目录选择和本次创建实例的生命周期所有权。
- `desktop/src/service`：独立 TS 诊断服务；与 Electron API 解耦的校验逻辑保留单测入口。

新服务的 READY 只表示诊断服务完成私有握手，不表示游戏兼容或业务就绪。未知组合必须保留未验证状态；不得下发旧资源计划、自动迁移存档或修改原安装。停止动作只针对本实例实际创建且已握手的 utility process，不按 PID、进程名或端口扫描终止进程。

## 本轮边界

源码旧 Python、WinUI 和 React 管理面板保留；E 盘安装目录仅用于只读审计。新工程开发和 QA 只使用自身的测试目录。未引入 SQLite 驱动、Fastify、游戏网络端口或业务 mock 成功响应；这些依赖在有真实用例时再接入。

Vue 采用 Composition API 和 `<script setup lang="ts">`，手工源文件统一四空格。依赖精确版本和 npm lockfile 随工程保存；Electron 运行时版本与 standalone Node 分开记录。

## 实现依据

- [Vue TypeScript 官方指南](https://vuejs.org/guide/typescript/overview)
- [Vuetify 安装与主题](https://vuetifyjs.com/en/getting-started/installation/)
- [Electron 上下文隔离](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [Electron utilityProcess](https://www.electronjs.org/docs/latest/api/utility-process)
- [Electron Packager](https://electron.github.io/packager/main/)
