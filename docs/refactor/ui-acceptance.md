# 基础组件视觉验收

验收时间：2026-10-11 16:36（UTC+8）。验收人：主代理。范围：真实 Vue 组件 demo，未接入服务端。

依据用户最终要求，采用 Vuetify 4.2.4 原生 light/dark 主题、组件表面、层级、状态色和输入样式；主题颜色只通过 Vuetify 的语义变量引用。基础组件薄包装处理 props、slots 和 busy 锁，不覆盖按钮、卡片、徽章、输入和提示组件的原生外观；只按需调整尺寸、密度及布局。

## 结果

- 主代理实际查看浅色、深色、窄屏截图，文本可读，卡片及提示层级一致，无重叠和横向溢出。
- 1280、960、390 像素宽度检查通过；主题切换、输入双向绑定、Tabs 选中状态和键盘焦点通过。
- renderer 无 console error 和未捕获异常。截图禁用动画，避免把主题切换中间帧当作最终样式。
- `npm run check:ui`、`npm run build:ui`、`npm run smoke:ui` 通过。

此记录满足本轮进入桌面外壳与 TS 系统底座实现的 UI 先行门槛。它是主代理视觉检查，不冒充用户对界面的最终确认；后续仍可按用户反馈调整，且共用样式修改必须先改 UI 库和 demo。

## 预览与证据

源码：`desktop/src/renderer/demo/ComponentDemo.vue`。在 `desktop` 运行 `npm run dev:ui`；普通浏览器仅打开真实组件预览，不获得桌面权限。

- [浅色截图](visual-qa/components-light.png)
- [深色截图](visual-qa/components-dark.png)
- [窄屏截图](visual-qa/components-mobile.png)

本轮只验收组件样式与交互，不包含登录、大厅、玩法、数据库或官方客户端兼容结果。
