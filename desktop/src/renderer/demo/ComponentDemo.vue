<script setup lang="ts">
import { ref } from 'vue'
import { VApp } from 'vuetify/components'
import { ApBadge, ApButton, ApCard, ApEmptyState, ApInput, ApNotice, ApShell, ApTabs } from '../ui'
import type { ApBadgeTone, ApTabItem } from '../ui'

const isDark = ref(false)
const mobileNavOpen = ref(false)
const activeSection = ref('foundation')
const activeTab = ref('overview')
const directory = ref('D:\\示例数据\\v5_server')
const actionMessage = ref('点击按钮查看交互反馈。')

const navigation = [
    { id: 'foundation', label: '基础组件' },
    { id: 'navigation', label: '导航组件' },
    { id: 'states', label: '界面状态' },
    { id: 'tokens', label: '设计令牌' },
]

const tabs: ApTabItem[] = [
    { id: 'overview', label: '概览' },
    { id: 'connection', label: '连接' },
    { id: 'activity', label: '活动' },
]

const tabDescriptions: Record<string, string> = {
    overview: '概览标签展示内容区域与选中状态。',
    connection: '连接标签切换到另一组示例内容。',
    activity: '活动标签可通过鼠标、触摸或键盘切换。',
}

const badgeSamples: Array<{ label: string; note: string; tone: ApBadgeTone }> = [
    { label: '中性', note: '默认状态', tone: 'neutral' },
    { label: '成功样例', note: '语义提示', tone: 'success' },
    { label: '注意样例', note: '需要关注', tone: 'warning' },
    { label: '错误样例', note: '需要处理', tone: 'danger' },
    { label: '强调', note: '品牌色', tone: 'accent' },
    { label: '处理中样例', note: '样式演示', tone: 'accent' },
]

const colorTokens = [
    { label: '页面底色', token: '--ap-color-page' },
    { label: '卡片表面', token: '--ap-color-surface' },
    { label: '主文本', token: '--ap-color-text' },
    { label: '次文本', token: '--ap-color-muted' },
    { label: '分隔线', token: '--ap-color-border' },
    { label: '青蓝强调', token: '--ap-color-accent' },
    { label: '成功', token: '--ap-color-success' },
    { label: '警告', token: '--ap-color-warning' },
    { label: '错误', token: '--ap-color-danger' },
]

const spacingTokens = [
    { label: '4', token: '--ap-space-1' },
    { label: '8', token: '--ap-space-2' },
    { label: '12', token: '--ap-space-3' },
    { label: '16', token: '--ap-space-4' },
    { label: '24', token: '--ap-space-5' },
    { label: '32', token: '--ap-space-6' },
]

function selectNavigation(id: string) {
    activeSection.value = id
    mobileNavOpen.value = false
}

function announceAction(message: string) {
    actionMessage.value = message
}
</script>

<template>
    <VApp class="demo-app" :theme="isDark ? 'dark' : 'light'">
        <ApShell class="demo-shell">
            <template #sidebar>
                <div class="demo-sidebar">
                    <div class="demo-sidebar__brand-row">
                        <div class="demo-brand">
                            <span class="demo-brand__mark" aria-hidden="true">AP</span>
                            <span class="demo-brand__name">Alpha Persei</span>
                        </div>
                        <ApButton
                            class="demo-mobile-toggle"
                            variant="ghost"
                            :aria-expanded="mobileNavOpen"
                            aria-controls="demo-navigation"
                            @click="mobileNavOpen = !mobileNavOpen"
                        >
                            {{ mobileNavOpen ? '收起导航' : '导航' }}
                        </ApButton>
                    </div>

                    <p class="demo-sidebar__eyebrow">界面基础库</p>
                    <nav
                        id="demo-navigation"
                        class="demo-nav"
                        :class="{ 'demo-nav--open': mobileNavOpen }"
                        aria-label="组件文档导航"
                    >
                        <a
                            v-for="item in navigation"
                            :key="item.id"
                            class="demo-nav__item"
                            :class="{ 'demo-nav__item--active': activeSection === item.id }"
                            :href="`#${item.id}`"
                            :aria-current="activeSection === item.id ? 'page' : undefined"
                            @click="selectNavigation(item.id)"
                        >
                            <span class="demo-nav__dot" aria-hidden="true" />
                            {{ item.label }}
                        </a>
                    </nav>

                    <div class="demo-sidebar__note">
                        <ApBadge tone="neutral">静态预览</ApBadge>
                        <p>组件状态与交互示例，不连接服务端。</p>
                    </div>
                </div>
            </template>

            <template #header>
                <div class="demo-topbar">
                    <span class="demo-topbar__title">界面基础库</span>
                    <div class="demo-topbar__actions">
                        <ApBadge tone="accent">Vue 3 / TypeScript</ApBadge>
                        <ApButton
                            class="demo-theme-toggle"
                            variant="ghost"
                            :aria-pressed="isDark"
                            :aria-label="isDark ? '切换到浅色主题' : '切换到深色主题'"
                            @click="isDark = !isDark"
                        >
                            <span aria-hidden="true">{{ isDark ? '☼' : '☾' }}</span>
                            <span class="demo-theme-toggle__label">{{ isDark ? '浅色' : '深色' }}</span>
                        </ApButton>
                    </div>
                </div>
            </template>

            <div class="demo-content">
                <section id="foundation" class="demo-page-heading" aria-labelledby="demo-page-title">
                    <div>
                        <p class="demo-kicker">Alpha Persei · Desktop</p>
                        <h1 id="demo-page-title">统一组件，先于业务。</h1>
                        <p class="demo-page-heading__description">
                            验证样式、状态与交互，让后续桌面页面共享同一套基础。
                        </p>
                    </div>
                    <ApBadge tone="neutral">组件预览</ApBadge>
                </section>

                <div class="demo-section-heading">
                    <div>
                        <h2>基础组件</h2>
                        <p>按钮、表单与状态标签使用统一的尺寸和语义色。</p>
                    </div>
                </div>

                <div class="demo-card-grid">
                    <ApCard title="按钮" description="清晰的主次关系，以及明确的忙碌和禁用反馈。">
                        <div class="demo-stack">
                            <div class="demo-control-row">
                                <ApButton @click="announceAction('主按钮已触发示例操作。')">
                                    主操作
                                </ApButton>
                                <ApButton variant="secondary" @click="announceAction('次要按钮已触发示例操作。')">
                                    次要操作
                                </ApButton>
                            </div>
                            <div class="demo-control-row">
                                <ApButton variant="ghost" @click="announceAction('文字按钮已触发示例操作。')">
                                    文字按钮
                                </ApButton>
                                <ApButton variant="danger" @click="announceAction('危险按钮已触发示例操作。')">
                                    危险操作
                                </ApButton>
                            </div>
                            <div class="demo-control-row">
                                <ApButton :busy="true">处理中</ApButton>
                                <ApButton :disabled="true">不可用</ApButton>
                            </div>
                            <p class="demo-feedback" role="status" aria-live="polite">
                                {{ actionMessage }}
                            </p>
                        </div>
                    </ApCard>

                    <ApCard title="目录输入" description="带标签、占位提示和错误反馈的表单控件。">
                        <div class="demo-stack">
                            <ApInput
                                v-model="directory"
                                label="服务端目录（示例）"
                                placeholder="例如：D:\服务端目录"
                                error="示例错误：路径尚未验证。"
                            />
                            <p class="demo-field-note">
                                当前内容是可编辑的测试数据，不会读取或修改此路径。
                            </p>
                        </div>
                    </ApCard>

                    <ApCard title="状态徽章" description="用短标签传达不同语义；以下均为视觉样例。">
                        <div class="demo-badge-grid">
                            <div v-for="badge in badgeSamples" :key="badge.label" class="demo-badge-sample">
                                <ApBadge :tone="badge.tone">{{ badge.label }}</ApBadge>
                                <span>{{ badge.note }}</span>
                            </div>
                        </div>
                    </ApCard>

                    <ApCard title="卡片组合" description="可组合标题、说明、操作区和内容槽。">
                        <template #action>
                            <ApBadge tone="neutral">测试数据</ApBadge>
                        </template>
                        <div class="demo-data-list">
                            <div class="demo-data-row">
                                <span>运行环境</span>
                                <strong>Windows · 示例</strong>
                            </div>
                            <div class="demo-data-row">
                                <span>服务状态</span>
                                <ApBadge tone="neutral">未连接</ApBadge>
                            </div>
                            <div class="demo-data-row">
                                <span>最近活动</span>
                                <strong>—</strong>
                            </div>
                        </div>
                    </ApCard>
                </div>

                <section id="navigation" class="demo-section" aria-labelledby="navigation-title">
                    <div class="demo-section-heading">
                        <div>
                            <h2 id="navigation-title">导航组件</h2>
                            <p>标签切换支持鼠标、触摸和键盘操作。</p>
                        </div>
                    </div>
                    <ApCard title="Tabs" description="选中项由父级状态控制，内容通过默认槽提供。">
                        <ApTabs v-model="activeTab" :items="tabs" label="标签组件预览">
                            <template #default="{ activeId }">
                                <div class="demo-tab-panel">
                                    <ApBadge tone="accent">{{ tabs.find((tab) => tab.id === activeId)?.label }}</ApBadge>
                                    <p>{{ tabDescriptions[activeId] }}</p>
                                    <span>当前示例：{{ activeId }}</span>
                                </div>
                            </template>
                        </ApTabs>
                    </ApCard>
                </section>

                <section id="states" class="demo-section" aria-labelledby="states-title">
                    <div class="demo-section-heading">
                        <div>
                            <h2 id="states-title">界面状态</h2>
                            <p>明确呈现暂无数据和需要注意的情况。</p>
                        </div>
                    </div>
                    <div class="demo-card-grid demo-card-grid--states">
                        <ApCard title="空状态" description="当前演示不伪装服务正在运行。">
                            <ApEmptyState
                                title="暂无服务"
                                description="当前预览只展示组件状态；连接真实服务后，这里再呈现实际运行信息。"
                            >
                                <ApButton variant="secondary" @click="announceAction('此按钮只触发本地预览反馈。')">
                                    了解空状态
                                </ApButton>
                            </ApEmptyState>
                        </ApCard>
                        <ApCard title="提示与错误" description="通知使用柔和底色，文字保持足够对比。">
                            <div class="demo-stack">
                                <ApNotice tone="danger" title="示例错误状态">
                                    这是错误样式预览，没有发生真实连接或路径检查。
                                </ApNotice>
                                <ApNotice tone="warning" title="需要注意">
                                    生产页面应显示经过确认的实际状态。
                                </ApNotice>
                                <ApNotice tone="accent" title="演示环境">
                                    所有示例值均为静态测试数据。
                                </ApNotice>
                            </div>
                        </ApCard>
                    </div>
                </section>

                <section id="tokens" class="demo-section" aria-labelledby="tokens-title">
                    <div class="demo-section-heading">
                        <div>
                            <h2 id="tokens-title">设计令牌</h2>
                    <p>颜色由 Vuetify 主题提供，间距使用少量 CSS tokens。</p>
                        </div>
                        <ApBadge tone="neutral">{{ isDark ? '深色主题' : '浅色主题' }}</ApBadge>
                    </div>

                    <div class="demo-card-grid demo-card-grid--tokens">
                        <ApCard title="语义色" description="切换右上角主题，可查看浅色与深色配套值。">
                            <div class="demo-token-grid">
                                <div v-for="token in colorTokens" :key="token.token" class="demo-token-swatch">
                                    <span
                                        class="demo-token-swatch__color"
                                        :class="{ 'demo-token-swatch__color--outlined': token.token === '--ap-color-surface' || token.token === '--ap-color-page' }"
                                        :style="{ backgroundColor: `var(${token.token})` }"
                                        aria-hidden="true"
                                    />
                                    <span class="demo-token-swatch__label">{{ token.label }}</span>
                                    <code>{{ token.token }}</code>
                                </div>
                            </div>
                        </ApCard>

                        <ApCard title="间距" description="基础间距按 4、8、12、16、24、32 px 递增。">
                            <div class="demo-spacing-list">
                                <div v-for="token in spacingTokens" :key="token.token" class="demo-spacing-row">
                                    <span class="demo-spacing-row__value">{{ token.label }} px</span>
                                    <span class="demo-spacing-row__track">
                                        <span :style="{ width: `var(${token.token})` }" />
                                    </span>
                                    <code>{{ token.token }}</code>
                                </div>
                            </div>
                        </ApCard>

                        <ApCard title="组件应用示例" description="静态测试数据，不代表真实系统状态。">
                            <div class="demo-applied-card">
                                <div class="demo-applied-card__heading">
                                    <div>
                                        <h3>Alpha Persei Desktop</h3>
                                        <p>示例工作区</p>
                                    </div>
                                    <ApBadge tone="neutral">演示</ApBadge>
                                </div>
                                <div class="demo-applied-card__details">
                                    <span>服务状态</span>
                                    <ApBadge tone="neutral">未连接</ApBadge>
                                    <span>数据来源</span>
                                    <strong>静态预览</strong>
                                    <span>目录</span>
                                    <strong>未验证</strong>
                                </div>
                            </div>
                        </ApCard>

                        <ApCard title="交互说明" description="组件可以独立组合，也能沿用统一的状态语义。">
                            <ApNotice tone="success" title="可复用基础">
                                按钮、输入、卡片、徽章、标签、空状态和通知都使用同一组主题变量。
                            </ApNotice>
                        </ApCard>
                    </div>
                </section>
            </div>

            <template #footer>
                <div class="demo-footer">
                    <span>Alpha Persei · 桌面界面基础库</span>
                    <span>静态组件预览</span>
                </div>
            </template>
        </ApShell>
    </VApp>
</template>

<style scoped>
.demo-app {
    min-height: 100vh;
}

.demo-sidebar {
    display: flex;
    min-height: calc(100vh - var(--ap-space-6) - var(--ap-space-6));
    flex-direction: column;
    gap: var(--ap-space-4);
}

.demo-sidebar__brand-row,
.demo-brand,
.demo-topbar,
.demo-topbar__actions,
.demo-page-heading,
.demo-section-heading,
.demo-control-row,
.demo-badge-sample,
.demo-data-row,
.demo-applied-card__heading,
.demo-footer {
    display: flex;
    align-items: center;
}

.demo-sidebar__brand-row,
.demo-topbar,
.demo-page-heading,
.demo-section-heading,
.demo-data-row,
.demo-footer {
    justify-content: space-between;
}

.demo-sidebar__brand-row,
.demo-brand,
.demo-topbar,
.demo-topbar__actions,
.demo-page-heading,
.demo-section-heading,
.demo-control-row,
.demo-badge-sample,
.demo-data-row,
.demo-applied-card__heading,
.demo-footer {
    gap: var(--ap-space-3);
}

.demo-brand {
    min-width: 0;
}

.demo-sidebar__eyebrow {
    margin: var(--ap-space-4) 0 0;
}

.demo-nav,
.demo-sidebar__note,
.demo-content,
.demo-section,
.demo-stack,
.demo-data-list,
.demo-token-swatch,
.demo-spacing-list {
    display: grid;
    gap: var(--ap-space-3);
}

.demo-nav__item {
    display: flex;
    min-height: 40px;
    align-items: center;
    gap: var(--ap-space-3);
    padding-inline: var(--ap-space-3);
    color: var(--ap-color-muted);
    text-decoration: none;
}

.demo-nav__item--active {
    color: var(--ap-color-accent);
}

.demo-nav__dot {
    width: 8px;
    height: 8px;
    flex: 0 0 auto;
    border-radius: 50%;
    background: currentColor;
}

.demo-sidebar__note {
    justify-items: start;
    margin-top: auto;
}

.demo-sidebar__note p,
.demo-page-heading p,
.demo-section-heading p,
.demo-tab-panel p,
.demo-feedback,
.demo-field-note {
    margin: 0;
}

.demo-mobile-toggle {
    display: none;
}

.demo-topbar {
    min-height: 64px;
    padding: var(--ap-space-3) var(--ap-space-6);
}

.demo-topbar__actions {
    flex-wrap: wrap;
}

.demo-content {
    max-width: 1248px;
    margin-inline: auto;
    padding: var(--ap-space-6);
}

.demo-page-heading {
    align-items: flex-start;
}

.demo-page-heading > div,
.demo-section-heading > div {
    min-width: 0;
}

.demo-card-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    align-items: start;
    gap: var(--ap-space-4);
}

.demo-section-heading {
    align-items: flex-start;
}

.demo-feedback,
.demo-field-note,
.demo-token-swatch code,
.demo-spacing-row code,
.demo-spacing-row__value {
    color: var(--ap-color-muted);
}

.demo-badge-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--ap-space-3);
}

.demo-badge-sample,
.demo-data-row {
    min-width: 0;
    justify-content: space-between;
}

.demo-badge-sample > span:last-child,
.demo-data-row > span:first-child {
    color: var(--ap-color-muted);
}

.demo-tab-panel {
    display: grid;
    justify-items: start;
    gap: var(--ap-space-2);
}

.demo-token-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: var(--ap-space-3);
}

.demo-token-swatch {
    min-width: 0;
}

.demo-token-swatch__color {
    display: block;
    width: 100%;
    height: var(--ap-token-swatch-height);
    border: 1px solid transparent;
}

.demo-token-swatch__color--outlined {
    border-color: var(--ap-color-border);
}

.demo-token-swatch__label,
.demo-token-swatch code,
.demo-spacing-row code {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.demo-spacing-row {
    display: grid;
    grid-template-columns: var(--ap-token-spacing-label-width) minmax(0, 1fr) var(--ap-token-spacing-name-width);
    align-items: center;
    gap: var(--ap-space-2);
}

.demo-spacing-row__track {
    display: flex;
    height: var(--ap-space-3);
    align-items: center;
}

.demo-spacing-row__track > span {
    display: block;
    height: var(--ap-space-2);
    background: var(--ap-color-accent);
}

.demo-applied-card {
    display: grid;
    gap: var(--ap-space-4);
}

.demo-applied-card__heading {
    justify-content: space-between;
    align-items: flex-start;
}

.demo-applied-card__heading h3,
.demo-applied-card__heading p {
    margin: 0;
}

.demo-applied-card__details {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    gap: var(--ap-space-2) var(--ap-space-3);
}

.demo-footer {
    justify-content: space-between;
    padding: var(--ap-space-4) var(--ap-space-6);
}

@media (max-width: 960px) {
    .demo-content {
        padding: var(--ap-space-5);
    }

    .demo-card-grid {
        gap: var(--ap-space-3);
    }
}

@media (max-width: 720px) {
    .demo-card-grid {
        grid-template-columns: minmax(0, 1fr);
    }

    .demo-content {
        gap: var(--ap-space-5);
        padding: var(--ap-space-4);
    }
}

@media (max-width: 640px) {
    .demo-sidebar {
        min-height: 0;
    }

    .demo-sidebar__eyebrow,
    .demo-sidebar__note {
        display: none;
    }

    .demo-mobile-toggle {
        display: inline-flex;
    }

    .demo-nav {
        display: none;
        margin-top: var(--ap-space-3);
    }

    .demo-nav--open {
        display: grid;
    }

    .demo-topbar {
        min-height: 0;
        padding: var(--ap-space-3) var(--ap-space-4);
    }

    .demo-topbar__actions {
        gap: var(--ap-space-2);
    }

    .demo-theme-toggle__label {
        display: none;
    }

    .demo-page-heading,
    .demo-section-heading {
        align-items: flex-start;
        flex-direction: column;
    }

    .demo-token-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .demo-spacing-row {
        grid-template-columns: var(--ap-token-spacing-label-width) minmax(0, 1fr);
    }

    .demo-spacing-row code {
        display: none;
    }

    .demo-footer {
        flex-direction: column;
        padding: var(--ap-space-3) var(--ap-space-4);
    }
}
</style>