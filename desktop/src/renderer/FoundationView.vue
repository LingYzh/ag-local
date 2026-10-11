<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue';
import { ApButton, ApCard, ApNotice } from './ui';
import { callDesktop } from './api/desktop';
import type { BundleReport, EnvironmentInfo, FoundationFault, RuntimeStatus } from '../shared/contracts';
import type { ClientInventory } from '../shared/client-contracts';

defineEmits<{ components: [] }>();
const isDark = ref(false);
const environment = ref<EnvironmentInfo | null>(null);
const status = ref<RuntimeStatus | null>(null);
const directory = ref('');
const report = ref<BundleReport | null>(null);
const clientDirectory = ref('');
const clientInventory = ref<ClientInventory | null>(null);
const error = ref<FoundationFault | null>(null);
const busy = ref('');
let polling = false;
let timer: ReturnType<typeof setInterval> | undefined;
let disposed = false;

async function refresh(): Promise<void> {
    if (busy.value || polling || disposed) return;
    polling = true;
    try {
        status.value = await callDesktop('getStatus');
    } catch (cause) {
        if (!disposed) error.value = cause as FoundationFault;
    } finally {
        polling = false;
    }
}

async function operate(action: 'startService' | 'stopService' | 'chooseBundle' | 'inspectBundle'): Promise<void> {
    if (busy.value) return;
    busy.value = action;
    error.value = null;
    try {
        if (action === 'startService' || action === 'stopService') {
            status.value = await callDesktop(action);
        } else if (action === 'chooseBundle') {
            const selection = await callDesktop(action);
            if (selection) {
                directory.value = selection.directory;
                report.value = null;
            }
        } else {
            report.value = await callDesktop(action);
        }
    } catch (cause) {
        error.value = cause as FoundationFault;
    } finally {
        busy.value = '';
        await refresh();
    }
}

onMounted(async () => {
    try {
        environment.value = await callDesktop('getEnvironment');
    } catch (cause) {
        error.value = cause as FoundationFault;
    }
    await refresh();
    if (!disposed) timer = setInterval(() => { void refresh(); }, 2000);
});
onUnmounted(() => { disposed = true; clearInterval(timer); });

function inspectClient(action: 'chooseClient' | 'inspectClient'): void {
    if (busy.value) return;
    busy.value = action;
    error.value = null;
    const operation = action === 'chooseClient'
        ? callDesktop('chooseClient').then(selection => {
            if (selection) {
                clientDirectory.value = selection.directory;
                clientInventory.value = null;
            }
        })
        : callDesktop('inspectClient').then(inventory => { clientInventory.value = inventory; });
    void operation.catch(cause => { error.value = cause as FoundationFault; })
        .finally(() => { busy.value = ''; });
}
</script>

<template>
    <VApp :theme="isDark ? 'dark' : 'light'">
        <VAppBar title="Alpha Persei" density="comfortable" flat border>
            <template #append>
                <VBtn variant="text" @click="$emit('components')">组件预览</VBtn>
                <VBtn variant="text" @click="isDark = !isDark">切换主题</VBtn>
            </template>
        </VAppBar>
        <VMain>
            <VContainer class="py-8" style="max-width: 1120px">
                <h1 class="text-h4 mb-2">客户端兼容接入</h1>
                <p class="text-body-1 text-medium-emphasis mb-6">Vue 3 · Electron · TypeScript</p>
                <ApNotice tone="warning" title="当前大厅验证尚未完成" class="mb-6">
                    先核验当前客户端与匹配协议，再接通登录和大厅。READY 仅表示诊断通道可用。
                </ApNotice>
                <ApNotice v-if="error" tone="danger" :title="error.code" class="mb-6">{{ error.detail }}</ApNotice>
                <VRow>
                    <VCol cols="12" md="5">
                        <ApCard title="运行环境" description="当前桌面进程的实际版本">
                            <VList v-if="environment" density="compact">
                                <VListItem title="Electron" :subtitle="environment.electron" />
                                <VListItem title="Node.js" :subtitle="environment.node" />
                                <VListItem title="平台" :subtitle="`${environment.platform} / ${environment.architecture}`" />
                                <VListItem title="底座版本" :subtitle="environment.appVersion" />
                            </VList>
                            <VProgressLinear v-else indeterminate />
                        </ApCard>
                    </VCol>
                    <VCol cols="12" md="7">
                        <ApCard title="诊断服务" description="桌面进程拥有的独立 TypeScript 服务">
                            <VChip class="mb-4" :color="status?.state === 'READY' ? 'success' : 'secondary'">
                                {{ status?.state ?? '读取中' }}
                            </VChip>
                            <p class="text-body-2 text-medium-emphasis mb-4" style="overflow-wrap: anywhere">
                                实例：{{ status?.instanceId ?? '未启动' }}
                            </p>
                            <ApNotice v-if="status?.lastError" tone="danger" :title="status.lastError.code" class="mb-4">
                                {{ status.lastError.detail }}
                            </ApNotice>
                            <div class="d-flex ga-3 flex-wrap">
                                <ApButton :busy="busy === 'startService'" :disabled="!!busy || status?.state === 'READY'" @click="operate('startService')">启动服务</ApButton>
                                <ApButton variant="secondary" :busy="busy === 'stopService'" :disabled="!!busy || !status?.instanceId" @click="operate('stopService')">停止服务</ApButton>
                            </div>
                        </ApCard>
                    </VCol>
                    <VCol cols="12">
                        <ApCard title="当前客户端" description="只读识别版本和关键文件，核对 scripts64 与当前索引">
                            <p class="text-body-2 mb-4" style="overflow-wrap: anywhere">{{ clientDirectory || '尚未选择客户端目录' }}</p>
                            <div class="d-flex ga-3 flex-wrap mb-4">
                                <ApButton variant="secondary" :busy="busy === 'chooseClient'" :disabled="!!busy" @click="inspectClient('chooseClient')">选择客户端</ApButton>
                                <ApButton :busy="busy === 'inspectClient'" :disabled="!!busy || !clientDirectory || status?.state !== 'READY'" @click="inspectClient('inspectClient')">识别当前材料</ApButton>
                            </div>
                            <template v-if="clientInventory">
                                <ApNotice tone="warning" title="材料已识别，大厅未验证" class="mb-4">
                                    此结果仅核验索引、核心文件和协议脚本；完整资源、SDK 与实际登录仍待验证。
                                </ApNotice>
                                <VList density="compact">
                                    <VListItem title="索引声明版本" :subtitle="`${clientInventory.identity.versionName} · app ${clientInventory.identity.appVersion} / resource ${clientInventory.identity.buildCode}`" />
                                    <VListItem title="资源条目" :subtitle="String(clientInventory.index.entryCount)" />
                                    <VListItem title="索引 SHA-256" :subtitle="clientInventory.index.sha256" />
                                    <VListItem title="scripts64 SHA-256" :subtitle="clientInventory.scripts.sha256" />
                                    <VListItem v-for="candidate in clientInventory.indexCandidates" :key="candidate.path"
                                        :title="candidate.canonicalMatch ? '与当前索引一致' : '其他候选索引'" :subtitle="candidate.path" />
                                </VList>
                            </template>
                        </ApCard>
                    </VCol>
                    <VCol cols="12">
                        <ApCard title="制品检查" description="读取 manifest、校验 SHA-256 与协议引用闭包">
                            <p class="text-body-2 mb-4" style="overflow-wrap: anywhere">{{ directory || '尚未选择制品目录' }}</p>
                            <div class="d-flex ga-3 flex-wrap mb-4">
                                <ApButton variant="secondary" :busy="busy === 'chooseBundle'" :disabled="!!busy" @click="operate('chooseBundle')">选择目录</ApButton>
                                <ApButton :busy="busy === 'inspectBundle'" :disabled="!!busy || !directory || status?.state !== 'READY'" @click="operate('inspectBundle')">执行检查</ApButton>
                            </div>
                            <VTable v-if="report" density="comfortable">
                                <tbody>
                                    <tr><th>制品标识</th><td>{{ report.tupleId }}</td></tr>
                                    <tr><th>清单声明状态</th><td>{{ report.state }}</td></tr>
                                    <tr><th>已核验文件</th><td>{{ report.artifactsVerified }}</td></tr>
                                    <tr><th>制品齐全</th><td>{{ report.manifestComplete ? '是' : '否' }}</td></tr>
                                    <tr><th>业务就绪</th><td>未验证</td></tr>
                                    <tr v-for="issue in report.issues" :key="issue"><th>待补齐</th><td>{{ issue }}</td></tr>
                                </tbody>
                            </VTable>
                        </ApCard>
                    </VCol>
                </VRow>
            </VContainer>
        </VMain>
    </VApp>
</template>
