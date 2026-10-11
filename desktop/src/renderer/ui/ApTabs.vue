<script setup lang="ts">
import { computed, useId } from 'vue'
import { VTab, VTabs } from 'vuetify/components'

export interface ApTabItem {
    id: string
    label: string
}

interface Props {
    items: ApTabItem[]
    modelValue: string
    label?: string
}

const props = withDefaults(defineProps<Props>(), {
    label: '内容标签',
})

const emit = defineEmits<{
    'update:modelValue': [value: string]
}>()

const selectedId = computed({
    get: () => props.modelValue,
    set: (value: string) => emit('update:modelValue', value),
})

const selectedTab = computed(() => {
    return props.items.find((item) => item.id === selectedId.value) ?? props.items[0]
})

const componentId = `ap-tabs-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`
const panelId = `${componentId}-panel`

function tabId(id: string) {
    return `${componentId}-tab-${encodeURIComponent(id)}`
}

defineSlots<{
    default(props: { activeId: string }): unknown
}>()
</script>

<template>
    <div class="ap-tabs">
        <VTabs
            v-model="selectedId"
            color="primary"
            density="comfortable"
            :aria-label="props.label"
        >
            <VTab
                v-for="item in items"
                :key="item.id"
                :id="tabId(item.id)"
                :aria-controls="panelId"
                :value="item.id"
            >
                {{ item.label }}
            </VTab>
        </VTabs>
        <div
            v-if="$slots.default && selectedTab"
            class="ap-tabs__panel"
            :id="panelId"
            role="tabpanel"
            tabindex="0"
            :aria-label="selectedTab.label"
            :aria-labelledby="tabId(selectedTab.id)"
        >
            <slot :active-id="selectedTab.id" />
        </div>
    </div>
</template>
