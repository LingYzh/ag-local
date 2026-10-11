<script setup lang="ts">
import { computed } from 'vue'
import { VAlert } from 'vuetify/components'

export type ApNoticeTone = 'neutral' | 'success' | 'warning' | 'danger' | 'accent'

interface Props {
    tone?: ApNoticeTone
    title: string
}

const props = withDefaults(defineProps<Props>(), {
    tone: 'neutral',
})

const color = computed(() => {
    if (props.tone === 'danger') {
        return 'error'
    }

    if (props.tone === 'accent') {
        return 'primary'
    }

    return props.tone === 'neutral' ? 'secondary' : props.tone
})

const role = computed(() => {
    return props.tone === 'danger' ? 'alert' : 'status'
})
</script>

<template>
    <VAlert
        :color="color"
        variant="tonal"
        density="comfortable"
        :role="role"
        :aria-live="props.tone === 'danger' ? 'assertive' : 'polite'"
    >
        <template #title>{{ title }}</template>
        <slot />
    </VAlert>
</template>
