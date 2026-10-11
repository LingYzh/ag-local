<script setup lang="ts">
import { computed } from 'vue'
import { VChip } from 'vuetify/components'

export type ApBadgeTone = 'neutral' | 'success' | 'warning' | 'danger' | 'accent'

interface Props {
    tone?: ApBadgeTone
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
</script>

<template>
    <VChip
        :color="color"
        variant="tonal"
        size="small"
    >
        <slot />
    </VChip>
</template>
