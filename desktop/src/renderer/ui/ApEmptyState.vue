<script setup lang="ts">
import { VEmptyState } from 'vuetify/components'

interface Props {
    title: string
    description?: string
}

defineProps<Props>()
</script>

<template>
    <VEmptyState
        class="ap-empty-state"
        :title="title"
        :text="description"
        aria-live="polite"
    >
        <template v-if="$slots.default" #actions>
            <slot />
        </template>
    </VEmptyState>
</template>
