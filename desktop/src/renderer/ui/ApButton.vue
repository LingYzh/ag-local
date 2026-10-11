<script setup lang="ts">
import { computed } from 'vue'
import { VBtn } from 'vuetify/components'

export type ApButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'

interface Props {
    variant?: ApButtonVariant
    busy?: boolean
    disabled?: boolean
}

const props = withDefaults(defineProps<Props>(), {
    variant: 'primary',
    busy: false,
    disabled: false,
})

const emit = defineEmits<{
    click: [event: MouseEvent]
}>()

const color = computed(() => {
    if (props.variant === 'danger') {
        return 'error'
    }

    if (props.variant === 'secondary') {
        return 'secondary'
    }

    return 'primary'
})

const vuetifyVariant = computed(() => {
    if (props.variant === 'secondary') {
        return 'outlined'
    }

    if (props.variant === 'ghost') {
        return 'text'
    }

    return 'flat'
})

function handleClick(event: MouseEvent) {
    if (props.busy || props.disabled) {
        return
    }

    emit('click', event)
}
</script>

<template>
    <VBtn
        type="button"
        :color="color"
        :variant="vuetifyVariant"
        :loading="props.busy"
        :disabled="props.disabled || props.busy"
        :aria-busy="props.busy"
        @click="handleClick"
    >
        <slot />
    </VBtn>
</template>
