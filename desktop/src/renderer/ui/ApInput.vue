<script setup lang="ts">
import { useId } from 'vue'
import { VTextField } from 'vuetify/components'

interface Props {
    modelValue: string
    label: string
    placeholder?: string
    error?: string
    disabled?: boolean
}

withDefaults(defineProps<Props>(), {
    placeholder: '',
    error: '',
    disabled: false,
})

const emit = defineEmits<{
    'update:modelValue': [value: string]
}>()

const fieldId = `ap-input-${useId()}`

function updateValue(value: unknown) {
    emit('update:modelValue', typeof value === 'string' ? value : '')
}
</script>

<template>
    <VTextField
        :id="fieldId"
        :model-value="modelValue"
        :label="label"
        :placeholder="placeholder"
        :error="Boolean(error)"
        :error-messages="error ? [error] : []"
        :disabled="disabled"
        hide-details="auto"
        variant="outlined"
        density="comfortable"
        color="primary"
        @update:model-value="updateValue"
    />
</template>
