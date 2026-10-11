<script setup lang="ts">
import { VCard, VCardItem, VCardSubtitle, VCardText, VCardTitle, VDivider } from 'vuetify/components'

interface Props {
    title?: string
    description?: string
}

defineProps<Props>()
</script>

<template>
    <VCard class="ap-card">
        <VCardItem v-if="title || description || $slots.action" class="ap-card__header">
            <VCardTitle v-if="title">{{ title }}</VCardTitle>
            <VCardSubtitle v-if="description">{{ description }}</VCardSubtitle>
            <template #append>
                <slot name="action" />
            </template>
        </VCardItem>
        <VDivider
            v-if="(title || description || $slots.action) && $slots.default"
            class="ap-card__divider"
        />
        <VCardText class="ap-card__body">
            <slot />
        </VCardText>
    </VCard>
</template>
