<script setup lang="ts">
import { ref } from 'vue';
import ComponentDemo from './demo/ComponentDemo.vue';
import FoundationView from './FoundationView.vue';

const desktop = !!window.apDesktop;
const components = ref(!desktop || window.location.hash === '#components');
</script>

<template>
    <FoundationView v-if="!components" @components="components = true" />
    <template v-else>
        <VBtn v-if="desktop" class="ma-4" variant="outlined" @click="components = false">返回底座</VBtn>
        <ComponentDemo />
    </template>
</template>
