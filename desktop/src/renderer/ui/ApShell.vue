<template>
    <div class="ap-shell">
        <aside v-if="$slots.sidebar" class="ap-shell__sidebar" aria-label="应用导航">
            <slot name="sidebar" />
        </aside>
        <div class="ap-shell__content">
            <header v-if="$slots.header" class="ap-shell__header">
                <slot name="header" />
            </header>
            <main class="ap-shell__main">
                <slot />
            </main>
            <footer v-if="$slots.footer" class="ap-shell__footer">
                <slot name="footer" />
            </footer>
        </div>
    </div>
</template>
