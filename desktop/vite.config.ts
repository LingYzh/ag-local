import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import vuetify from 'vite-plugin-vuetify';
import { fileURLToPath } from 'node:url';

export default defineConfig({
    root: fileURLToPath(new URL('./src/renderer', import.meta.url)),
    base: './',
    plugins: [vue(), vuetify({ autoImport: true }), {
        name: 'desktop-production-csp',
        apply: 'build',
        transformIndexHtml(html) {
            return html.replace("connect-src 'self' ws://127.0.0.1:5173", "connect-src 'none'")
                .replace("frame-src 'self'", "frame-src 'none'");
        }
    }],
    server: {
        host: '127.0.0.1',
        port: 5173,
        strictPort: true
    },
    build: {
        outDir: fileURLToPath(new URL('./dist/renderer', import.meta.url)),
        emptyOutDir: true
    }
});
