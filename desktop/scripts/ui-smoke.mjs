import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { extname, relative, resolve } from 'node:path';
import { build } from 'vite';
import { chromium } from 'playwright';

const root = fileURLToPath(new URL('..', import.meta.url));
const output = resolve(root, 'qa');
await mkdir(output, { recursive: true });
await build({ configFile: resolve(root, 'vite.config.ts') });
const bundle = resolve(root, 'dist/renderer');
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const errors = [];
const results = [];
try {
    const page = await browser.newPage();
    // Fulfill from disk before network transport: local HTTP antivirus injection must
    // not rewrite the built CSP. This creates no listener and contacts no remote site.
    await page.route('**/*', async route => {
        try {
            const url = new URL(route.request().url());
            if (url.origin !== 'http://ap-preview.local') return route.abort();
            const pathname = decodeURIComponent(url.pathname);
            const file = resolve(bundle, `.${pathname === '/' ? '/index.html' : pathname}`);
            if (relative(bundle, file).startsWith('..')) return route.abort();
            const mime = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
            await route.fulfill({ status: 200, contentType: mime[extname(file)] || 'application/octet-stream', body: await readFile(file) });
        } catch {
            await route.fulfill({ status: 404, body: '' });
        }
    });
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => {
        if (message.type() === 'error') errors.push(message.text());
    });
    await page.goto('http://ap-preview.local', { waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: '统一组件，先于业务。' }).waitFor();
    for (const width of [1280, 960, 390]) {
        await page.setViewportSize({ width, height: 960 });
        await page.screenshot({ path: resolve(output, `ui-light-${width}.png`), fullPage: true, animations: 'disabled' });
        const dimensions = await page.evaluate(() => ({
            body: document.documentElement.scrollWidth,
            viewport: window.innerWidth
        }));
        assert(dimensions.body <= dimensions.viewport, `Horizontal overflow at ${width}px`);
        results.push({ width, overflow: false });
    }
    await page.setViewportSize({ width: 1280, height: 960 });
    const themeButton = page.getByRole('button', { name: /深色|浅色|主题/ }).first();
    await themeButton.click();
    await page.screenshot({ path: resolve(output, 'ui-dark-1280.png'), fullPage: true, animations: 'disabled' });
    const editable = page.getByRole('textbox').first();
    await editable.fill('D:/Workspace/Client');
    assert.equal(await editable.inputValue(), 'D:/Workspace/Client');
    const tabs = page.getByRole('tab');
    assert(await tabs.count() >= 2);
    await tabs.nth(1).click();
    assert.equal(await tabs.nth(1).getAttribute('aria-selected'), 'true');
    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(() => document.activeElement === document.body), false);
    assert.deepEqual(errors, [], 'Renderer errors');
    await writeFile(resolve(output, 'ui-smoke.json'), JSON.stringify({
        at: new Date().toISOString(), results, errors,
        interactions: ['theme', 'v-model input', 'tabs', 'keyboard focus']
    }, null, 4));
    console.log('UI preview passed: 1280/960/390px, theme, input, tabs and keyboard focus.');
} finally {
    await browser.close();
}
