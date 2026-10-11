import { mkdir, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import type { BrowserWindow } from 'electron';
import type { ServiceSupervisor } from './service-supervisor';
import type { BundleReport, EnvironmentInfo, Result, RuntimeStatus } from '../shared/contracts';
import type { ClientInventory } from '../shared/client-contracts';

interface SmokeOptions {
    output: string;
    fixture: string;
    crashOwnedChild: () => Promise<void>;
}

export async function runDesktopSmoke(window: BrowserWindow, supervisor: ServiceSupervisor, options: SmokeOptions): Promise<void> {
    if (!isAbsolute(options.output)) throw new Error('Smoke output must be absolute');
    await mkdir(options.output, { recursive: true });
    const checks: string[] = [];
    function check(condition: unknown, label: string): void {
        if (!condition) throw new Error(`Smoke failed: ${label}`);
        checks.push(label);
    }
    async function invoke<T>(method: string): Promise<T> {
        const result: Result<T> = await window.webContents.executeJavaScript(`window.apDesktop.${method}()`);
        if (!result.ok) throw new Error(`${result.error.code}: ${result.error.detail}`);
        return result.value;
    }
    const isolation = await window.webContents.executeJavaScript(`({
        require: typeof require, process: typeof process,
        methods: Object.keys(window.apDesktop).sort(), title: document.querySelector('h1')?.textContent,
        csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.getAttribute('content')
    })`);
    check(isolation.require === 'undefined' && isolation.process === 'undefined', 'sandboxed renderer has no Node globals');
    check(isolation.methods.join(',') === 'chooseBundle,chooseClient,getEnvironment,getStatus,inspectBundle,inspectClient,startService,stopService', 'bridge exposes eight semantic methods');
    check(isolation.title === '客户端兼容接入', 'compatibility view rendered');
    check(isolation.csp.includes("connect-src 'none';") && isolation.csp.includes("frame-src 'none'"), 'production CSP blocks network and embedded frames');
    const environment = await invoke<EnvironmentInfo>('getEnvironment');
    check(environment.mode === 'foundation' && !!environment.electron, 'actual Electron environment over IPC');
    const missing = await window.webContents.executeJavaScript('window.apDesktop.inspectBundle()');
    check(!missing.ok && missing.error.code === 'BUNDLE_NOT_SELECTED', 'inspection requires main-process directory selection');
    const noClient = await window.webContents.executeJavaScript('window.apDesktop.inspectClient()');
    check(!noClient.ok && noClient.error.code === 'CLIENT_NOT_SELECTED', 'client inventory requires native directory selection');
    await window.webContents.executeJavaScript("Array.from(document.querySelectorAll('button')).find(button => button.textContent?.trim() === '选择目录')?.click()");
    const selectedDeadline = Date.now() + 3000;
    while (!(await window.webContents.executeJavaScript('document.body.textContent.includes("fixtures")')) && Date.now() < selectedDeadline) {
        await new Promise(resolve => setTimeout(resolve, 25));
    }
    check(await window.webContents.executeJavaScript('document.body.textContent.includes("fixtures")'), 'directory selection button uses semantic IPC');
    const first = await invoke<RuntimeStatus>('startService');
    check(first.state === 'READY' && !first.businessReady && !!first.instanceId, 'private child reports diagnostic READY');
    const report = await invoke<BundleReport>('inspectBundle');
    check(report.state === 'observed' && !report.manifestComplete && !report.businessReady, 'observed fixture cannot claim business readiness');
    const stopped = await invoke<RuntimeStatus>('stopService');
    check(stopped.state === 'STOPPED', 'shutdown acknowledges and child exits');
    const second = await invoke<RuntimeStatus>('startService');
    check(second.state === 'READY' && second.instanceId !== first.instanceId, 'restart creates a fresh identity');
    await options.crashOwnedChild();
    const deadline = Date.now() + 5000;
    while (supervisor.getStatus().state !== 'FAILED' && Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, 25));
    }
    check(supervisor.getStatus().state === 'FAILED', 'owned child crash detected');
    const recovered = await invoke<RuntimeStatus>('startService');
    check(recovered.state === 'READY' && recovered.instanceId !== second.instanceId, 'restart after crash');
    await invoke<BundleReport>('inspectBundle');
    // Wait for the actual view's status polling before clicking its inspection button.
    const renderDeadline = Date.now() + 4000;
    while (!(await window.webContents.executeJavaScript("Array.from(document.querySelectorAll('button')).some(button => button.textContent?.trim() === '执行检查' && !button.disabled)")) && Date.now() < renderDeadline) {
        await new Promise(resolve => setTimeout(resolve, 25));
    }
    await window.webContents.executeJavaScript("Array.from(document.querySelectorAll('button')).find(button => button.textContent?.trim() === '执行检查')?.click()");
    const inspectionDeadline = Date.now() + 3000;
    while (!(await window.webContents.executeJavaScript('document.body.textContent.includes("candidate-5.3.1-unverified")')) && Date.now() < inspectionDeadline) {
        await new Promise(resolve => setTimeout(resolve, 25));
    }
    check(await window.webContents.executeJavaScript('document.body.textContent.includes("candidate-5.3.1-unverified")'), 'inspection button renders the real report');
    await invoke('chooseClient');
    const client = await invoke<ClientInventory>('inspectClient');
    check(client.identity.versionName === 'synthetic-control-only' && client.businessReady === false,
        'real inventory worker fingerprints synthetic client through the private bridge');
    // Also exercise the actual buttons and their renderer result/lock, using the same filesystem fixture.
    await window.webContents.executeJavaScript("Array.from(document.querySelectorAll('button')).find(button => button.textContent?.trim() === '选择客户端')?.click()");
    const clientDeadline = Date.now() + 4000;
    while (!(await window.webContents.executeJavaScript("Array.from(document.querySelectorAll('button')).some(button => button.textContent?.trim() === '识别当前材料' && !button.disabled)")) && Date.now() < clientDeadline) {
        await new Promise(resolve => setTimeout(resolve, 25));
    }
    await window.webContents.executeJavaScript("Array.from(document.querySelectorAll('button')).find(button => button.textContent?.trim() === '识别当前材料')?.click()");
    const inventoryDeadline = Date.now() + 4000;
    while (!(await window.webContents.executeJavaScript('document.body.textContent.includes("synthetic-control-only")')) && Date.now() < inventoryDeadline) {
        await new Promise(resolve => setTimeout(resolve, 25));
    }
    check(await window.webContents.executeJavaScript('document.body.textContent.includes("synthetic-control-only")'),
        'client identification buttons render the real fingerprint report');
    await window.webContents.executeJavaScript('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
    check(await window.webContents.executeJavaScript("Array.from(document.querySelectorAll('button')).some(button => button.textContent?.trim() === '停止服务' && !button.disabled)"), 'UI releases its operation lock');
    await writeFile(join(options.output, 'foundation.png'), (await window.webContents.capturePage(undefined, { stayHidden: true, stayAwake: true })).toPNG());
    await window.webContents.executeJavaScript("Array.from(document.querySelectorAll('.v-card-title')).find(element => element.textContent?.trim() === '当前客户端')?.closest('.v-card')?.scrollIntoView({ block: 'center' })");
    await window.webContents.executeJavaScript('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
    await writeFile(join(options.output, 'client-inventory.png'), (await window.webContents.capturePage(undefined, { stayHidden: true, stayAwake: true })).toPNG());
    await window.webContents.executeJavaScript('window.scrollTo({ top: 0 })');
    await window.webContents.executeJavaScript("Array.from(document.querySelectorAll('button')).find(button => button.textContent?.trim() === '切换主题')?.click()");
    await new Promise(resolve => setTimeout(resolve, 800));
    await window.webContents.executeJavaScript('document.getAnimations().forEach(animation => { try { animation.finish(); } catch {} })');
    const darkStyles = await window.webContents.executeJavaScript(`Array.from(document.querySelectorAll('.v-application,.v-card,h1')).map(element => ({
        tag: element.tagName, class: element.className,
        background: getComputedStyle(element).backgroundColor, color: getComputedStyle(element).color,
        surface: getComputedStyle(element).getPropertyValue('--v-theme-surface')
    }))`);
    check(darkStyles.every((style: { color: string }) => style.color !== 'rgb(0, 0, 0)'), 'dark theme text uses the native light foreground');
    await writeFile(join(options.output, 'foundation-dark.png'), (await window.webContents.capturePage(undefined, { stayHidden: true, stayAwake: true })).toPNG());
    await window.webContents.executeJavaScript("Array.from(document.querySelectorAll('.v-card-title')).find(element => element.textContent?.trim() === '当前客户端')?.closest('.v-card')?.scrollIntoView({ block: 'center' })");
    await window.webContents.executeJavaScript('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
    await writeFile(join(options.output, 'client-inventory-dark.png'), (await window.webContents.capturePage(undefined, { stayHidden: true, stayAwake: true })).toPNG());
    await invoke<RuntimeStatus>('stopService');
    await writeFile(join(options.output, 'electron-smoke.json'), JSON.stringify({
        passed: true, timestamp: new Date().toISOString(), environment, checks,
        instanceIds: [first.instanceId, second.instanceId, recovered.instanceId], report
    }, null, 4));
    console.log(JSON.stringify({ stage: 'electron_smoke', passed: true, checks: checks.length, output: options.output }));
}
