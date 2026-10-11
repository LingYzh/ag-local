import { app, BrowserWindow, dialog, ipcMain, session, utilityProcess } from 'electron';
import { realpath, stat } from 'node:fs/promises';
import { mkdirSync, mkdtempSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { IPC_CHANNELS } from '../shared/contracts';
import type { Result } from '../shared/contracts';
import { fault } from '../shared/validation';
import { isBundleResource, isTrustedRenderer } from './security';
import { ServiceSupervisor } from './service-supervisor';
import { runDesktopSmoke } from './smoke';
import { createSmokeClient } from './smoke-fixtures';

const smoke = process.argv.includes('--foundation-smoke');
const smokeOutput = process.argv.find(value => value.startsWith('--smoke-output='))?.slice('--smoke-output='.length);
if (smoke) {
    if (!smokeOutput || !isAbsolute(smokeOutput)) throw new Error('Smoke test requires an explicit absolute output directory');
    mkdirSync(smokeOutput, { recursive: true });
    const profile = mkdtempSync(join(smokeOutput, 'profile-'));
    app.setPath('userData', profile);
    app.setPath('sessionData', profile);
}
const rendererRoot = join(__dirname, '../renderer');
const rendererEntry = join(rendererRoot, 'index.html');
const expectedUrl = pathToFileURL(rendererEntry).href;
let window: BrowserWindow | null = null;
let selectedDirectory: string | null = null;
let selectedClient: string | null = null;
let smokeClient: string | null = null;
let quitting = false;
let ownedChild: { child: Electron.UtilityProcess; instanceId: string } | null = null;

const supervisor = new ServiceSupervisor(join(__dirname, '../service/worker.cjs'), {
    fork: (workerPath, instanceId) => {
        const child = utilityProcess.fork(workerPath, [instanceId], {
            stdio: 'pipe', serviceName: 'Alpha Persei Diagnostics'
        });
        ownedChild = { child, instanceId };
        // Consume pipe data even without a logger so a child cannot stall on a full pipe.
        child.stdout?.on('data', () => {});
        child.stderr?.on('data', () => {});
        return child;
    }
});

function registerBridge(): void {
    function handle(channel: string, operation: () => unknown | Promise<unknown>): void {
        ipcMain.handle(channel, async (event, ...args): Promise<Result<unknown>> => {
            if (!window || event.sender !== window.webContents || args.length !== 0
                || !isTrustedRenderer(event.senderFrame?.url ?? '', expectedUrl,
                    event.senderFrame === window.webContents.mainFrame)) {
                return { ok: false, error: { code: 'IPC_FORBIDDEN', detail: 'Only the local main frame may use the desktop bridge' } };
            }
            try {
                return { ok: true, value: await operation() };
            } catch (error) {
                return { ok: false, error: fault(error) };
            }
        });
    }
    handle(IPC_CHANNELS.environment, () => ({
        appVersion: app.getVersion(), electron: process.versions.electron,
        node: process.versions.node, platform: process.platform,
        architecture: process.arch, mode: 'foundation'
    }));
    handle(IPC_CHANNELS.status, () => supervisor.getStatus());
    handle(IPC_CHANNELS.start, () => supervisor.start());
    handle(IPC_CHANNELS.stop, () => supervisor.stop());
    handle(IPC_CHANNELS.choose, async () => {
        if (smoke) {
            selectedDirectory = await realpath(join(__dirname, '../fixtures/observed'));
            return { directory: selectedDirectory };
        }
        const choice = await dialog.showOpenDialog(window!, {
            title: '选择待检查的制品目录', properties: ['openDirectory', 'dontAddToRecent']
        });
        if (choice.canceled || !choice.filePaths[0]) return null;
        const directory = await realpath(choice.filePaths[0]);
        if (!(await stat(directory)).isDirectory()) throw new Error('BUNDLE_DIRECTORY_INVALID');
        selectedDirectory = directory;
        return { directory };
    });
    handle(IPC_CHANNELS.inspect, () => {
        if (!selectedDirectory) {
            throw { code: 'BUNDLE_NOT_SELECTED', detail: '请先选择待检查的制品目录。' };
        }
        return supervisor.inspect(selectedDirectory);
    });
    handle(IPC_CHANNELS.chooseClient, async () => {
        if (smoke && smokeClient) {
            selectedClient = smokeClient;
            return { directory: selectedClient };
        }
        const choice = await dialog.showOpenDialog(window!, {
            title: '选择客户端目录（包含 AetherGazer.exe）', properties: ['openDirectory', 'dontAddToRecent']
        });
        if (choice.canceled || !choice.filePaths[0]) return null;
        const directory = await realpath(choice.filePaths[0]);
        if (!(await stat(directory)).isDirectory()) throw new Error('CLIENT_DIRECTORY_INVALID');
        selectedClient = directory;
        return { directory };
    });
    handle(IPC_CHANNELS.inspectClient, () => {
        if (!selectedClient) throw { code: 'CLIENT_NOT_SELECTED', detail: '请先选择客户端目录。' };
        return supervisor.inventory(selectedClient);
    });
}

async function createWindow(): Promise<void> {
    if (smoke) smokeClient = await createSmokeClient(smokeOutput!);
    const isolatedSession = session.fromPartition('ap-foundation');
    isolatedSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
    isolatedSession.setPermissionCheckHandler(() => false);
    isolatedSession.webRequest.onBeforeRequest((details, callback) => {
        callback({ cancel: !isBundleResource(details.url, rendererRoot) });
    });
    window = new BrowserWindow({
        width: 1280, height: 900, minWidth: 800, minHeight: 640,
        title: 'Alpha Persei', show: !smoke,
        webPreferences: {
            preload: join(__dirname, '../preload/preload.cjs'), session: isolatedSession,
            contextIsolation: true, sandbox: true, nodeIntegration: false,
            webSecurity: true, allowRunningInsecureContent: false,
            webviewTag: false, spellcheck: false, backgroundThrottling: !smoke,
            offscreen: smoke
        }
    });
    window.removeMenu();
    window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    window.webContents.on('will-navigate', event => event.preventDefault());
    window.webContents.on('will-attach-webview', event => event.preventDefault());
    registerBridge();
    await window.loadFile(rendererEntry);
    if (smoke) {
        await runDesktopSmoke(window, supervisor, {
            output: smokeOutput!,
            fixture: join(__dirname, '../fixtures/observed'),
            crashOwnedChild: async () => {
                const owner = ownedChild;
                // Test-only fault injection after two private identity responses.
                await supervisor.inspect(join(__dirname, '../fixtures/observed'));
                await supervisor.inspect(join(__dirname, '../fixtures/observed'));
                if (!owner || ownedChild !== owner || supervisor.getStatus().instanceId !== owner.instanceId) {
                    throw new Error('Smoke cannot prove child ownership');
                }
                owner.child.kill();
            }
        });
        app.quit();
    }
}

if (!smoke && !app.requestSingleInstanceLock()) {
    app.quit();
} else {
    app.on('second-instance', () => {
        if (window?.isMinimized()) window.restore();
        window?.focus();
    });
    app.on('before-quit', event => {
        if (quitting) return;
        event.preventDefault();
        supervisor.stop().catch(error => console.error(JSON.stringify({ stage: 'shutdown', error: fault(error) })))
            .finally(() => { quitting = true; app.quit(); });
    });
    app.on('window-all-closed', () => app.quit());
    app.whenReady().then(createWindow).catch(async error => {
        console.error(JSON.stringify({ stage: 'desktop_bootstrap', error: fault(error) }));
        await supervisor.stop().catch(() => {});
        quitting = true;
        app.exit(1);
    });
}
