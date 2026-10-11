import { contextBridge, ipcRenderer } from 'electron';
import { IPC_CHANNELS } from '../shared/contracts';
import type { DesktopBridge } from '../shared/contracts';

// One method per allowlisted operation. No raw ipcRenderer, path argument,
// shell execution, SQL or filesystem API crosses the isolated bridge.
const bridge: DesktopBridge = Object.freeze({
    getEnvironment: () => ipcRenderer.invoke(IPC_CHANNELS.environment),
    getStatus: () => ipcRenderer.invoke(IPC_CHANNELS.status),
    startService: () => ipcRenderer.invoke(IPC_CHANNELS.start),
    stopService: () => ipcRenderer.invoke(IPC_CHANNELS.stop),
    chooseBundle: () => ipcRenderer.invoke(IPC_CHANNELS.choose),
    inspectBundle: () => ipcRenderer.invoke(IPC_CHANNELS.inspect),
    chooseClient: () => ipcRenderer.invoke(IPC_CHANNELS.chooseClient),
    inspectClient: () => ipcRenderer.invoke(IPC_CHANNELS.inspectClient)
});

contextBridge.exposeInMainWorld('apDesktop', bridge);
