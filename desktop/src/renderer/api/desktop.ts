import type { DesktopBridge, Result } from '../../shared/contracts';

export async function callDesktop<K extends keyof DesktopBridge>(method: K): Promise<
    Awaited<ReturnType<DesktopBridge[K]>> extends Result<infer T> ? T : never
> {
    const bridge = window.apDesktop;
    if (!bridge) throw { code: 'DESKTOP_UNAVAILABLE', detail: '请通过 Electron 启动桌面底座。' };
    const result = await bridge[method]();
    if (!result.ok) throw result.error;
    return result.value as Awaited<ReturnType<DesktopBridge[K]>> extends Result<infer T> ? T : never;
}
