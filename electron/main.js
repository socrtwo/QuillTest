/*
 * Anne's Test — Electron main process (desktop build)
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * The desktop shell loads the same web app the browser build serves (the
 * command shell and the AI wizard), but in a privileged context: unlike the
 * pure-web build, the main process can make the scanner's network calls
 * without browser CORS getting in the way (see docs/ARCHITECTURE-PLAN.md).
 *
 * Security posture: the renderer runs with contextIsolation on, nodeIntegration
 * off and sandbox on. It cannot touch Node or the filesystem directly. The one
 * capability it is granted, through a narrow preload bridge, is to ask the main
 * process to run a KNOWN Anne's Test command by its registry id — never an
 * arbitrary command line. The main process validates the id against the command
 * registry, requires string arguments, and spawns the mapped script with an
 * argument array (no shell), so there is no command-injection surface.
 *
 * This file is scaffolded to spec but is not built or run in the cloud CI
 * session (Electron needs a display); build it on a desktop with `npm run
 * electron:build`.
 */
import { app, BrowserWindow, ipcMain, shell } from 'electron';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { execFile } from 'node:child_process';

// The data folder keeps the app's former name (QuillTest) so settings and keys stay where earlier versions put them. // rename:keep
app.setPath('userData', join(app.getPath('appData'), 'QuillTest')); // rename:keep
app.setPath('sessionData', app.getPath('userData')); // rename:keep

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');
// In a packaged app `repoRoot` is inside app.asar, which a child process cannot chdir into or
// read from; the scripts and engine are unpacked (package.json build.asarUnpack) next to it.
const scriptRoot = app.isPackaged ? repoRoot.replace(/app\.asar(?=[\\/]|$)/, 'app.asar.unpacked') : repoRoot;
// Reports, the verification store and quilltest.ai.json live under the user's data folder when
// packaged (the archive is read-only); in development they stay in the checkout as the CLIs do.
const workDir = app.isPackaged ? app.getPath('userData') : repoRoot;
const devUrl = process.env.VITE_DEV_SERVER_URL;
const isAppUrl = (url) => (devUrl ? url.startsWith(devUrl) : url.startsWith('file://'));

// Build the allow-list of runnable commands from the registry: id → script path.
const { COMMANDS } = await import('../src/commands/registry.mjs');
const { buildRunnableMap, resolveRun } = await import('./bridge.mjs');
const RUNNABLE = buildRunnableMap(COMMANDS);

function createWindow() {
  const win = new BrowserWindow({
    width: 1200, height: 800, minWidth: 720,
    title: 'Anne\'s Test',
    webPreferences: {
      preload: join(here, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  // External links (the wizard's "get a key" links) open in the system browser, never in a new
  // Electron window, and the app window itself never navigates away from the app's own pages.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (event, url) => {
    if (isAppUrl(url)) return;
    event.preventDefault();
    if (/^https?:\/\//i.test(url)) shell.openExternal(url);
  });
  if (devUrl) win.loadURL(devUrl);
  else win.loadFile(resolve(repoRoot, 'dist', 'index.html'));
  return win;
}

// Guarded command bridge: run a known Anne's Test command id with string args.
ipcMain.handle('quilltest:run', async (event, payload) => {
  const sender = event.senderFrame?.url || '';
  if (!isAppUrl(sender)) return { ok: false, code: -1, stdout: '', stderr: 'Refused: request did not come from the app page.' };
  const { id, args } = payload || {};
  const check = resolveRun(RUNNABLE, id, args);
  if (!check.ok) return check;
  const scriptPath = resolve(scriptRoot, check.script);
  return await new Promise((res) => {
    // Run the bundled Electron binary as plain Node to execute the script.
    execFile(process.execPath, [scriptPath, ...args], {
      cwd: workDir,
      timeout: 15 * 60_000, // a 25-page crawl plus protocol checks can take well over two minutes
      maxBuffer: 8 * 1024 * 1024,
      env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
    }, (err, stdout, stderr) => {
      res({ ok: !err, code: err?.code ?? 0, stdout: String(stdout || ''), stderr: String(stderr || (err ? err.message : '')) });
    });
  });
});

ipcMain.handle('quilltest:version', () => app.getVersion());

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
