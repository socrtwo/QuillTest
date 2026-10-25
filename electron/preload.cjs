/*
 * QuillTest — Electron preload (CommonJS; runs with sandbox on)
 * Exposes a minimal, explicit API to the renderer. No Node, no fs, no shell —
 * only the ability to ask the main process to run a known command id and to
 * read the app version. Everything is validated again in the main process.
 */
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('quilltest', {
  /** Run a known QuillTest command by registry id. args: string[] → { ok, code, stdout, stderr }. */
  run: (id, args = []) => ipcRenderer.invoke('quilltest:run', { id, args }),
  /** The app version. */
  version: () => ipcRenderer.invoke('quilltest:version'),
  /** Marks the desktop build so the shell can enable in-app execution. */
  isDesktop: true,
});
