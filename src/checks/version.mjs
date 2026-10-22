/** Tiny version comparison for fingerprinted components ("1.12.4" < "3.5.0"). */
export function parseVersion(v) {
  const m = /(\d+(?:\.\d+){0,3})/.exec(String(v || ''));
  return m ? m[1].split('.').map(Number) : null;
}
export function compareVersions(a, b) {
  const x = Array.isArray(a) ? a : parseVersion(a); const y = Array.isArray(b) ? b : parseVersion(b);
  if (!x || !y) return NaN;
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d < 0 ? -1 : 1; }
  return 0;
}
export function versionBelow(v, limit) { const c = compareVersions(v, limit); return Number.isNaN(c) ? false : c < 0; }
export function versionInRange(v, [lo, hi]) { return !versionBelow(v, lo) && versionBelow(v, hi); }
