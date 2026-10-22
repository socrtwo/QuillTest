/** AI tab — optional analysis layer over QuillTest's own findings (docs/AI.md). Setup commands are implemented. */
import { def } from './registry.mjs';
import { PROVIDERS, getProvider, buildTestRequest, extractText } from '../ai/providers.mjs';
import { loadAiConfig, activeProvider, resolveApiKey, AiConfigError } from '../ai/config.mjs';
import { readFileSync, writeFileSync } from 'node:fs';

const loadOrNull = (ctx) => {
  try { return loadAiConfig(ctx.aiConfigPath).config; } catch (e) { if (e instanceof AiConfigError) return null; throw e; }
};

def([
  {
    id: 'ai.setup', label: 'AI Setup Wizard', icon: 'auto_fix_high', tab: 'AI', group: 'Setup', popular: true,
    tip: 'Choose a provider and model, test the connection, save quilltest.ai.json',
    run: (ctx) => ({ cli: 'node scripts/ai-setup-wizard.mjs', browser: 'public/ai-wizard.html', configPath: ctx.aiConfigPath, configured: Boolean(loadOrNull(ctx)) }),
  },
  {
    id: 'ai.active', label: 'Active Provider', icon: 'smart_toy', tab: 'AI', group: 'Setup', kind: 'combo', noRecord: true,
    tip: 'Which configured provider analysis uses; pass a provider id to switch',
    run: (ctx, arg) => {
      const cfg = loadOrNull(ctx);
      if (!cfg) return { configured: false, active: null };
      const want = typeof arg === 'string' ? arg : arg?.providerId;
      if (want) {
        if (!cfg.providers[want]) throw new RangeError(`${want} is not configured; run the setup wizard for it first`);
        cfg.active = want;
        writeFileSync(ctx.aiConfigPath, JSON.stringify(cfg, null, 2) + '\n');
      }
      const p = activeProvider(cfg);
      return { configured: true, active: cfg.active, model: p.model, base: p.base, hasKey: Boolean(resolveApiKey(p, ctx.env)) };
    },
  },
  {
    id: 'ai.providers', label: 'Providers', icon: 'hub', tab: 'AI', group: 'Setup', noRecord: true,
    tip: 'Supported providers and which are configured',
    run: (ctx) => {
      const cfg = loadOrNull(ctx);
      return PROVIDERS.map((p) => ({ id: p.id, label: p.label, apiStyle: p.apiStyle, configured: Boolean(cfg?.providers[p.id]), models: p.models }));
    },
  },
  {
    id: 'ai.test', label: 'Test Connection', icon: 'network_check', tab: 'AI', group: 'Setup',
    run: async (ctx, arg) => {
      const cfg = loadOrNull(ctx);
      if (!cfg) return { ok: false, error: `no valid config at ${ctx.aiConfigPath}; run ai.setup` };
      const p = cfg.providers[(typeof arg === 'string' ? arg : arg?.providerId) || cfg.active];
      const apiKey = resolveApiKey(p, ctx.env);
      if (!apiKey && p.providerId !== 'local') return { ok: false, error: `no API key available (set $${p.apiKeyEnv})` };
      const { url, init } = buildTestRequest({ providerId: p.providerId, base: p.base, apiKey, model: p.model });
      if (arg?.dryRun) return { ok: true, dryRun: true, url, method: init.method, body: init.body };
      const t0 = Date.now();
      try {
        const res = await fetch(url, { ...init, signal: AbortSignal.timeout(30_000) });
        const text = await res.text();
        let json = null; try { json = JSON.parse(text); } catch { /* not JSON */ }
        if (!res.ok) return { ok: false, status: res.status, error: json?.error?.message || json?.message || text.slice(0, 200), ms: Date.now() - t0 };
        return { ok: true, status: res.status, ms: Date.now() - t0, reply: json ? extractText(getProvider(p.providerId).apiStyle, json) : '' };
      } catch (e) { return { ok: false, error: e?.cause?.message || e.message }; }
    },
  },
  {
    id: 'ai.privacy', label: 'What Is Sent to the AI', icon: 'privacy_tip', tab: 'AI', group: 'Setup', noRecord: true,
    run: () => readFileSync(new URL('../../docs/AI.md', import.meta.url), 'utf8'),
  },
  { id: 'ai.stop', label: 'Stop AI Request', icon: 'stop_circle', tab: 'AI', group: 'Setup', noRecord: true },
  { id: 'ai.dryRun', label: 'Dry Run (show prompt, send nothing)', icon: 'visibility', tab: 'AI', group: 'Setup', kind: 'toggle' },
  { id: 'ai.scrubPreview', label: 'Preview Secret Scrubbing', icon: 'cleaning_services', tab: 'AI', group: 'Setup', noRecord: true, tip: 'Exactly which fragments would leave the machine, after scrubbing' },
  { id: 'ai.triage', label: 'Triage Findings', icon: 'sort', tab: 'AI', group: 'Analyze', popular: true, tip: 'Deduplicate, rank by exploitability, flag likely false positives' },
  { id: 'ai.prioritize', label: "Attacker's-Eye Ranking", icon: 'crisis_alert', tab: 'AI', group: 'Analyze' },
  { id: 'ai.explain', label: 'Explain Finding', icon: 'psychology', tab: 'AI', group: 'Analyze', tip: 'Plain-language risk explanation for the selected finding' },
  { id: 'ai.falsePositives', label: 'Flag False Positives', icon: 'flag', tab: 'AI', group: 'Analyze' },
  { id: 'ai.mapCwe', label: 'Confirm CWE / OWASP Mapping', icon: 'account_tree', tab: 'AI', group: 'Analyze' },
  { id: 'ai.draftFix', label: 'Draft Remediation', icon: 'edit_note', tab: 'AI', group: 'Fix', tip: 'Refine the generated fix for the detected stack' },
  { id: 'ai.refineFix', label: 'Refine Remediation', icon: 'tune', tab: 'AI', group: 'Fix' },
  { id: 'ai.summary', label: 'Draft Executive Summary', icon: 'summarize', tab: 'AI', group: 'Report' },
  { id: 'ai.askAboutFinding', label: 'Ask About This Finding…', icon: 'chat', tab: 'AI', group: 'Analyze' },
  { id: 'ai.ensembleMode', label: 'Several AIs', icon: 'groups', tab: 'AI', group: 'Several AIs', kind: 'toggle', tip: 'Ask multiple configured providers and show where they agree', origin: 'QuillStage ensemble mode' },
  { id: 'ai.ensembleMembers', label: 'Ensemble Members…', icon: 'group_add', tab: 'AI', group: 'Several AIs' },
  { id: 'ai.showDeliberation', label: 'Show Deliberation', icon: 'forum', tab: 'AI', group: 'Several AIs', kind: 'toggle', noRecord: true },
  { id: 'ai.prompts', label: 'Prompt Library', icon: 'menu_book', tab: 'AI', group: 'Setup', noRecord: true, tip: 'The exact prompts QuillTest uses; read-only guardrails are marked' },
]);
