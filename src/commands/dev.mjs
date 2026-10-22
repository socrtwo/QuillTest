/** Developer — macros, scripting, diagnostics. Macro recording is implemented on the executor. */
import { def, getCommand } from './registry.mjs';

def([
  {
    id: 'dev.recordMacro', label: 'Record Macro', icon: 'fiber_manual_record', tab: 'Developer', group: 'Macros', noRecord: true,
    tip: 'Every command run until Stop Recording becomes a step',
    run: (ctx) => { if (ctx.recording) throw new Error('Already recording'); ctx.recording = []; return { recording: true }; },
  },
  {
    id: 'dev.stopRecording', label: 'Stop Recording', icon: 'stop_circle', tab: 'Developer', group: 'Macros', noRecord: true,
    run: (ctx, arg) => {
      if (!ctx.recording) throw new Error('Not recording');
      const steps = ctx.recording;
      ctx.recording = null;
      const name = (typeof arg === 'string' ? arg : arg?.name) || `Macro ${((ctx.macros ||= new Map()).size) + 1}`;
      (ctx.macros ||= new Map()).set(name, { name, steps, created: ctx.now().toISOString() });
      return { name, steps };
    },
  },
  {
    id: 'dev.runMacro', label: 'Run Macro', icon: 'play_circle', tab: 'Developer', group: 'Macros', noRecord: true,
    run: async (ctx, arg) => {
      const name = typeof arg === 'string' ? arg : arg?.name;
      const macro = ctx.macros?.get(name);
      if (!macro) throw new RangeError(`No macro named ${JSON.stringify(name)}`);
      const results = [];
      for (const step of macro.steps) results.push(await ctx.exec(step.id, step.arg));
      return { name, results };
    },
  },
  { id: 'dev.macros', label: 'Macros…', icon: 'smart_button', tab: 'Developer', group: 'Macros', noRecord: true, run: (ctx) => [...(ctx.macros?.values() || [])].map((m) => ({ name: m.name, steps: m.steps.length, created: m.created })) },
  { id: 'dev.console', label: 'Command Console', icon: 'terminal', tab: 'Developer', group: 'Scripting', noRecord: true, tip: 'Run commands by id with JSON arguments' },
  { id: 'dev.scripts', label: 'Scripts…', icon: 'code', tab: 'Developer', group: 'Scripting', tip: 'JavaScript automation over the command API' },
  { id: 'dev.api', label: 'Command API Reference', icon: 'api', tab: 'Developer', group: 'Scripting', noRecord: true, run: () => getCommand('help.commandReference').run() },
  { id: 'dev.diagnostics', label: 'Diagnostics', icon: 'monitor_heart', tab: 'Developer', group: 'Diagnostics', noRecord: true },
  { id: 'dev.logs', label: 'Application Logs', icon: 'receipt_long', tab: 'Developer', group: 'Diagnostics', noRecord: true },
  { id: 'dev.resetState', label: 'Reset Application State', icon: 'restart_alt', tab: 'Developer', group: 'Diagnostics' },
]);
