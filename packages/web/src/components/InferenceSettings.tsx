import { useId, useState, type ReactNode } from 'react';
import {
  DEFAULT_MODEL,
  PROBLEM_MESSAGE,
  SUGGESTED_MODELS,
  maskToken,
  validateSettings,
  type InferenceSettings,
} from '../lib/byok.js';

/**
 * Panel for supplying your own Hugging Face token.
 *
 * The token input is a password field, is never rendered back in clear text,
 * and is never included in any request to this origin — it is attached only to
 * the Hugging Face call the browser makes directly.
 */
export function InferenceSettingsPanel({
  settings,
  onApply,
  onClear,
  active,
  busy,
}: {
  settings: InferenceSettings | null;
  onApply: (next: InferenceSettings) => void;
  onClear: () => void;
  active: boolean;
  busy: boolean;
}): ReactNode {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState('');
  const [model, setModel] = useState(settings?.model ?? DEFAULT_MODEL);
  const [remember, setRemember] = useState(settings?.remember ?? false);
  const [reveal, setReveal] = useState(false);
  const [problems, setProblems] = useState<string[]>([]);

  function apply(): void {
    const found = validateSettings({ token, model });
    if (found.length > 0) {
      setProblems(found.map((p) => PROBLEM_MESSAGE[p]));
      return;
    }
    setProblems([]);
    onApply({ token: token.trim(), model: model.trim(), remember });
    setToken('');
    setOpen(false);
  }

  if (active && settings && !open) {
    return (
      <div
        className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-4 text-sm text-emerald-100"
        data-testid="byok-active"
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="font-semibold text-emerald-200">Live inference with your own key</p>
            <p className="mt-1 leading-relaxed">
              Using <code className="font-mono text-[12px]">{settings.model}</code> with token{' '}
              <code className="font-mono text-[12px]">{maskToken(settings.token)}</code>. Requests go straight from
              this browser to Hugging Face; they never touch this project&rsquo;s servers.
              {settings.remember
                ? ' Stored for this tab only — closing it forgets the key.'
                : ' Held in memory only — a refresh forgets the key.'}
            </p>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              className="dfai-btn dfai-btn-ghost px-3 py-1 text-xs"
              onClick={() => setOpen(true)}
              disabled={busy}
            >
              Change
            </button>
            <button
              type="button"
              className="dfai-btn dfai-btn-ghost px-3 py-1 text-xs"
              onClick={onClear}
              disabled={busy}
              data-testid="byok-clear"
            >
              Remove key
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!open) {
    return (
      <button
        type="button"
        className="dfai-btn dfai-btn-ghost w-full justify-start text-left text-xs"
        onClick={() => setOpen(true)}
        disabled={busy}
        data-testid="byok-open"
      >
        Use your own Hugging Face token for live model answers
      </button>
    );
  }

  return (
    <div className="dfai-panel space-y-3 p-4" data-testid="byok-panel">
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--color-forge-muted)]">
          Live inference with your own key
        </p>
        <p className="mt-1.5 text-[13px] leading-relaxed text-[var(--color-forge-muted)]">
          Supply your own Hugging Face token and this page will ask a real model instead of matching templates.
          The token stays in your browser and is sent to <code className="font-mono">huggingface.co</code> and
          nowhere else — that destination is fixed in the code, not a field you or anyone else can change.
        </p>
      </div>

      <div>
        <label htmlFor={`${id}-token`} className="mb-1.5 block text-xs font-semibold text-[var(--color-forge-text)]">
          Hugging Face access token
        </label>
        <div className="flex gap-2">
          <input
            id={`${id}-token`}
            type={reveal ? 'text' : 'password'}
            className="dfai-input font-mono text-[12px]"
            placeholder="hf_..."
            autoComplete="off"
            spellCheck={false}
            value={token}
            onChange={(event) => setToken(event.target.value)}
            data-testid="byok-token"
          />
          <button
            type="button"
            className="dfai-btn dfai-btn-ghost shrink-0 px-3 text-xs"
            onClick={() => setReveal((v) => !v)}
          >
            {reveal ? 'Hide' : 'Show'}
          </button>
        </div>
        <p className="mt-1.5 text-[11px] leading-relaxed text-[var(--color-forge-muted)]">
          Create one at huggingface.co/settings/tokens as a fine-grained token with only{' '}
          <em>Make calls to Inference Providers</em>. Give it no other permission, so a leak costs you inference
          credit and nothing else.
        </p>
      </div>

      <div>
        <label htmlFor={`${id}-model`} className="mb-1.5 block text-xs font-semibold text-[var(--color-forge-text)]">
          Model
        </label>
        <input
          id={`${id}-model`}
          list={`${id}-models`}
          className="dfai-input font-mono text-[12px]"
          placeholder="owner/model"
          autoComplete="off"
          spellCheck={false}
          value={model}
          onChange={(event) => setModel(event.target.value)}
          data-testid="byok-model"
        />
        <datalist id={`${id}-models`}>
          {SUGGESTED_MODELS.map((m) => (
            <option key={m.id} value={m.id}>
              {m.label} — {m.note}
            </option>
          ))}
        </datalist>
        <p className="mt-1.5 text-[11px] leading-relaxed text-[var(--color-forge-muted)]">
          Any model Hugging Face can route to works — the suggestions are a starting point. Add{' '}
          <code className="font-mono">:provider</code> to pin one, for example{' '}
          <code className="font-mono">{DEFAULT_MODEL}:together</code>. Smaller models are cheaper but hold the
          output schema less reliably, and this application rejects output that does not match it.
        </p>
      </div>

      <label className="flex items-start gap-2 text-[12px] leading-relaxed text-[var(--color-forge-muted)]">
        <input
          type="checkbox"
          className="mt-0.5"
          checked={remember}
          onChange={(event) => setRemember(event.target.checked)}
          data-testid="byok-remember"
        />
        <span>
          Keep the key for this tab so a refresh does not lose it. It is stored in session storage, never local
          storage, so closing the tab discards it. Leave this off on a shared machine.
        </span>
      </label>

      {problems.length > 0 ? (
        <ul className="space-y-1 rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-[12px] text-rose-100">
          {problems.map((problem) => (
            <li key={problem}>{problem}</li>
          ))}
        </ul>
      ) : null}

      <div className="flex flex-wrap gap-2">
        <button type="button" className="dfai-btn dfai-btn-primary text-xs" onClick={apply} data-testid="byok-apply">
          Use this key
        </button>
        <button
          type="button"
          className="dfai-btn dfai-btn-ghost text-xs"
          onClick={() => {
            setOpen(false);
            setProblems([]);
            setToken('');
          }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
