import type { ReactNode, RefObject } from 'react';
import type { Catalog } from '../lib/api.js';
import { LogSourceCombobox } from './LogSourceCombobox.js';
import { Spinner } from './Primitives.js';

export interface FormState {
  requirement: string;
  vendorId: string;
  logSourceId: string;
}

const EXAMPLES: readonly string[] = [
  'Detect suspicious PowerShell execution followed by external network communication.',
  'Detect multiple failed logins followed by successful authentication.',
  'Alert on a service account authenticating interactively for the first time.',
];

export function RequirementForm({
  catalog,
  state,
  onChange,
  onSubmit,
  onClear,
  busy,
  logSourceInputRef,
}: {
  catalog: Catalog;
  state: FormState;
  onChange: (next: FormState) => void;
  onSubmit: () => void;
  onClear: () => void;
  busy: boolean;
  logSourceInputRef: RefObject<HTMLInputElement | null>;
}): ReactNode {
  const max = catalog.limits.requirementMaxChars;
  const min = catalog.limits.requirementMinChars;
  const length = state.requirement.length;
  const tooShort = length > 0 && length < min;
  const canSubmit = !busy && length >= min && length <= max;

  const logSources = state.vendorId && state.vendorId !== 'multi_vendor'
    ? catalog.logSources.filter((source) => source.vendorId === state.vendorId)
    : catalog.logSources;

  return (
    <form
      className="dfai-panel space-y-4 p-5"
      onSubmit={(event) => {
        event.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <div>
        <div className="mb-1.5 flex items-baseline justify-between gap-3">
          <label
            htmlFor="requirement"
            className="text-xs font-semibold uppercase tracking-[0.14em] text-[var(--color-forge-muted)]"
          >
            Detection requirement
          </label>
          <span
            className={`font-mono text-[11px] ${
              length > max ? 'text-[var(--color-forge-danger)]' : 'text-[var(--color-forge-muted)]'
            }`}
          >
            {length}/{max}
          </span>
        </div>
        <textarea
          id="requirement"
          name="requirement"
          rows={3}
          maxLength={max}
          required
          spellCheck
          disabled={busy}
          className="dfai-input resize-y font-[inherit]"
          placeholder="Describe the behaviour to detect, e.g. detect multiple failed logins followed by a successful authentication from the same source."
          value={state.requirement}
          onChange={(event) => onChange({ ...state, requirement: event.target.value })}
          aria-describedby="requirement-help"
        />
        <p id="requirement-help" className="mt-1.5 text-[11px] leading-relaxed text-[var(--color-forge-muted)]">
          Defensive detection logic only. Do not paste raw logs, credentials or customer data — the backend rejects or
          redacts them before any inference call.
        </p>
        {tooShort ? (
          <p className="mt-1 text-[11px] text-[var(--color-forge-warn)]">
            Add a little more detail: at least {min} characters of detection logic.
          </p>
        ) : null}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label
            htmlFor="vendor"
            className="mb-1.5 block text-xs font-semibold uppercase tracking-[0.14em] text-[var(--color-forge-muted)]"
          >
            Vendor
          </label>
          <select
            id="vendor"
            name="vendor"
            disabled={busy}
            className="dfai-input"
            value={state.vendorId}
            onChange={(event) => {
              const vendorId = event.target.value;
              const keep =
                state.logSourceId &&
                catalog.logSources.some(
                  (source) =>
                    source.id === state.logSourceId && (vendorId === 'multi_vendor' || source.vendorId === vendorId),
                );
              onChange({ ...state, vendorId, logSourceId: keep ? state.logSourceId : '' });
            }}
          >
            <option value="">Not specified</option>
            {catalog.vendors.map((vendor) => (
              <option key={vendor.id} value={vendor.id}>
                {vendor.name}
              </option>
            ))}
          </select>
        </div>

        <LogSourceCombobox
          sources={logSources}
          value={state.logSourceId}
          onChange={(logSourceId) => onChange({ ...state, logSourceId })}
          inputRef={logSourceInputRef}
          disabled={busy}
        />
      </div>

      <div className="flex flex-wrap items-center gap-2.5">
        <button type="submit" className="dfai-btn dfai-btn-primary" disabled={!canSubmit} data-testid="generate">
          {busy ? <Spinner /> : null}
          {busy ? 'Generating…' : 'Generate Detection'}
        </button>
        <button type="button" className="dfai-btn dfai-btn-ghost" onClick={onClear} disabled={busy} data-testid="clear">
          Clear
        </button>
      </div>

      <div className="border-t border-[var(--color-forge-border)] pt-3">
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--color-forge-muted)]">
          Try an example
        </p>
        <div className="flex flex-wrap gap-2">
          {EXAMPLES.map((example) => (
            <button
              key={example}
              type="button"
              disabled={busy}
              className="dfai-btn dfai-btn-ghost max-w-full px-2.5 py-1 text-left text-[11px] font-normal"
              onClick={() => onChange({ ...state, requirement: example })}
            >
              {example}
            </button>
          ))}
        </div>
      </div>
    </form>
  );
}
