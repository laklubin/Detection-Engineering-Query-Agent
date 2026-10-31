import type { ReactNode } from 'react';

export function ErrorNotice({
  title,
  message,
  details,
  code,
  onDismiss,
}: {
  title: string;
  message: string;
  details?: readonly string[];
  code?: string;
  onDismiss?: () => void;
}): ReactNode {
  return (
    <div
      role="alert"
      className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-100"
      data-testid="error-notice"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <p className="font-semibold text-rose-200">{title}</p>
          <p className="leading-relaxed">{message}</p>
          {code ? (
            <p className="font-mono text-[11px] uppercase tracking-wide text-rose-300/80">error code: {code}</p>
          ) : null}
          {details && details.length > 0 ? (
            <ul className="mt-1 list-inside list-disc space-y-0.5 text-[13px] text-rose-200/90">
              {details.map((detail, index) => (
                <li key={index}>{detail}</li>
              ))}
            </ul>
          ) : null}
        </div>
        {onDismiss ? (
          <button type="button" onClick={onDismiss} className="dfai-btn dfai-btn-ghost px-2 py-1 text-xs">
            Dismiss
          </button>
        ) : null}
      </div>
    </div>
  );
}

export function WarningList({ warnings }: { warnings: readonly string[] }): ReactNode {
  if (warnings.length === 0) return null;
  return (
    <div
      role="status"
      className="rounded-xl border border-amber-500/35 bg-amber-500/10 p-4 text-sm text-amber-100"
      data-testid="warning-notice"
    >
      <p className="mb-1.5 font-semibold text-amber-200">Notices</p>
      <ul className="list-inside list-disc space-y-1">
        {warnings.map((warning, index) => (
          <li key={index} className="leading-relaxed">
            {warning}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ClarifyingQuestion({
  question,
  onFocusLogSource,
}: {
  question: string;
  onFocusLogSource: () => void;
}): ReactNode {
  return (
    <div
      role="status"
      className="rounded-xl border border-sky-500/40 bg-sky-500/10 p-4 text-sm text-sky-100"
      data-testid="clarifying-question"
    >
      <p className="mb-1 font-semibold text-sky-200">One quick question before generating</p>
      <p className="leading-relaxed">{question}</p>
      <button type="button" onClick={onFocusLogSource} className="dfai-btn dfai-btn-ghost mt-3 text-xs">
        Choose vendor and log source
      </button>
    </div>
  );
}

export function DemoBanner({ model }: { model: string | null }): ReactNode {
  return (
    <div
      role="status"
      className="rounded-xl border border-violet-500/40 bg-violet-500/10 p-4 text-sm text-violet-100"
      data-testid="demo-banner"
    >
      <p className="font-semibold text-violet-200">Demo mode — output is a synthetic fixture</p>
      <p className="mt-1 leading-relaxed">
        No Hugging Face token is configured on the backend, so these detection use cases come from a built-in
        synthetic example and were <strong>not</strong> produced by a language model. Everything else — guardrails,
        sanitisation, the seven adapters and the validation checks — runs exactly as it does in live mode.
        {model ? ` Reported model: ${model}.` : ''}
      </p>
    </div>
  );
}

export function CommercialNotice({ notice }: { notice: string }): ReactNode {
  return (
    <div
      className="rounded-xl border border-[var(--color-forge-border-strong)] bg-[var(--color-forge-panel-2)] p-4 text-sm leading-relaxed text-[var(--color-forge-text)]/90"
      data-testid="commercial-notice"
    >
      {notice}
    </div>
  );
}
