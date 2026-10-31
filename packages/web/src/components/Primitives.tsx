import type { ReactNode } from 'react';
import { VALIDATION_STATUS_LABEL, type ValidationStatus } from '@detectionforge/core';

const STATUS_STYLES: Record<ValidationStatus, string> = {
  validated_syntax: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
  not_validated: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  mapping_required: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
  unsupported: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
};

export function StatusBadge({ status }: { status: ValidationStatus }): ReactNode {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${STATUS_STYLES[status]}`}
      title="Validation performed inside DetectionForge only — no query was run against a live SIEM."
    >
      {VALIDATION_STATUS_LABEL[status]}
    </span>
  );
}

const SEVERITY_STYLES: Record<string, string> = {
  informational: 'border-slate-500/40 bg-slate-500/10 text-slate-300',
  low: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  critical: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
};

export function SeverityBadge({ severity }: { severity: string }): ReactNode {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${
        SEVERITY_STYLES[severity] ?? SEVERITY_STYLES['medium']
      }`}
    >
      {severity}
    </span>
  );
}

export function Chip({ children, title }: { children: ReactNode; title?: string }): ReactNode {
  return (
    <span className="dfai-chip" title={title}>
      {children}
    </span>
  );
}

export function Section({
  title,
  children,
  subtitle,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
}): ReactNode {
  return (
    <section className="space-y-2">
      <h4 className="text-xs font-semibold uppercase tracking-[0.14em] text-[var(--color-forge-muted)]">{title}</h4>
      {subtitle ? <p className="text-xs text-[var(--color-forge-muted)]">{subtitle}</p> : null}
      {children}
    </section>
  );
}

export function BulletList({ items }: { items: readonly string[] }): ReactNode {
  if (items.length === 0) {
    return <p className="text-sm text-[var(--color-forge-muted)]">None recorded.</p>;
  }
  return (
    <ul className="space-y-1.5">
      {items.map((item, index) => (
        <li key={index} className="flex gap-2 text-sm leading-relaxed text-[var(--color-forge-text)]/90">
          <span aria-hidden="true" className="mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--color-forge-accent)]/70" />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

export function Spinner(): ReactNode {
  return (
    <span
      aria-hidden="true"
      className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"
    />
  );
}
