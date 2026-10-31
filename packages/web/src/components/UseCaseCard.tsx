import { useMemo, useState, type ReactNode } from 'react';
import {
  PLATFORMS,
  exportFilename,
  platformFileExtension,
  renderQueryFile,
  renderUseCaseMarkdown,
  type GeneratedUseCase,
  type PlatformId,
  type PlatformQuery,
} from '@detectionforge/core';
import { CodeBlock } from './CodeBlock.js';
import { BulletList, Chip, Section, SeverityBadge, StatusBadge } from './Primitives.js';
import { copyText, downloadText } from '../lib/download.js';
import type { HighlightLanguage } from '../lib/highlight.js';

function describeCorrelation(useCase: GeneratedUseCase): string {
  const c = useCase.spec.correlation;
  const parts = [`${c.type.replace('_', ' ')}`, `window ${c.timeWindowSeconds}s`];
  if (c.eventThreshold !== undefined) parts.push(`≥ ${c.eventThreshold} events`);
  if (c.distinctThreshold !== undefined) parts.push(`≥ ${c.distinctThreshold} distinct ${c.thresholdField ?? ''}`.trim());
  if (c.groupBy.length > 0) parts.push(`by ${c.groupBy.join(', ')}`);
  return parts.join(' · ');
}

function QueryPanel({
  useCase,
  query,
  generatedAt,
}: {
  useCase: GeneratedUseCase;
  query: PlatformQuery;
  generatedAt: string;
}): ReactNode {
  const [copied, setCopied] = useState(false);
  const descriptor = PLATFORMS[query.platform];
  const fileText = useMemo(() => renderQueryFile(useCase, query, generatedAt), [useCase, query, generatedAt]);

  async function onCopy(): Promise<void> {
    const ok = await copyText(query.query ?? '');
    setCopied(ok);
    setTimeout(() => setCopied(false), 1800);
  }

  function onDownload(): void {
    downloadText(
      exportFilename([useCase.spec.slug, query.platform], platformFileExtension(query.platform)),
      fileText,
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold text-[var(--color-forge-text)]">{descriptor.product}</span>
          <Chip>{descriptor.language}</Chip>
          <StatusBadge status={query.status} />
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            className="dfai-btn dfai-btn-ghost px-3 py-1 text-xs"
            onClick={() => void onCopy()}
            disabled={query.query === null}
            data-testid={`copy-${query.platform}`}
          >
            {copied ? 'Copied' : 'Copy Query'}
          </button>
          <button
            type="button"
            className="dfai-btn dfai-btn-ghost px-3 py-1 text-xs"
            onClick={onDownload}
            data-testid={`download-${query.platform}`}
          >
            Download Query
          </button>
        </div>
      </div>

      {query.query === null ? (
        <p className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-100">
          This platform cannot express this detection as a standalone query.
        </p>
      ) : (
        <CodeBlock code={query.query} language={descriptor.highlight as HighlightLanguage} />
      )}

      {query.mappingGaps.length > 0 ? (
        <div className="rounded-lg border border-sky-500/35 bg-sky-500/10 p-3">
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-sky-200">Mapping required</p>
          <ul className="space-y-1 text-[13px] leading-relaxed text-sky-100">
            {query.mappingGaps.map((gap) => (
              <li key={gap.logical}>
                <code className="font-mono text-[12px] text-sky-200">{gap.logical}</code> — {gap.note}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {query.validationMessages.length > 0 ? (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/8 p-3">
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-amber-200">Validation messages</p>
          <ul className="list-inside list-disc space-y-1 text-[13px] leading-relaxed text-amber-100/95">
            {query.validationMessages.map((message, index) => (
              <li key={index}>{message}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {query.requiresPlatformConfiguration && query.configurationGuidance.length > 0 ? (
        <div className="rounded-lg border border-[var(--color-forge-border-strong)] bg-[var(--color-forge-panel-2)] p-3">
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-[var(--color-forge-muted)]">
            Platform configuration required
          </p>
          <BulletList items={query.configurationGuidance} />
        </div>
      ) : null}

      {query.notes.length > 0 ? (
        <details className="rounded-lg border border-[var(--color-forge-border)] bg-[var(--color-forge-panel-2)]/60 p-3">
          <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-[var(--color-forge-muted)]">
            Platform notes ({query.notes.length})
          </summary>
          <div className="mt-2">
            <BulletList items={query.notes} />
          </div>
        </details>
      ) : null}
    </div>
  );
}

export function UseCaseCard({
  useCase,
  generatedAt,
  index,
}: {
  useCase: GeneratedUseCase;
  generatedAt: string;
  index: number;
}): ReactNode {
  const [activePlatform, setActivePlatform] = useState<PlatformId>(useCase.queries[0]?.platform ?? 'splunk');
  const active = useCase.queries.find((q) => q.platform === activePlatform) ?? useCase.queries[0];
  const { spec } = useCase;

  function downloadDocument(): void {
    downloadText(
      exportFilename([spec.slug, 'detection'], 'md'),
      renderUseCaseMarkdown(useCase, generatedAt),
      'text/markdown;charset=utf-8',
    );
  }

  return (
    <article className="dfai-panel overflow-hidden" data-testid={`use-case-${index}`}>
      <header className="border-b border-[var(--color-forge-border)] bg-[var(--color-forge-panel-2)]/55 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1.5">
            <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--color-forge-muted)]">
              Use case {index + 1}
            </p>
            <h3 className="text-lg font-semibold leading-snug text-[var(--color-forge-text)]">{spec.name}</h3>
            <p className="font-mono text-[11px] text-[var(--color-forge-accent)]">{useCase.useCaseId}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={spec.severity} />
            <StatusBadge status={useCase.overallStatus} />
            <button type="button" className="dfai-btn dfai-btn-ghost px-3 py-1 text-xs" onClick={downloadDocument}>
              Download document
            </button>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap gap-1.5">
          <Chip title="Vendor">{spec.vendorId}</Chip>
          {spec.logSourceIds.map((id) => (
            <Chip key={id} title="Log source">
              {id}
            </Chip>
          ))}
          {spec.mitre.map((m) => (
            <Chip key={m.techniqueId} title={`${m.tacticName} — ${m.techniqueName}`}>
              {m.techniqueId}
            </Chip>
          ))}
        </div>
      </header>

      <div className="grid gap-5 p-5 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
        <div className="space-y-5">
          <Section title="Detection objective">
            <p className="text-sm leading-relaxed text-[var(--color-forge-text)]/90">{spec.objective}</p>
          </Section>

          <Section title="Attack scenario">
            <p className="text-sm leading-relaxed text-[var(--color-forge-text)]/90">{spec.attackScenario}</p>
          </Section>

          <Section title="Detection logic">
            <div className="space-y-3">
              {spec.stages.map((stage, stageIndex) => (
                <div
                  key={stage.id}
                  className="rounded-lg border border-[var(--color-forge-border)] bg-[var(--color-forge-panel-2)]/55 p-3"
                >
                  <p className="text-sm font-semibold text-[var(--color-forge-text)]">
                    Stage {stageIndex + 1}: {stage.name}
                  </p>
                  <p className="mt-1 text-[13px] leading-relaxed text-[var(--color-forge-muted)]">{stage.description}</p>
                  <p className="mt-2 text-[11px] uppercase tracking-wide text-[var(--color-forge-muted)]">
                    telemetry: {stage.telemetry} · match {stage.conditionLogic === 'all' ? 'ALL' : 'ANY'}
                  </p>
                  <ul className="mt-2 space-y-1">
                    {stage.conditions.map((condition, conditionIndex) => (
                      <li key={conditionIndex} className="dfai-code text-[12px] whitespace-pre-wrap">
                        <span className="tok-field">{condition.field}</span>{' '}
                        <span className="tok-keyword">{condition.operator}</span>{' '}
                        <span className="tok-string">
                          {condition.value === undefined
                            ? ''
                            : Array.isArray(condition.value)
                              ? `[${condition.value.map((v) => String(v)).join(', ')}]`
                              : String(condition.value)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
              <p className="text-[13px] leading-relaxed text-[var(--color-forge-muted)]">
                <span className="font-semibold text-[var(--color-forge-text)]/85">Correlation:</span>{' '}
                {describeCorrelation(useCase)}
              </p>
              <p className="text-[13px] leading-relaxed text-[var(--color-forge-text)]/85">
                {spec.correlation.description}
              </p>
            </div>
          </Section>

          <Section title="Required event fields">
            <div className="flex flex-wrap gap-1.5">
              {spec.requiredEventFields.map((field) => (
                <code
                  key={field}
                  className="rounded border border-[var(--color-forge-border-strong)] bg-[var(--color-forge-panel-2)] px-1.5 py-0.5 font-mono text-[11px]"
                >
                  {field}
                </code>
              ))}
            </div>
          </Section>

          <Section title="Mapping assumptions">
            <BulletList items={spec.mappingAssumptions} />
          </Section>

          <Section title="False-positive considerations">
            <BulletList items={spec.falsePositives} />
          </Section>

          <Section title="Tuning and whitelisting">
            <BulletList items={spec.tuning} />
          </Section>

          <Section title="Validation and test recommendations">
            <BulletList items={spec.validationRecommendations} />
          </Section>
        </div>

        <div className="space-y-3">
          <div
            className="flex flex-wrap gap-1.5 border-b border-[var(--color-forge-border)] pb-3"
            role="tablist"
            aria-label="SIEM platforms"
          >
            {useCase.queries.map((query) => {
              const isActive = query.platform === activePlatform;
              return (
                <button
                  key={query.platform}
                  type="button"
                  role="tab"
                  aria-selected={isActive}
                  onClick={() => setActivePlatform(query.platform)}
                  data-testid={`tab-${query.platform}`}
                  className={`rounded-lg border px-2.5 py-1.5 text-xs font-semibold transition-colors ${
                    isActive
                      ? 'border-[var(--color-forge-accent)]/60 bg-[var(--color-forge-accent)]/12 text-[var(--color-forge-accent)]'
                      : 'border-[var(--color-forge-border-strong)] bg-[var(--color-forge-panel-2)] text-[var(--color-forge-muted)] hover:text-[var(--color-forge-text)]'
                  }`}
                >
                  {PLATFORMS[query.platform].product}
                </button>
              );
            })}
          </div>
          {active ? <QueryPanel useCase={useCase} query={active} generatedAt={generatedAt} /> : null}
        </div>
      </div>
    </article>
  );
}
