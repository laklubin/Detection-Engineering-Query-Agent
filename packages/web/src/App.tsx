import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  LOG_SOURCES,
  PLATFORMS,
  VENDORS,
  APP_NAME,
  APP_SUBTITLE,
  COMMERCIAL_NOTICE,
  LIMITS,
  MAX_USE_CASES_PER_REQUEST,
  OFF_TOPIC_REJECTION_MESSAGE,
  PLATFORM_IDS,
  SYSTEM_PROMPT_VERSION,
  VALIDATION_DISCLAIMER,
  exportFilename,
  generateDetections,
  renderBundleJson,
  renderBundleMarkdown,
  type GenerateResponse,
} from '@detectionforge/core';
import { ApiError, DetectionForgeApi, type Catalog, type Health } from './lib/api.js';
import {
  buildConfig,
  describeBrowserInferenceFailure,
  forget as forgetKey,
  loadRemembered,
  remember as rememberKey,
  type InferenceSettings,
} from './lib/byok.js';
import { downloadText } from './lib/download.js';
import { InferenceSettingsPanel } from './components/InferenceSettings.js';
import { RequirementForm, type FormState } from './components/RequirementForm.js';
import { UseCaseCard } from './components/UseCaseCard.js';
import {
  ClarifyingQuestion,
  CommercialNotice,
  DemoBanner,
  ErrorNotice,
  WarningList,
} from './components/Notifications.js';
import { Chip } from './components/Primitives.js';

const API_BASE_URL = (import.meta.env['VITE_API_BASE_URL'] as string | undefined) ?? '';
const ALLOW_LOCAL_DEMO = (import.meta.env['VITE_ALLOW_LOCAL_DEMO'] as string | undefined) !== 'false';

/**
 * Fallback catalogue built from the compiled core package. Used before the
 * backend catalogue loads, and when the backend is unreachable and the operator
 * has enabled the explicitly-labelled local demo.
 */
function localCatalog(): Catalog {
  return {
    vendors: VENDORS.map((vendor) => ({ ...vendor })),
    logSources: LOG_SOURCES.map((source) => ({ ...source, keywords: [...source.keywords] })),
    platforms: PLATFORM_IDS.map((id) => ({
      id,
      product: PLATFORMS[id].product,
      language: PLATFORMS[id].language,
      highlight: PLATFORMS[id].highlight,
      fileExtension: PLATFORMS[id].fileExtension,
      standaloneQueryIsDeployable: PLATFORMS[id].standaloneQueryIsDeployable,
      notes: PLATFORMS[id].notes,
    })),
    limits: {
      requirementMinChars: LIMITS.requirementMinChars,
      requirementMaxChars: LIMITS.requirementMaxChars,
      maxUseCasesPerRequest: MAX_USE_CASES_PER_REQUEST,
    },
    notices: {
      commercial: COMMERCIAL_NOTICE,
      offTopicRejection: OFF_TOPIC_REJECTION_MESSAGE,
      validationDisclaimer: VALIDATION_DISCLAIMER,
    },
  };
}

type Phase = 'idle' | 'loading-catalog' | 'generating' | 'done' | 'error';

const EMPTY_FORM: FormState = { requirement: '', vendorId: '', logSourceId: '' };

export function App(): ReactNode {
  const api = useMemo(() => new DetectionForgeApi(API_BASE_URL), []);
  const [catalog, setCatalog] = useState<Catalog>(() => localCatalog());
  const [health, setHealth] = useState<Health | null>(null);
  const [backendReachable, setBackendReachable] = useState<boolean | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [phase, setPhase] = useState<Phase>('loading-catalog');
  const [result, setResult] = useState<GenerateResponse | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [statusLine, setStatusLine] = useState<string>('Ready.');
  const [byok, setByok] = useState<InferenceSettings | null>(null);
  const logSourceInputRef = useRef<HTMLInputElement | null>(null);

  // Restore a key the visitor chose to keep for this tab.
  useEffect(() => {
    const stored = loadRemembered();
    if (stored) setByok({ ...stored, remember: true });
  }, []);

  // --- bootstrap: health + catalogue ---------------------------------------
  useEffect(() => {
    let cancelled = false;
    async function bootstrap(): Promise<void> {
      if (!api.configured) {
        if (!cancelled) {
          setBackendReachable(false);
          setPhase('idle');
          setStatusLine('Template mode: matching against the built-in detection catalogue in your browser.');
        }
        return;
      }
      try {
        const [healthPayload, catalogPayload] = await Promise.all([api.health(), api.catalog()]);
        if (cancelled) return;
        setHealth(healthPayload);
        setCatalog(catalogPayload);
        setBackendReachable(true);
        setPhase('idle');
        setStatusLine(
          healthPayload.mode === 'live'
            ? `Connected. Live inference via ${healthPayload.model ?? 'configured model'}.`
            : 'Connected. Backend is in template mode (no inference credential configured).',
        );
      } catch {
        if (cancelled) return;
        setBackendReachable(false);
        setPhase('idle');
        setStatusLine('Backend unreachable. Running in template mode in your browser.');
      }
    }
    void bootstrap();
    return () => {
      cancelled = true;
    };
  }, [api]);

  const runGenerate = useCallback(
    async (localDemo: boolean): Promise<void> => {
      setPhase('generating');
      setError(null);
      setResult(null);
      setStatusLine(
        byok
          ? 'Asking your configured model…'
          : localDemo
            ? 'Matching against the detection template catalogue…'
            : 'Validating input and generating…',
      );

      const request = {
        requirement: form.requirement,
        ...(form.vendorId ? { vendorId: form.vendorId } : {}),
        ...(form.logSourceId ? { logSourceId: form.logSourceId } : {}),
      };

      try {
        let response: GenerateResponse;
        if (byok) {
          // The visitor's own key. The same core pipeline runs here as on the
          // server: sanitise, guardrails, inference, schema validation,
          // adapters. The key reaches Hugging Face and nothing else.
          const outcome = await generateDetections(request, {
            mode: 'live',
            huggingFace: buildConfig(byok),
          });
          response = outcome.response;
        } else if (localDemo) {
          // Runs the identical core pipeline in the browser against the
          // detection-template catalogue. No credential is involved and
          // nothing the user typed leaves the page.
          const outcome = await generateDetections(request, { mode: 'demo' });
          response = outcome.response;
        } else {
          response = await api.generate(request);
        }
        setResult(response);
        setPhase('done');
        if (response.clarifyingQuestion) {
          setStatusLine('More information needed before generating.');
        } else {
          setStatusLine(
            `Generated ${response.useCases.length} use case${response.useCases.length === 1 ? '' : 's'} × ` +
              `${PLATFORM_IDS.length} formats${response.mode === 'demo' ? ' (template mode)' : ''}.`,
          );
        }
      } catch (caught) {
        const rawCode = (caught as { code?: string }).code ?? 'internal_error';
        const rawMessage = caught instanceof Error ? caught.message : 'Generation failed.';
        const apiError =
          caught instanceof ApiError
            ? caught
            : new ApiError(
                rawCode,
                // A browser-side call fails in ways a server call does not, so
                // translate the code into something the visitor can act on.
                byok ? describeBrowserInferenceFailure(rawCode, rawMessage) : rawMessage,
                { details: [...((caught as { details?: string[] }).details ?? [])] },
              );
        setError(apiError);
        setPhase('error');
        setStatusLine('Generation failed.');
      }
    },
    [api, form, byok],
  );

  function clearAll(): void {
    setForm(EMPTY_FORM);
    setResult(null);
    setError(null);
    setPhase('idle');
    setStatusLine('Cleared.');
    api.forgetSession();
  }

  function downloadBundle(format: 'md' | 'json'): void {
    if (!result) return;
    const filename = exportFilename(['detectionforge', result.requestId], format);
    if (format === 'md') {
      downloadText(filename, renderBundleMarkdown(result), 'text/markdown;charset=utf-8');
    } else {
      downloadText(filename, renderBundleJson(result), 'application/json;charset=utf-8');
    }
  }

  function applyKey(next: InferenceSettings): void {
    setByok(next);
    if (next.remember) rememberKey({ token: next.token, model: next.model });
    else forgetKey();
    setStatusLine(`Live inference enabled with ${next.model}.`);
  }

  function clearKey(): void {
    setByok(null);
    forgetKey();
    setStatusLine('Key removed. Back to template mode.');
  }

  const busy = phase === 'generating';
  const offline = backendReachable === false;
  const effectiveMode = byok ? 'live' : (result?.mode ?? health?.mode ?? (offline ? 'demo' : null));

  return (
    <div className="mx-auto max-w-[94rem] px-4 py-6 sm:px-6 lg:px-8">
      <header className="mb-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <svg aria-hidden="true" viewBox="0 0 32 32" className="h-9 w-9 shrink-0">
                <rect width="32" height="32" rx="7" fill="#0b1220" />
                <path d="M16 4l9 4v8c0 6-4 9-9 12-5-3-9-6-9-12V8z" fill="none" stroke="#22d3ee" strokeWidth="2" />
                <path d="M11 16l3.5 3.5L21 13" fill="none" stroke="#34d399" strokeWidth="2.2" strokeLinecap="round" />
              </svg>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-[var(--color-forge-text)] sm:text-3xl">
                  {APP_NAME}
                </h1>
                <p className="text-sm text-[var(--color-forge-muted)]">{APP_SUBTITLE}</p>
              </div>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            {effectiveMode ? (
              <Chip
                title={
                  effectiveMode === 'live'
                    ? 'Live model inference'
                    : 'Matched from the built-in detection template catalogue, not written by a model'
                }
              >
                {effectiveMode === 'live' ? 'live inference' : 'template mode'}
              </Chip>
            ) : null}
            <Chip title="Supported query formats">{PLATFORM_IDS.length} formats</Chip>
            <Chip title="Detection engineering system prompt version">prompt v{health?.promptVersion ?? SYSTEM_PROMPT_VERSION}</Chip>
            {health ? (
              <Chip title={health.rateLimitDurable ? 'Durable rate limiting' : 'Best-effort in-memory rate limiting'}>
                {health.rateLimitDurable ? 'durable limits' : 'in-memory limits'}
              </Chip>
            ) : null}
          </div>
        </div>
      </header>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
        <div className="space-y-4">
          <RequirementForm
            catalog={catalog}
            state={form}
            onChange={setForm}
            onSubmit={() => void runGenerate(offline)}
            onClear={clearAll}
            busy={busy}
            logSourceInputRef={logSourceInputRef}
          />

          <InferenceSettingsPanel
            settings={byok}
            onApply={applyKey}
            onClear={clearKey}
            active={byok !== null}
            busy={busy}
          />

          <div
            className="dfai-panel p-4 text-sm"
            role="status"
            aria-live="polite"
            data-testid="status-line"
          >
            <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--color-forge-muted)]">
              Generation status
            </p>
            <p className="mt-1 leading-relaxed text-[var(--color-forge-text)]/90">{statusLine}</p>
          </div>

          {offline && ALLOW_LOCAL_DEMO && !byok ? (
            <div className="rounded-xl border border-violet-500/40 bg-violet-500/10 p-4 text-sm text-violet-100">
              <p className="font-semibold text-violet-200">Running in template mode</p>
              <p className="mt-1 leading-relaxed">
                No inference backend is configured for this deployment, so generation runs entirely in your browser:
                your requirement is matched against a catalogue of human-authored detection templates and rendered
                through the identical guardrail, sanitisation, adapter and validation pipeline. Nothing you type
                leaves your browser, and no Hugging Face token exists in this page — a public static bundle could
                never hold one safely.
              </p>
            </div>
          ) : null}

          <div className="dfai-panel space-y-2 p-4 text-[13px] leading-relaxed text-[var(--color-forge-muted)]">
            <p className="text-[11px] font-semibold uppercase tracking-[0.14em]">Scope</p>
            <p>
              This platform generates defensive detection logic only. Unrelated programming requests, offensive
              tooling and attempts to extract configuration are rejected by the backend before any inference call.
            </p>
            <p>{VALIDATION_DISCLAIMER}</p>
          </div>
        </div>

        <div className="space-y-4">
          {error ? (
            <ErrorNotice
              title={error.code === 'off_topic' ? 'Request out of scope' : 'Generation error'}
              message={error.message}
              code={error.code}
              details={error.details}
              onDismiss={() => {
                setError(null);
                setPhase('idle');
              }}
            />
          ) : null}

          {result?.mode === 'demo' ? <DemoBanner model={result.model} /> : null}

          {result?.clarifyingQuestion ? (
            <ClarifyingQuestion
              question={result.clarifyingQuestion}
              onFocusLogSource={() => logSourceInputRef.current?.focus()}
            />
          ) : null}

          {result && result.warnings.length > 0 ? <WarningList warnings={result.warnings} /> : null}

          {result && result.useCases.length > 0 ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2.5">
                <p className="text-sm text-[var(--color-forge-muted)]">
                  <span className="font-semibold text-[var(--color-forge-text)]">{result.useCases.length}</span> use
                  case{result.useCases.length === 1 ? '' : 's'} ·{' '}
                  <span className="font-semibold text-[var(--color-forge-text)]">{PLATFORM_IDS.length}</span> formats
                  each · request <code className="font-mono text-[11px]">{result.requestId}</code>
                </p>
                <div className="flex gap-2">
                  <button type="button" className="dfai-btn dfai-btn-ghost px-3 py-1 text-xs" onClick={() => downloadBundle('md')}>
                    Download all (Markdown)
                  </button>
                  <button type="button" className="dfai-btn dfai-btn-ghost px-3 py-1 text-xs" onClick={() => downloadBundle('json')}>
                    Download all (JSON)
                  </button>
                </div>
              </div>

              {result.useCases.map((useCase, index) => (
                <UseCaseCard key={useCase.useCaseId} useCase={useCase} generatedAt={result.generatedAt} index={index} />
              ))}

              <CommercialNotice notice={result.commercialNotice} />
            </>
          ) : null}

          {!result && !error ? (
            <div className="dfai-panel flex min-h-[18rem] flex-col items-center justify-center gap-2 p-8 text-center">
              <p className="text-base font-semibold text-[var(--color-forge-text)]">No detections generated yet</p>
              <p className="max-w-xl text-sm leading-relaxed text-[var(--color-forge-muted)]">
                Describe a detection requirement in natural language, or pick a vendor and log source, then choose
                Generate Detection. Each use case is rendered for Splunk, Microsoft Sentinel, IBM QRadar, Elastic
                Security, Securonix, FortiSIEM and Sigma, with explicit mapping and validation status.
              </p>
            </div>
          ) : null}
        </div>
      </div>

      <footer className="mt-10 border-t border-[var(--color-forge-border)] pt-5 text-xs leading-relaxed text-[var(--color-forge-muted)]">
        <p>
          {APP_NAME} · generated detection content is read-only. Nothing in this interface deploys a query to a SIEM,
          and no SIEM credentials are held by this application.
        </p>
      </footer>
    </div>
  );
}
