/**
 * Generation orchestrator — implements the documented processing workflow:
 *
 *   input -> validate -> guardrails -> sanitise/normalise -> identify vendor &
 *   log source -> build structured specification -> invoke Hugging Face ->
 *   validate model output against schema -> render 6 SIEM formats + Sigma ->
 *   syntax & mapping checks -> cap at two use cases -> response
 *
 * Nothing in this module executes queries, touches the filesystem, or reads
 * secrets beyond the injected configuration.
 */

import {
  COMMERCIAL_NOTICE,
  LIMITS,
  MAX_USE_CASES_PER_REQUEST,
  OFF_TOPIC_REJECTION_MESSAGE,
  SYSTEM_PROMPT_VERSION,
  VALIDATION_DISCLAIMER,
  type ValidationStatus,
} from '../constants.js';
import { LOG_SOURCES, findLogSource, findVendor } from '../catalog.js';
import {
  GenerateRequestSchema,
  ModelResponseSchema,
  type DetectionSpec,
  type ErrorCode,
  type GeneratedUseCase,
  type GenerateResponse,
  type GenerationMode,
  type ModelResponse,
  type PlatformQuery,
} from '../schemas.js';
import { evaluateGuardrails, evaluateModelOutputSafety, type GuardrailCategory } from '../guardrails.js';
import { sanitiseRequirement } from '../sanitize.js';
import { buildAllPlatforms } from '../adapters/index.js';
import { validateStructure } from '../validate/syntax.js';
import { stableUuid } from '../adapters/common.js';
import { DEMO_MODEL_RESPONSE } from '../demo/fixtures.js';
import { buildSystemPrompt, buildUserPrompt } from './prompt.js';
import { InferenceError, createChatCompletion, extractJsonObject, type ClientDeps, type HuggingFaceConfig } from './client.js';

export class GenerationError extends Error {
  readonly code: ErrorCode;
  readonly details: readonly string[];
  readonly retryAfterSeconds?: number;
  /** Internal guardrail category, for metrics only. Never shown to a user. */
  readonly guardrailCategory?: GuardrailCategory;

  constructor(
    code: ErrorCode,
    message: string,
    options: {
      details?: readonly string[];
      retryAfterSeconds?: number;
      guardrailCategory?: GuardrailCategory;
    } = {},
  ) {
    super(message);
    this.name = 'GenerationError';
    this.code = code;
    this.details = options.details ?? [];
    if (options.retryAfterSeconds !== undefined) this.retryAfterSeconds = options.retryAfterSeconds;
    if (options.guardrailCategory !== undefined) this.guardrailCategory = options.guardrailCategory;
  }
}

export interface GenerationConfig {
  readonly mode: GenerationMode;
  /** Required when mode is 'live'. */
  readonly huggingFace?: HuggingFaceConfig | undefined;
  readonly maxUseCases?: number;
  /** ISO date stamped into generated rule metadata. */
  readonly generatedDate?: string;
  readonly now?: () => Date;
}

export interface GenerationDeps extends ClientDeps {
  /** Override the model layer entirely (used by demo mode and tests). */
  readonly modelOverride?: (systemPrompt: string, userPrompt: string) => Promise<ModelResponse>;
  readonly requestId?: string;
}

const STATUS_RANK: Record<ValidationStatus, number> = {
  unsupported: 0,
  mapping_required: 1,
  not_validated: 2,
  validated_syntax: 3,
};

function worstStatus(queries: readonly PlatformQuery[]): ValidationStatus {
  return queries.reduce<ValidationStatus>((worst, q) => {
    return STATUS_RANK[q.status] < STATUS_RANK[worst] ? q.status : worst;
  }, 'validated_syntax');
}

function useCaseIdFor(slug: string, date: string): string {
  const uuid = stableUuid(`usecase:${slug}:${date}`);
  const year = date.slice(0, 4);
  return `DFAI-${year}-${uuid.replace(/-/g, '').slice(0, 8).toUpperCase()}`;
}

/**
 * Deterministic telemetry inference used to decide whether a clarifying
 * question is needed before any inference spend.
 */
export function inferTelemetryHints(requirement: string): string[] {
  const lower = requirement.toLowerCase();
  const hits = new Set<string>();
  for (const source of LOG_SOURCES) {
    if (lower.includes(source.name.toLowerCase())) {
      hits.add(source.id);
      continue;
    }
    for (const keyword of source.keywords) {
      if (keyword.length >= 3 && lower.includes(keyword.toLowerCase())) {
        hits.add(source.id);
        break;
      }
    }
  }
  return [...hits];
}

function clarificationQuestion(hasVendor: boolean, hasLogSource: boolean): string {
  if (!hasVendor && !hasLogSource) {
    return 'Which vendor and log source should this detection target (for example Microsoft / Windows Security Events)?';
  }
  if (!hasLogSource) {
    return 'Which log source should this detection read from (for example Windows Security Events, Sysmon, or an EDR process table)?';
  }
  return 'Which vendor product generates this telemetry?';
}

function renderUseCase(spec: DetectionSpec, generatedDate: string): GeneratedUseCase {
  const queries = buildAllPlatforms(spec, { generatedDate }).map((platformQuery) => {
    if (platformQuery.query === null) return platformQuery;
    const issues = validateStructure(platformQuery.query, platformQuery.platform);
    if (issues.length === 0) return platformQuery;

    const messages = [...platformQuery.validationMessages];
    for (const issue of issues) {
      const text = `${issue.severity === 'error' ? 'Error' : 'Warning'}: ${issue.message}`;
      if (!messages.includes(text)) messages.push(text);
    }
    const hasError = issues.some((i) => i.severity === 'error');
    let status = platformQuery.status;
    if (hasError && status === 'validated_syntax') status = 'not_validated';
    return { ...platformQuery, status, validationMessages: messages };
  });

  return {
    useCaseId: useCaseIdFor(spec.slug, generatedDate),
    spec,
    queries,
    overallStatus: worstStatus(queries),
  };
}

export interface GenerationOutcome {
  readonly response: GenerateResponse;
  /** Observability only: never serialised to the client. */
  readonly telemetry: {
    readonly mode: GenerationMode;
    readonly model: string | null;
    readonly attempts: number;
    readonly usedFallback: boolean;
    readonly guardrailSignals: readonly string[];
    readonly redactionCount: number;
  };
}

export async function generateDetections(
  rawRequest: unknown,
  config: GenerationConfig,
  deps: GenerationDeps = {},
): Promise<GenerationOutcome> {
  const requestId = deps.requestId ?? stableUuid(`req:${Date.now()}:${Math.random()}`);
  const now = config.now ?? (() => new Date());
  const generatedAt = now().toISOString();
  const generatedDate = config.generatedDate ?? generatedAt.slice(0, 10);
  const maxUseCases = Math.min(config.maxUseCases ?? MAX_USE_CASES_PER_REQUEST, MAX_USE_CASES_PER_REQUEST);

  // ---- 1. Structural request validation ----------------------------------
  // Size is checked first so that an oversized body gets a precise code rather
  // than being lumped in with generic schema failures.
  if (
    typeof rawRequest === 'object' &&
    rawRequest !== null &&
    typeof (rawRequest as { requirement?: unknown }).requirement === 'string' &&
    (rawRequest as { requirement: string }).requirement.length > LIMITS.requirementMaxChars
  ) {
    throw new GenerationError(
      'payload_too_large',
      `The requirement exceeds the ${LIMITS.requirementMaxChars}-character limit.`,
    );
  }

  const parsed = GenerateRequestSchema.safeParse(rawRequest);
  if (!parsed.success) {
    throw new GenerationError('bad_request', 'The request payload is invalid.', {
      details: parsed.error.issues.map((i) => `${i.path.join('.') || 'body'}: ${i.message}`),
    });
  }
  const request = parsed.data;

  // ---- 2. Deterministic sanitisation -------------------------------------
  const sanitised = sanitiseRequirement(request.requirement);
  if (!sanitised.ok) {
    const code: ErrorCode =
      sanitised.code === 'too_long' ? 'payload_too_large' : sanitised.code === 'not_a_string' ? 'bad_request' : 'unsafe_input';
    throw new GenerationError(code, sanitised.reason);
  }

  const vendor = request.vendorId ? findVendor(request.vendorId) : undefined;
  const logSource = request.logSourceId ? findLogSource(request.logSourceId) : undefined;
  const hasVendor = Boolean(vendor && vendor.id !== 'multi_vendor');
  const hasLogSource = Boolean(logSource);

  // ---- 3. Guardrails (before any inference) -------------------------------
  const guardrail = evaluateGuardrails({
    requirement: sanitised.text,
    hasVendor,
    hasLogSource,
  });
  if (!guardrail.allowed) {
    throw new GenerationError('off_topic', guardrail.userMessage, {
      guardrailCategory: guardrail.category,
    });
  }

  const warnings: string[] = [];
  if (sanitised.redactions.length > 0) {
    warnings.push(
      `Sensitive content was redacted before processing and was never sent to the ` +
        `inference provider: ${sanitised.redactions.join(', ')}.`,
    );
  }

  const baseResponse = {
    ok: true as const,
    mode: config.mode,
    requestId,
    promptVersion: SYSTEM_PROMPT_VERSION,
    generatedAt,
    commercialNotice: COMMERCIAL_NOTICE,
    validationDisclaimer: VALIDATION_DISCLAIMER,
    sanitisation: { redactions: [...sanitised.redactions], normalised: sanitised.normalised },
  };

  // ---- 4. Identify vendor / log source; clarify instead of guessing -------
  if (!hasLogSource && inferTelemetryHints(sanitised.text).length === 0) {
    return {
      response: {
        ...baseResponse,
        model: null,
        useCases: [],
        clarifyingQuestion: clarificationQuestion(hasVendor, hasLogSource),
        truncatedUseCases: 0,
        warnings,
      },
      telemetry: {
        mode: config.mode,
        model: null,
        attempts: 0,
        usedFallback: false,
        guardrailSignals: guardrail.signals,
        redactionCount: sanitised.redactions.length,
      },
    };
  }

  // ---- 5. Build the structured specification request ---------------------
  const systemPrompt = buildSystemPrompt();
  const userPrompt = buildUserPrompt({
    requirement: sanitised.text,
    vendorId: request.vendorId,
    logSourceId: request.logSourceId,
    maxUseCases,
  });

  // ---- 6. Invoke the model layer -----------------------------------------
  let modelResponse: ModelResponse;
  let modelName: string | null;
  let attempts = 0;
  let usedFallback = false;

  if (deps.modelOverride) {
    modelResponse = await deps.modelOverride(systemPrompt, userPrompt);
    modelName = config.mode === 'demo' ? 'demo-fixture' : 'model-override';
  } else if (config.mode === 'demo') {
    modelResponse = DEMO_MODEL_RESPONSE;
    modelName = 'demo-fixture';
    warnings.push(
      'DEMO MODE: no Hugging Face token is configured on this backend, so these use ' +
        'cases come from a built-in synthetic fixture and were NOT generated by a ' +
        'language model.',
    );
  } else {
    const hf = config.huggingFace;
    if (!hf) {
      throw new GenerationError(
        'missing_credentials',
        'Live generation is enabled but no Hugging Face configuration is present on the backend.',
      );
    }
    let raw: string;
    try {
      const result = await createChatCompletion(
        hf,
        [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        deps,
      );
      raw = result.content;
      modelName = result.model;
      attempts = result.attempts;
      usedFallback = result.usedFallback;
    } catch (error) {
      if (error instanceof InferenceError) {
        throw new GenerationError(error.code, error.message, {
          ...(error.retryAfterSeconds !== undefined ? { retryAfterSeconds: error.retryAfterSeconds } : {}),
        });
      }
      throw new GenerationError('internal_error', 'Inference failed unexpectedly.');
    }

    if (raw.length > LIMITS.maxModelOutputChars) {
      throw new GenerationError('invalid_model_output', 'The model response exceeded the accepted size limit.');
    }

    // ---- 7. Model output is untrusted: safety scan, then schema parse ----
    const outputSafety = evaluateModelOutputSafety(raw);
    if (!outputSafety.allowed) {
      throw new GenerationError(
        'invalid_model_output',
        'The generated content failed the output safety check and was discarded.',
        { guardrailCategory: outputSafety.category },
      );
    }

    let candidate: unknown;
    try {
      candidate = JSON.parse(extractJsonObject(raw));
    } catch (error) {
      if (error instanceof InferenceError) {
        throw new GenerationError(error.code, error.message);
      }
      throw new GenerationError('invalid_model_output', 'The model response was not valid JSON.');
    }

    const validated = ModelResponseSchema.safeParse(candidate);
    if (!validated.success) {
      throw new GenerationError('invalid_model_output', 'The model response did not match the required schema.', {
        details: validated.error.issues.slice(0, 12).map((i) => `${i.path.join('.') || 'root'}: ${i.message}`),
      });
    }
    modelResponse = validated.data;
    if (usedFallback) {
      warnings.push('The primary inference model was unavailable; a configured fallback model was used.');
    }
  }

  if (modelResponse.status === 'out_of_scope') {
    throw new GenerationError('off_topic', OFF_TOPIC_REJECTION_MESSAGE, { guardrailCategory: 'no_detection_intent' });
  }

  if (modelResponse.status === 'needs_clarification') {
    return {
      response: {
        ...baseResponse,
        model: modelName,
        useCases: [],
        clarifyingQuestion: modelResponse.clarifyingQuestion ?? clarificationQuestion(hasVendor, hasLogSource),
        truncatedUseCases: 0,
        warnings,
      },
      telemetry: {
        mode: config.mode,
        model: modelName,
        attempts,
        usedFallback,
        guardrailSignals: guardrail.signals,
        redactionCount: sanitised.redactions.length,
      },
    };
  }

  // ---- 8. Commercial guardrail: hard cap of two use cases ----------------
  const unique: DetectionSpec[] = [];
  const seenSlugs = new Set<string>();
  for (const spec of modelResponse.useCases) {
    if (seenSlugs.has(spec.slug)) continue;
    seenSlugs.add(spec.slug);
    unique.push(spec);
  }
  const selected = unique.slice(0, maxUseCases);
  const truncatedUseCases = Math.max(0, unique.length - selected.length);

  if (selected.length === 0) {
    throw new GenerationError('invalid_model_output', 'No usable detection use case was produced.');
  }

  // ---- 9. Render all seven formats + structural validation ---------------
  const useCases = selected.map((spec) => renderUseCase(spec, generatedDate));

  if (truncatedUseCases > 0) {
    warnings.push(
      `${truncatedUseCases} additional eligible use case(s) were generated but withheld ` +
        `by the ${MAX_USE_CASES_PER_REQUEST}-use-case limit.`,
    );
  }
  const anyMappingGaps = useCases.some((u) => u.queries.some((q) => q.mappingGaps.length > 0));
  if (anyMappingGaps) {
    warnings.push(
      'Some platforms have undocumented field mappings for this telemetry. Those outputs ' +
        'are marked "Mapping Required" and contain placeholders instead of guessed field names.',
    );
  }

  return {
    response: {
      ...baseResponse,
      model: modelName,
      useCases,
      clarifyingQuestion: null,
      truncatedUseCases,
      warnings,
    },
    telemetry: {
      mode: config.mode,
      model: modelName,
      attempts,
      usedFallback,
      guardrailSignals: guardrail.signals,
      redactionCount: sanitised.redactions.length,
    },
  };
}
