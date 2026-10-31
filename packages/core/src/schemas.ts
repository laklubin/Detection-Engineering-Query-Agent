/**
 * Zod schemas for every trust boundary in DetectionForge AI.
 *
 *   1. `GenerateRequestSchema`   — browser  -> backend   (untrusted)
 *   2. `ModelResponseSchema`     — model    -> backend   (untrusted)
 *   3. `GenerateResponseSchema`  — backend  -> browser   (shape contract)
 *
 * Model output is treated with exactly the same suspicion as user input: it is
 * parsed, not trusted. Identifier-shaped values that will be interpolated into
 * query text are constrained by regex so that generated queries cannot be used
 * as an injection channel.
 */

import { z } from 'zod';
import { LIMITS, MAX_USE_CASES_PER_REQUEST, PLATFORM_IDS, SEVERITIES, VALIDATION_STATUSES } from './constants.js';
import { LOG_SOURCE_IDS, TELEMETRY_FAMILIES, VENDOR_IDS } from './catalog.js';

// ---------------------------------------------------------------------------
// Primitive guards
// ---------------------------------------------------------------------------

/**
 * A logical field name. Deliberately narrow: lowercase, dots and underscores
 * only. Anything that could terminate a string literal, start a comment or
 * inject a pipeline operator is impossible to express.
 */
export const LogicalFieldSchema = z
  .string()
  .min(2)
  .max(64)
  .regex(/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$/, 'logical field must be lower_snake dotted path');

/** Short machine identifier used for stage ids and use-case slugs. */
export const SlugSchema = z
  .string()
  .min(2)
  .max(48)
  .regex(/^[a-z0-9][a-z0-9_-]*$/, 'slug must be lowercase alphanumeric with - or _');

/** Human-readable text that will be rendered (escaped) in the UI. */
const prose = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    // Control characters are stripped earlier; reject them here as a backstop.
    // eslint-disable-next-line no-control-regex -- deliberately matching control characters
    .refine((s) => !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(s), {
      message: 'control characters are not permitted',
    });

export const MITRE_TECHNIQUE_RE = /^T\d{4}(?:\.\d{3})?$/;
export const MITRE_TACTIC_RE = /^TA\d{4}$/;

export const MitreReferenceSchema = z.object({
  tacticId: z.string().regex(MITRE_TACTIC_RE, 'tactic id must look like TA0002').optional(),
  tacticName: prose(80),
  techniqueId: z.string().regex(MITRE_TECHNIQUE_RE, 'technique id must look like T1059 or T1059.001'),
  techniqueName: prose(140),
});
export type MitreReference = z.infer<typeof MitreReferenceSchema>;

// ---------------------------------------------------------------------------
// Detection logic intermediate representation (IR)
// ---------------------------------------------------------------------------

export const CONDITION_OPERATORS = [
  'equals',
  'not_equals',
  'contains',
  'not_contains',
  'startswith',
  'not_startswith',
  'endswith',
  'not_endswith',
  'regex',
  'not_regex',
  'in',
  'not_in',
  'gt',
  'gte',
  'lt',
  'lte',
  'exists',
  'not_exists',
] as const;
export type ConditionOperator = (typeof CONDITION_OPERATORS)[number];

/** Operators that take no value. */
export const VALUELESS_OPERATORS: readonly ConditionOperator[] = ['exists', 'not_exists'];
/** Operators that take a list of values. */
export const LIST_OPERATORS: readonly ConditionOperator[] = ['in', 'not_in'];
/** Operators that require a numeric value. */
export const NUMERIC_OPERATORS: readonly ConditionOperator[] = ['gt', 'gte', 'lt', 'lte'];

const ScalarValueSchema = z.union([z.string().max(512), z.number().finite(), z.boolean()]);

export const ConditionSchema = z
  .object({
    field: LogicalFieldSchema,
    operator: z.enum(CONDITION_OPERATORS),
    value: z.union([ScalarValueSchema, z.array(ScalarValueSchema).min(1).max(64)]).optional(),
    caseSensitive: z.boolean().optional(),
    /** Why this predicate exists — rendered as documentation, never executed. */
    rationale: prose(240).optional(),
  })
  .superRefine((cond, ctx) => {
    const needsValue = !VALUELESS_OPERATORS.includes(cond.operator);
    if (needsValue && cond.value === undefined) {
      ctx.addIssue({ code: 'custom', message: `operator "${cond.operator}" requires a value` });
      return;
    }
    if (!needsValue && cond.value !== undefined) {
      ctx.addIssue({ code: 'custom', message: `operator "${cond.operator}" must not carry a value` });
    }
    if (LIST_OPERATORS.includes(cond.operator) && !Array.isArray(cond.value)) {
      ctx.addIssue({ code: 'custom', message: `operator "${cond.operator}" requires an array value` });
    }
    if (!LIST_OPERATORS.includes(cond.operator) && Array.isArray(cond.value)) {
      ctx.addIssue({ code: 'custom', message: `operator "${cond.operator}" must not take an array` });
    }
    if (NUMERIC_OPERATORS.includes(cond.operator) && typeof cond.value !== 'number') {
      ctx.addIssue({ code: 'custom', message: `operator "${cond.operator}" requires a numeric value` });
    }
    if ((cond.operator === 'regex' || cond.operator === 'not_regex') && typeof cond.value === 'string') {
      try {
        // Compile to prove it is a usable pattern. Never executed against input.
        new RegExp(cond.value);
      } catch {
        ctx.addIssue({ code: 'custom', message: 'regex value is not a valid regular expression' });
      }
      if (cond.value.length > 256) {
        ctx.addIssue({ code: 'custom', message: 'regex value is too long' });
      }
    }
  });
export type Condition = z.infer<typeof ConditionSchema>;

export const StageSchema = z.object({
  id: SlugSchema,
  name: prose(120),
  description: prose(500),
  /** Telemetry family this stage reads from — enables cross-source correlation. */
  telemetry: z.enum(TELEMETRY_FAMILIES),
  conditionLogic: z.enum(['all', 'any']).default('all'),
  conditions: z.array(ConditionSchema).min(1).max(16),
});
export type Stage = z.infer<typeof StageSchema>;

export const CORRELATION_TYPES = ['single_event', 'threshold', 'sequence'] as const;
export type CorrelationType = (typeof CORRELATION_TYPES)[number];

export const CorrelationSchema = z
  .object({
    type: z.enum(CORRELATION_TYPES),
    /** Logical fields used to pivot/group the correlation. */
    groupBy: z.array(LogicalFieldSchema).max(6).default([]),
    /** Correlation window in seconds (30s .. 7d). */
    timeWindowSeconds: z.number().int().min(30).max(604_800),
    /** Event count threshold; required for `threshold` correlation. */
    eventThreshold: z.number().int().min(1).max(100_000).optional(),
    /** Distinct-count threshold over `thresholdField`. */
    distinctThreshold: z.number().int().min(1).max(100_000).optional(),
    thresholdField: LogicalFieldSchema.optional(),
    /** For sequences: must stages occur in the declared order? */
    ordered: z.boolean().default(true),
    description: prose(400),
  })
  .superRefine((c, ctx) => {
    if (c.type === 'threshold' && c.eventThreshold === undefined && c.distinctThreshold === undefined) {
      ctx.addIssue({ code: 'custom', message: 'threshold correlation requires eventThreshold or distinctThreshold' });
    }
    if (c.distinctThreshold !== undefined && c.thresholdField === undefined) {
      ctx.addIssue({ code: 'custom', message: 'distinctThreshold requires thresholdField' });
    }
  });
export type Correlation = z.infer<typeof CorrelationSchema>;

/**
 * The normalised, vendor-neutral detection specification. Adapters consume this
 * and nothing else — they never see raw user input or raw model text.
 */
export const DetectionSpecSchema = z
  .object({
    slug: SlugSchema,
    name: prose(140),
    objective: prose(600),
    attackScenario: prose(1200),
    vendorId: z.enum(VENDOR_IDS as [string, ...string[]]),
    logSourceIds: z.array(z.enum(LOG_SOURCE_IDS as [string, ...string[]])).min(1).max(6),
    requiredEventFields: z.array(LogicalFieldSchema).min(1).max(32),
    mappingAssumptions: z.array(prose(400)).max(12).default([]),
    mitre: z.array(MitreReferenceSchema).max(8).default([]),
    stages: z.array(StageSchema).min(1).max(4),
    correlation: CorrelationSchema,
    severity: z.enum(SEVERITIES),
    falsePositives: z.array(prose(400)).min(1).max(12),
    tuning: z.array(prose(400)).min(1).max(12),
    validationRecommendations: z.array(prose(400)).min(1).max(12),
  })
  .superRefine((spec, ctx) => {
    const ids = new Set<string>();
    for (const stage of spec.stages) {
      if (ids.has(stage.id)) {
        ctx.addIssue({ code: 'custom', message: `duplicate stage id "${stage.id}"` });
      }
      ids.add(stage.id);
    }
    if (spec.correlation.type === 'sequence' && spec.stages.length < 2) {
      ctx.addIssue({ code: 'custom', message: 'sequence correlation requires at least two stages' });
    }
    if (spec.correlation.type === 'single_event' && spec.stages.length !== 1) {
      ctx.addIssue({ code: 'custom', message: 'single_event correlation requires exactly one stage' });
    }
  });
export type DetectionSpec = z.infer<typeof DetectionSpecSchema>;

// ---------------------------------------------------------------------------
// Model contract
// ---------------------------------------------------------------------------

export const MODEL_RESPONSE_STATUSES = ['ok', 'needs_clarification', 'out_of_scope'] as const;

/**
 * What the LLM is contractually required to emit. The model produces detection
 * *logic*, never platform query strings — query rendering is deterministic and
 * happens in the adapters, so the model cannot smuggle arbitrary text into an
 * exported query.
 */
export const ModelResponseSchema = z
  .object({
    status: z.enum(MODEL_RESPONSE_STATUSES),
    clarifyingQuestion: prose(300).optional(),
    useCases: z.array(DetectionSpecSchema).max(MAX_USE_CASES_PER_REQUEST * 3).default([]),
  })
  .superRefine((r, ctx) => {
    if (r.status === 'ok' && r.useCases.length === 0) {
      ctx.addIssue({ code: 'custom', message: 'status "ok" requires at least one use case' });
    }
    if (r.status === 'needs_clarification' && !r.clarifyingQuestion) {
      ctx.addIssue({ code: 'custom', message: 'needs_clarification requires clarifyingQuestion' });
    }
  });
export type ModelResponse = z.infer<typeof ModelResponseSchema>;

// ---------------------------------------------------------------------------
// API request / response
// ---------------------------------------------------------------------------

export const GenerateRequestSchema = z
  .object({
    requirement: z
      .string()
      .min(LIMITS.requirementMinChars, `requirement must be at least ${LIMITS.requirementMinChars} characters`)
      .max(LIMITS.requirementMaxChars, `requirement must be at most ${LIMITS.requirementMaxChars} characters`),
    vendorId: z.enum(VENDOR_IDS as [string, ...string[]]).optional(),
    logSourceId: z.enum(LOG_SOURCE_IDS as [string, ...string[]]).optional(),
    /** Echoed back for client-side correlation. Opaque, never logged. */
    clientRequestId: z.string().regex(/^[A-Za-z0-9_-]{8,64}$/).optional(),
  })
  .strict();
export type GenerateRequest = z.infer<typeof GenerateRequestSchema>;

export const MappingGapSchema = z.object({
  logical: z.string(),
  note: z.string(),
});

export const PlatformQuerySchema = z.object({
  platform: z.enum(PLATFORM_IDS),
  product: z.string(),
  language: z.string(),
  /** Null when the platform cannot express this detection as a query. */
  query: z.string().nullable(),
  status: z.enum(VALIDATION_STATUSES),
  validationMessages: z.array(z.string()),
  mappingGaps: z.array(MappingGapSchema),
  notes: z.array(z.string()),
  /** True when proprietary rule/policy configuration is also required. */
  requiresPlatformConfiguration: z.boolean(),
  configurationGuidance: z.array(z.string()),
});
export type PlatformQuery = z.infer<typeof PlatformQuerySchema>;

export const GeneratedUseCaseSchema = z.object({
  /** Stable unique identifier, e.g. DFAI-2026-7F3A91. */
  useCaseId: z.string(),
  spec: DetectionSpecSchema,
  queries: z.array(PlatformQuerySchema),
  /** Aggregate status across platforms. */
  overallStatus: z.enum(VALIDATION_STATUSES),
});
export type GeneratedUseCase = z.infer<typeof GeneratedUseCaseSchema>;

export const GENERATION_MODES = ['live', 'demo'] as const;
export type GenerationMode = (typeof GENERATION_MODES)[number];

export const GenerateResponseSchema = z.object({
  ok: z.literal(true),
  mode: z.enum(GENERATION_MODES),
  requestId: z.string(),
  model: z.string().nullable(),
  promptVersion: z.string(),
  generatedAt: z.string(),
  useCases: z.array(GeneratedUseCaseSchema).max(MAX_USE_CASES_PER_REQUEST),
  /** Set when the model needs more information before generating. */
  clarifyingQuestion: z.string().nullable(),
  /** Number of eligible use cases that were discarded by the 2-case cap. */
  truncatedUseCases: z.number().int().min(0),
  commercialNotice: z.string(),
  validationDisclaimer: z.string(),
  warnings: z.array(z.string()),
  /** Sanitisation actions applied, for transparency. */
  sanitisation: z.object({
    redactions: z.array(z.string()),
    normalised: z.boolean(),
  }),
});
export type GenerateResponse = z.infer<typeof GenerateResponseSchema>;

export const ERROR_CODES = [
  'bad_request',
  'off_topic',
  'unsafe_input',
  'payload_too_large',
  'unauthorized',
  'forbidden_origin',
  'rate_limited',
  'quota_exceeded',
  'model_unavailable',
  'credits_exhausted',
  'upstream_timeout',
  'invalid_model_output',
  'missing_credentials',
  'internal_error',
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

export const ErrorResponseSchema = z.object({
  ok: z.literal(false),
  code: z.enum(ERROR_CODES),
  message: z.string(),
  requestId: z.string(),
  details: z.array(z.string()).optional(),
  retryAfterSeconds: z.number().int().optional(),
});
export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
