/**
 * Shared, side-effect-free helpers for the SIEM adapters.
 *
 * Every value that reaches generated query text passes through a literal
 * escaper here. Adapters never concatenate a raw value into a query.
 */

import type { PlatformId, ValidationStatus } from '../constants.js';
import { PLATFORMS } from '../constants.js';
import type { TelemetryFamily } from '../catalog.js';
import { findLogSource } from '../catalog.js';
import type { Condition, DetectionSpec, PlatformQuery, Stage } from '../schemas.js';
import { resolveField, type ResolvedField } from '../mappings/fields.js';

/** Strip anything that could break out of a quoted literal or a line. */
export function scrubLiteral(value: string): string {
  return value
    // eslint-disable-next-line no-control-regex -- stripping control characters from query literals
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function stringifyValue(value: Condition['value']): string {
  if (value === undefined) return '';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (Array.isArray(value)) return value.map((v) => stringifyValue(v)).join(', ');
  return scrubLiteral(value);
}

/** Double-quoted literal with backslash escaping (SPL, KQL, EQL, ES|QL). */
export function dq(value: unknown): string {
  const raw = typeof value === 'string' ? scrubLiteral(value) : String(value);
  return `"${raw.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/** Single-quoted literal with SQL-style doubling (AQL). */
export function sq(value: unknown): string {
  const raw = typeof value === 'string' ? scrubLiteral(value) : String(value);
  return `'${raw.replace(/'/g, "''")}'`;
}

export function asArray(value: Condition['value']): (string | number | boolean)[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? [...value] : [value];
}

export function isNumericLike(value: Condition['value']): boolean {
  return typeof value === 'number';
}

// ---------------------------------------------------------------------------
// Mapping resolution
// ---------------------------------------------------------------------------

export interface MappingContext {
  readonly platform: PlatformId;
  /** Resolved field per (stage telemetry, logical field) key. */
  readonly resolved: Map<string, ResolvedField>;
  readonly gaps: { logical: string; note: string }[];
  readonly notes: Set<string>;
}

function key(telemetry: TelemetryFamily, logical: string): string {
  return `${telemetry}::${logical}`;
}

export function createMappingContext(platform: PlatformId): MappingContext {
  return { platform, resolved: new Map(), gaps: [], notes: new Set() };
}

/**
 * Resolve a logical field for a platform, recording mapping gaps and caveats.
 * Returns null when no documented mapping exists — the caller must then emit a
 * "Mapping Required" marker instead of inventing a field name.
 */
export function mapField(
  ctx: MappingContext,
  logical: string,
  telemetry: TelemetryFamily,
): string | null {
  const k = key(telemetry, logical);
  let resolved = ctx.resolved.get(k);
  if (!resolved) {
    resolved = resolveField(logical, ctx.platform, telemetry);
    ctx.resolved.set(k, resolved);
    if (resolved.status === 'mapping_required') {
      if (!ctx.gaps.some((g) => g.logical === logical)) {
        ctx.gaps.push({ logical, note: resolved.note ?? 'No documented mapping.' });
      }
    } else if (resolved.note) {
      ctx.notes.add(`${logical} -> ${resolved.physical}: ${resolved.note}`);
    }
  }
  return resolved.physical;
}

/** Placeholder emitted inline when a mapping is unavailable. */
export function mappingPlaceholder(logical: string): string {
  return `<<MAPPING_REQUIRED:${logical}>>`;
}

export function mapFieldOrPlaceholder(
  ctx: MappingContext,
  logical: string,
  telemetry: TelemetryFamily,
): string {
  return mapField(ctx, logical, telemetry) ?? mappingPlaceholder(logical);
}

// ---------------------------------------------------------------------------
// Spec helpers
// ---------------------------------------------------------------------------

export function primaryTelemetry(spec: DetectionSpec): TelemetryFamily {
  const first = spec.stages[0];
  if (first) return first.telemetry;
  const source = spec.logSourceIds[0] ? findLogSource(spec.logSourceIds[0]) : undefined;
  return source?.telemetry ?? 'generic';
}

export function stageTelemetries(spec: DetectionSpec): TelemetryFamily[] {
  return [...new Set(spec.stages.map((s) => s.telemetry))];
}

export function humanWindow(seconds: number): string {
  if (seconds % 86_400 === 0) return `${seconds / 86_400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

export function stageComment(stage: Stage, index: number): string {
  return `Stage ${index + 1} (${stage.id}): ${stage.name}`;
}

/** Wrap a list of predicate strings with the stage's AND/OR logic. */
export function joinPredicates(
  predicates: readonly string[],
  logic: 'all' | 'any',
  operators: { and: string; or: string } = { and: 'AND', or: 'OR' },
): string {
  const usable = predicates.filter((p) => p.length > 0);
  if (usable.length === 0) return '';
  if (usable.length === 1) return usable[0] as string;
  const glue = logic === 'all' ? ` ${operators.and} ` : ` ${operators.or} `;
  return usable.map((p) => (usable.length > 1 ? `(${p})` : p)).join(glue);
}

// ---------------------------------------------------------------------------
// Result assembly
// ---------------------------------------------------------------------------

export interface BuildResultInput {
  readonly platform: PlatformId;
  readonly query: string | null;
  readonly ctx: MappingContext;
  readonly syntaxMessages: readonly string[];
  readonly requiresPlatformConfiguration: boolean;
  readonly configurationGuidance: readonly string[];
  readonly extraNotes?: readonly string[];
  /** Force a status, e.g. 'unsupported'. */
  readonly forcedStatus?: ValidationStatus;
}

/**
 * Decide the honest status for a platform output.
 *
 *   mapping_required  — at least one referenced field has no documented mapping
 *   not_validated     — syntax check failed, or deployment needs proprietary
 *                       rule configuration this tool cannot emit
 *   validated_syntax  — structural checks passed inside DetectionForge only
 */
export function finaliseResult(input: BuildResultInput): PlatformQuery {
  const descriptor = PLATFORMS[input.platform];
  const messages = [...input.syntaxMessages];
  let status: ValidationStatus;

  if (input.forcedStatus) {
    status = input.forcedStatus;
  } else if (input.query === null) {
    status = 'unsupported';
  } else if (input.ctx.gaps.length > 0) {
    status = 'mapping_required';
    messages.push(
      `${input.ctx.gaps.length} field mapping(s) are undocumented for this platform; ` +
        'placeholders are emitted instead of guessed field names.',
    );
  } else if (messages.length > 0) {
    status = 'not_validated';
  } else if (input.requiresPlatformConfiguration) {
    status = 'not_validated';
    messages.push(
      'Query-level syntax checks passed, but deployment requires proprietary rule ' +
        'configuration that cannot be represented as a standalone query.',
    );
  } else {
    status = 'validated_syntax';
  }

  const notes = [...input.ctx.notes, ...(input.extraNotes ?? []), descriptor.notes];

  return {
    platform: input.platform,
    product: descriptor.product,
    language: descriptor.language,
    query: input.query,
    status,
    validationMessages: messages,
    mappingGaps: input.ctx.gaps,
    notes,
    requiresPlatformConfiguration: input.requiresPlatformConfiguration,
    configurationGuidance: [...input.configurationGuidance],
  };
}

/** Deterministic 128-bit-ish hash used for stable Sigma rule identifiers. */
export function stableUuid(seed: string): string {
  // FNV-1a over four offset passes -> 32 hex chars, formatted as a UUID.
  const hexes: string[] = [];
  for (let pass = 0; pass < 4; pass += 1) {
    let h = 0x811c9dc5 ^ (pass * 0x9e3779b9);
    const material = `${seed}#${pass}`;
    for (let i = 0; i < material.length; i += 1) {
      h ^= material.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    hexes.push(h.toString(16).padStart(8, '0'));
  }
  const hex = hexes.join('');
  // Force RFC-4122 version 4 / variant bits so the value is a well-formed UUID.
  const v = `4${hex.slice(13, 16)}`;
  const variantNibble = ((parseInt(hex[16] as string, 16) & 0x3) | 0x8).toString(16);
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    v,
    `${variantNibble}${hex.slice(17, 20)}`,
    hex.slice(20, 32),
  ].join('-');
}

export function mitreTags(spec: DetectionSpec): string[] {
  const tags = new Set<string>();
  for (const m of spec.mitre) {
    tags.add(`attack.${m.techniqueId.toLowerCase()}`);
    const tactic = m.tacticName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '');
    if (tactic) tags.add(`attack.${tactic}`);
  }
  return [...tags].sort();
}
