/**
 * IBM QRadar adapter — AQL.
 *
 * AQL is a *search* language. It cannot express QRadar rule tests, building
 * blocks, or multi-stage offense logic. This adapter therefore emits AQL
 * hunting queries and returns explicit Rule Wizard guidance for anything that
 * AQL cannot represent, instead of fabricating rule syntax.
 */

import type { TelemetryFamily } from '../catalog.js';
import type { Condition, DetectionSpec, PlatformQuery, Stage } from '../schemas.js';
import { scopeNote, sourceScope } from '../mappings/sources.js';
import type { SiemAdapter } from './types.js';
import {
  createMappingContext,
  finaliseResult,
  joinPredicates,
  mapField,
  mapFieldOrPlaceholder,
  mappingPlaceholder,
  type MappingContext,
  scrubLiteral,
  sq,
} from './common.js';

function aqlPredicate(field: string, cond: Condition): string {
  const isNum = typeof cond.value === 'number';
  const isBool = typeof cond.value === 'boolean';
  const lit = isNum || isBool ? String(cond.value) : sq(cond.value);
  const list = (Array.isArray(cond.value) ? cond.value : [])
    .map((v) => (typeof v === 'number' ? String(v) : sq(v)))
    .join(', ');
  const ci = cond.caseSensitive === true;

  switch (cond.operator) {
    case 'equals':
      return `${field} = ${lit}`;
    case 'not_equals':
      return `${field} <> ${lit}`;
    case 'contains':
      return `${field} ${ci ? 'LIKE' : 'ILIKE'} ${sq(`%${String(cond.value)}%`)}`;
    case 'not_contains':
      return `${field} NOT ${ci ? 'LIKE' : 'ILIKE'} ${sq(`%${String(cond.value)}%`)}`;
    case 'startswith':
      return `${field} ${ci ? 'LIKE' : 'ILIKE'} ${sq(`${String(cond.value)}%`)}`;
    case 'not_startswith':
      return `${field} NOT ${ci ? 'LIKE' : 'ILIKE'} ${sq(`${String(cond.value)}%`)}`;
    case 'endswith':
      return `${field} ${ci ? 'LIKE' : 'ILIKE'} ${sq(`%${String(cond.value)}`)}`;
    case 'not_endswith':
      return `${field} NOT ${ci ? 'LIKE' : 'ILIKE'} ${sq(`%${String(cond.value)}`)}`;
    case 'regex':
      return `${field} ${ci ? 'MATCHES' : 'IMATCHES'} ${sq(String(cond.value))}`;
    case 'not_regex':
      return `${field} NOT ${ci ? 'MATCHES' : 'IMATCHES'} ${sq(String(cond.value))}`;
    case 'in':
      return `${field} IN (${list})`;
    case 'not_in':
      return `${field} NOT IN (${list})`;
    case 'gt':
      return `${field} > ${lit}`;
    case 'gte':
      return `${field} >= ${lit}`;
    case 'lt':
      return `${field} < ${lit}`;
    case 'lte':
      return `${field} <= ${lit}`;
    case 'exists':
      return `${field} IS NOT NULL`;
    case 'not_exists':
      return `${field} IS NULL`;
    default:
      return '';
  }
}

function scopeFor(ctx: MappingContext, telemetry: TelemetryFamily): string | null {
  const scope = sourceScope(telemetry).qradar;
  if (scope === null) {
    const logical = `qradar_logsource:${telemetry}`;
    if (!ctx.gaps.some((g) => g.logical === logical)) {
      ctx.gaps.push({
        logical,
        note: scopeNote(telemetry, 'qradar') ?? `No documented QRadar log source scope for ${telemetry} telemetry.`,
      });
    }
    return null;
  }
  const note = scopeNote(telemetry, 'qradar');
  if (note) ctx.notes.add(`QRadar scope (${telemetry}): ${note}`);
  return scope;
}

function stageSelect(ctx: MappingContext, spec: DetectionSpec, stage: Stage, index: number): string {
  const lines: string[] = [];
  const minutes = Math.max(1, Math.ceil(spec.correlation.timeWindowSeconds / 60));
  const scope = scopeFor(ctx, stage.telemetry);
  const predicates = joinPredicates(
    stage.conditions.map((c) => aqlPredicate(mapFieldOrPlaceholder(ctx, c.field, stage.telemetry), c)),
    stage.conditionLogic,
  );

  const projected = [
    'QIDNAME(qid) AS event_name',
    'DATEFORMAT(starttime, \'YYYY-MM-dd HH:mm:ss\') AS event_time',
    ...new Set(
      spec.requiredEventFields
        .map((f) => mapField(ctx, f, stage.telemetry))
        .filter((f): f is string => f !== null),
    ),
  ];

  lines.push(`-- Stage ${index + 1} (${stage.id}): ${scrubLiteral(stage.name)}`);
  lines.push(`SELECT ${projected.join(', ')}`);
  lines.push('FROM events');
  const whereParts = [scope ?? mappingPlaceholder(`qradar_logsource:${stage.telemetry}`), predicates].filter(
    (p) => p.length > 0,
  );
  lines.push(`WHERE ${whereParts.join(' AND ')}`);
  lines.push(`LAST ${minutes} MINUTES`);
  return lines.join('\n');
}

function build(spec: DetectionSpec): PlatformQuery {
  const ctx = createMappingContext('qradar');
  const minutes = Math.max(1, Math.ceil(spec.correlation.timeWindowSeconds / 60));
  const blocks: string[] = [];
  const configurationGuidance: string[] = [];

  blocks.push(
    [
      `-- ${spec.name} — ${spec.slug}`,
      `-- Objective: ${scrubLiteral(spec.objective)}`,
      spec.mitre.length > 0
        ? `-- MITRE ATT&CK: ${spec.mitre.map((m) => `${m.techniqueId} ${m.techniqueName}`).join('; ')}`
        : '',
      '-- AQL below is a HUNTING/VERIFICATION search. QRadar offense logic must be',
      '-- implemented in the Rule Wizard (see configuration guidance).',
    ]
      .filter((l) => l.length > 0)
      .join('\n'),
  );

  if (spec.correlation.type === 'threshold') {
    const stage = spec.stages[0] as Stage;
    const scope = scopeFor(ctx, stage.telemetry);
    const predicates = joinPredicates(
      stage.conditions.map((c) => aqlPredicate(mapFieldOrPlaceholder(ctx, c.field, stage.telemetry), c)),
      stage.conditionLogic,
    );
    const groupFields = spec.correlation.groupBy
      .map((g) => mapFieldOrPlaceholder(ctx, g, stage.telemetry))
      .filter((f) => f.length > 0);
    const selected = [...groupFields, 'COUNT(*) AS event_count'];
    if (spec.correlation.thresholdField) {
      selected.push(
        `COUNT(DISTINCT ${mapFieldOrPlaceholder(ctx, spec.correlation.thresholdField, stage.telemetry)}) AS distinct_count`,
      );
    }
    const having: string[] = [];
    if (spec.correlation.eventThreshold !== undefined) having.push(`COUNT(*) >= ${spec.correlation.eventThreshold}`);
    if (spec.correlation.distinctThreshold !== undefined && spec.correlation.thresholdField) {
      having.push(
        `COUNT(DISTINCT ${mapFieldOrPlaceholder(ctx, spec.correlation.thresholdField, stage.telemetry)}) >= ${spec.correlation.distinctThreshold}`,
      );
    }
    const lines = [
      `SELECT ${selected.join(', ')}`,
      'FROM events',
      `WHERE ${[scope ?? mappingPlaceholder(`qradar_logsource:${stage.telemetry}`), predicates]
        .filter((p) => p.length > 0)
        .join(' AND ')}`,
      groupFields.length > 0 ? `GROUP BY ${groupFields.join(', ')}` : '',
      having.length > 0 ? `HAVING ${having.join(' AND ')}` : '',
      `ORDER BY event_count DESC`,
      `LAST ${minutes} MINUTES`,
    ].filter((l) => l.length > 0);
    blocks.push(lines.join('\n'));
    configurationGuidance.push(
      `Implement as a QRadar event rule with the test "when at least ${spec.correlation.eventThreshold ?? spec.correlation.distinctThreshold ?? 'N'} ` +
        `events are seen with the same ${spec.correlation.groupBy.join(' and ') || 'property'} in ${minutes} minutes".`,
    );
  } else {
    spec.stages.forEach((stage, index) => {
      blocks.push(stageSelect(ctx, spec, stage, index));
    });
    if (spec.correlation.type === 'sequence') {
      configurationGuidance.push(
        'AQL has no sequence operator. Build one building block per stage, then a ' +
          `rule with "when these building blocks occur in sequence within ${minutes} minutes" ` +
          `and the counting property set to ${spec.correlation.groupBy.join(', ') || 'the correlation entity'}.`,
      );
      configurationGuidance.push(
        'Use Rule Response > Dispatch New Event with an appropriate severity/credibility/' +
          'relevance so the offense is raised with the intended magnitude.',
      );
    }
  }

  configurationGuidance.push(
    'Any referenced property that is not a standard normalised column requires a ' +
      'Custom Event Property (regex or JSON) created on the relevant log source, ' +
      'optimised for search, before the query will return data.',
  );
  configurationGuidance.push(
    'Confirm exact log source type strings in Admin > Log Sources; DSM naming differs ' +
      'between QRadar versions.',
  );

  const query = blocks.join('\n\n');
  const syntaxMessages: string[] = [];
  if (!/\bSELECT\b/.test(query)) syntaxMessages.push('No SELECT statement was produced.');
  if (!/\bFROM\s+(?:events|flows)\b/.test(query)) syntaxMessages.push('No FROM events/flows clause was produced.');
  if (!/\bLAST\s+\d+\s+(?:MINUTES|HOURS|DAYS)\b/.test(query)) {
    syntaxMessages.push('No time-range (LAST ...) clause was produced.');
  }

  return finaliseResult({
    platform: 'qradar',
    query,
    ctx,
    syntaxMessages,
    requiresPlatformConfiguration: true,
    configurationGuidance,
    extraNotes: [
      'Multi-stage correlation is intentionally not expressed in AQL; the emitted ' +
        'statements are per-stage hunting searches used to validate data availability.',
    ],
  });
}

export const qradarAdapter: SiemAdapter = { platform: 'qradar', build };
