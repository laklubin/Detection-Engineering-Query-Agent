/**
 * Microsoft Sentinel adapter — KQL.
 *
 * Emits an analytics-rule style query. Entity mapping, incident grouping and
 * scheduling live in the Analytics Rule resource (ARM/Bicep/API) and are
 * returned as configuration guidance rather than invented as KQL.
 */

import type { TelemetryFamily } from '../catalog.js';
import type { Condition, DetectionSpec, PlatformQuery, Stage } from '../schemas.js';
import { scopeNote, sourceScope } from '../mappings/sources.js';
import type { SiemAdapter } from './types.js';
import {
  createMappingContext,
  dq,
  finaliseResult,
  humanWindow,
  joinPredicates,
  mapField,
  mapFieldOrPlaceholder,
  mappingPlaceholder,
  type MappingContext,
  scrubLiteral,
} from './common.js';

function alias(logical: string): string {
  return `dfai_${logical.replace(/[^a-z0-9]+/gi, '_')}`;
}

function kqlPredicate(field: string, cond: Condition): string {
  const cs = cond.caseSensitive === true;
  const isNum = typeof cond.value === 'number';
  const isBool = typeof cond.value === 'boolean';
  const lit = isNum || isBool ? String(cond.value) : dq(cond.value);
  const values = Array.isArray(cond.value) ? cond.value : [];
  const numericList = values.length > 0 && values.every((v) => typeof v === 'number');
  const list = values.map((v) => (typeof v === 'number' ? String(v) : dq(v))).join(', ');

  switch (cond.operator) {
    case 'equals':
      return isNum || isBool || cs ? `${field} == ${lit}` : `${field} =~ ${lit}`;
    case 'not_equals':
      return isNum || isBool || cs ? `${field} != ${lit}` : `${field} !~ ${lit}`;
    case 'contains':
      return `${field} ${cs ? 'contains_cs' : 'contains'} ${lit}`;
    case 'not_contains':
      return `${field} ${cs ? '!contains_cs' : '!contains'} ${lit}`;
    case 'startswith':
      return `${field} ${cs ? 'startswith_cs' : 'startswith'} ${lit}`;
    case 'not_startswith':
      return `${field} ${cs ? '!startswith_cs' : '!startswith'} ${lit}`;
    case 'endswith':
      return `${field} ${cs ? 'endswith_cs' : 'endswith'} ${lit}`;
    case 'not_endswith':
      return `${field} ${cs ? '!endswith_cs' : '!endswith'} ${lit}`;
    case 'regex':
      return `${field} matches regex ${dq(String(cond.value))}`;
    case 'not_regex':
      return `not (${field} matches regex ${dq(String(cond.value))})`;
    case 'in':
      return `${field} ${cs || numericList ? 'in' : 'in~'} (${list})`;
    case 'not_in':
      return `${field} ${cs || numericList ? '!in' : '!in~'} (${list})`;
    case 'gt':
      return `${field} > ${lit}`;
    case 'gte':
      return `${field} >= ${lit}`;
    case 'lt':
      return `${field} < ${lit}`;
    case 'lte':
      return `${field} <= ${lit}`;
    case 'exists':
      return `isnotempty(${field})`;
    case 'not_exists':
      return `isempty(${field})`;
    default:
      return '';
  }
}

function tableFor(ctx: MappingContext, telemetry: TelemetryFamily): string {
  const table = sourceScope(telemetry).sentinel;
  if (table === null) {
    const logical = `sentinel_table:${telemetry}`;
    if (!ctx.gaps.some((g) => g.logical === logical)) {
      ctx.gaps.push({
        logical,
        note: scopeNote(telemetry, 'sentinel') ?? `No documented Sentinel table for ${telemetry} telemetry.`,
      });
    }
    return mappingPlaceholder(logical);
  }
  const note = scopeNote(telemetry, 'sentinel');
  if (note) ctx.notes.add(`Sentinel table (${telemetry}): ${note}`);
  return table;
}

function stagePredicates(ctx: MappingContext, stage: Stage): string {
  return joinPredicates(
    stage.conditions.map((c) => kqlPredicate(mapFieldOrPlaceholder(ctx, c.field, stage.telemetry), c)),
    stage.conditionLogic,
    { and: 'and', or: 'or' },
  );
}

function build(spec: DetectionSpec): PlatformQuery {
  const ctx = createMappingContext('sentinel');
  const window = spec.correlation.timeWindowSeconds;
  const windowLiteral = `${window}s`;
  const lookback = Math.max(window * 4, 86_400);
  const lines: string[] = [];
  const configurationGuidance: string[] = [];

  lines.push(`// ${spec.name} — ${spec.slug}`);
  lines.push(`// Objective: ${scrubLiteral(spec.objective)}`);
  if (spec.mitre.length > 0) {
    lines.push(`// MITRE ATT&CK: ${spec.mitre.map((m) => `${m.techniqueId} ${m.techniqueName}`).join('; ')}`);
  }
  lines.push(`let lookback = ${lookback}s;`);
  lines.push(`let correlationWindow = ${windowLiteral};`);

  const pivotNames = spec.correlation.groupBy.map((g) => ({ logical: g, name: alias(g) }));

  if (spec.correlation.type === 'sequence' && spec.stages.length > 1 && pivotNames.length > 0) {
    spec.stages.forEach((stage, index) => {
      const table = tableFor(ctx, stage.telemetry);
      const projections = pivotNames.map(
        (p) => `${p.name} = ${mapFieldOrPlaceholder(ctx, p.logical, stage.telemetry)}`,
      );
      lines.push(`// Stage ${index + 1} (${stage.id}): ${scrubLiteral(stage.name)}`);
      lines.push(`let ${alias(stage.id)} = ${table}`);
      lines.push(`    | where TimeGenerated >= ago(lookback)`);
      lines.push(`    | where ${stagePredicates(ctx, stage)}`);
      lines.push(
        `    | project ${alias(stage.id)}_time = TimeGenerated, ${projections.join(', ')}, ${alias(stage.id)}_count = 1;`,
      );
    });

    const first = spec.stages[0] as Stage;
    lines.push(alias(first.id));
    for (let i = 1; i < spec.stages.length; i += 1) {
      const stage = spec.stages[i] as Stage;
      lines.push(`| join kind=inner (${alias(stage.id)}) on ${pivotNames.map((p) => p.name).join(', ')}`);
    }
    for (let i = 1; i < spec.stages.length; i += 1) {
      const prev = spec.stages[i - 1] as Stage;
      const stage = spec.stages[i] as Stage;
      if (spec.correlation.ordered) {
        lines.push(
          `| where ${alias(stage.id)}_time between (${alias(prev.id)}_time .. ${alias(prev.id)}_time + correlationWindow)`,
        );
      } else {
        lines.push(
          `| where abs(datetime_diff('second', ${alias(stage.id)}_time, ${alias(prev.id)}_time)) <= ${window}`,
        );
      }
    }
    const last = spec.stages[spec.stages.length - 1] as Stage;
    lines.push(
      `| extend DetectionTime = ${alias(last.id)}_time, UseCaseId = ${dq(spec.slug)}, Severity = ${dq(spec.severity)}`,
    );
    lines.push(
      `| project DetectionTime, ${pivotNames.map((p) => p.name).join(', ')}, ${spec.stages
        .map((s) => `${alias(s.id)}_time`)
        .join(', ')}, UseCaseId, Severity`,
    );
    configurationGuidance.push(
      'A `join` is used because KQL has no sequence operator. For high-volume tables ' +
        'consider `partition` or a materialised view to keep the rule within the ' +
        'analytics-rule execution budget.',
    );
  } else if (spec.correlation.type === 'threshold') {
    const stage = spec.stages[0] as Stage;
    const table = tableFor(ctx, stage.telemetry);
    lines.push(table);
    lines.push(`| where TimeGenerated >= ago(lookback)`);
    lines.push(`| where ${stagePredicates(ctx, stage)}`);
    const summarise = ['EventCount = count()', 'FirstSeen = min(TimeGenerated)', 'LastSeen = max(TimeGenerated)'];
    if (spec.correlation.thresholdField) {
      const tf = mapFieldOrPlaceholder(ctx, spec.correlation.thresholdField, stage.telemetry);
      summarise.push(`DistinctCount = dcount(${tf})`);
      summarise.push(`DistinctValues = make_set(${tf}, 64)`);
    }
    const by = [
      `TimeBucket = bin(TimeGenerated, correlationWindow)`,
      ...pivotNames.map((p) => `${p.name} = ${mapFieldOrPlaceholder(ctx, p.logical, stage.telemetry)}`),
    ];
    lines.push(`| summarize ${summarise.join(', ')} by ${by.join(', ')}`);
    const having: string[] = [];
    if (spec.correlation.eventThreshold !== undefined) having.push(`EventCount >= ${spec.correlation.eventThreshold}`);
    if (spec.correlation.distinctThreshold !== undefined)
      having.push(`DistinctCount >= ${spec.correlation.distinctThreshold}`);
    if (having.length > 0) lines.push(`| where ${having.join(' and ')}`);
    lines.push(`| extend UseCaseId = ${dq(spec.slug)}, Severity = ${dq(spec.severity)}`);
    configurationGuidance.push(
      `Set the analytics rule query period to at least ${humanWindow(lookback)} and the ` +
        `frequency to ${humanWindow(window)} so buckets are evaluated exactly once.`,
    );
  } else {
    const stage = spec.stages[0] as Stage;
    const table = tableFor(ctx, stage.telemetry);
    lines.push(table);
    lines.push(`| where TimeGenerated >= ago(lookback)`);
    lines.push(`| where ${stagePredicates(ctx, stage)}`);
    const projected = [
      'TimeGenerated',
      ...new Set(
        spec.requiredEventFields
          .map((f) => mapField(ctx, f, stage.telemetry))
          .filter((f): f is string => f !== null),
      ),
    ];
    lines.push(`| project ${projected.join(', ')}`);
    lines.push(`| extend UseCaseId = ${dq(spec.slug)}, Severity = ${dq(spec.severity)}`);
  }

  if (spec.correlation.type === 'sequence' && pivotNames.length === 0) {
    ctx.notes.add(
      'No correlation pivot field was supplied, so the sequence could not be expressed ' +
        'as a join. Add a group-by entity (user, host or IP) for a deployable rule.',
    );
  }

  configurationGuidance.push(
    'Entity mapping (Account/Host/IP), custom details, incident grouping, suppression ' +
      'and the MITRE tactic/technique assignment are properties of the Analytics Rule, ' +
      'not of the KQL query.',
  );

  const query = lines.join('\n');
  const syntaxMessages: string[] = [];
  const pipeLines = query.split('\n').filter((l) => l.trim().startsWith('|'));
  if (pipeLines.length === 0) syntaxMessages.push('Query contains no tabular operators.');

  return finaliseResult({
    platform: 'sentinel',
    query,
    ctx,
    syntaxMessages,
    requiresPlatformConfiguration: false,
    configurationGuidance,
  });
}

export const sentinelAdapter: SiemAdapter = { platform: 'sentinel', build };
