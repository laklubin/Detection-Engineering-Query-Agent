/**
 * Splunk Enterprise Security adapter — SPL.
 *
 * Emits a scoped base search, an eval-based predicate filter, and correlation
 * logic appropriate to the specification (single event, threshold, or multi
 * stage sequence). Enterprise Security notable-event configuration is described
 * as guidance; it is never fabricated as query syntax.
 */

import type { TelemetryFamily } from '../catalog.js';
import type { Condition, DetectionSpec, PlatformQuery, Stage } from '../schemas.js';
import { sourceScope, scopeNote } from '../mappings/sources.js';
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
  stageTelemetries,
} from './common.js';

function regexEscape(value: string): string {
  return scrubLiteral(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function alias(logical: string): string {
  return `dfai_${logical.replace(/[^a-z0-9]+/gi, '_')}`;
}

/** Render one predicate in SPL *eval* syntax (usable inside where/case). */
function evalPredicate(field: string, cond: Condition): string {
  const ci = cond.caseSensitive ? '' : '(?i)';
  switch (cond.operator) {
    case 'equals':
      return typeof cond.value === 'number' || typeof cond.value === 'boolean'
        ? `${field}==${String(cond.value)}`
        : `${field}==${dq(cond.value)}`;
    case 'not_equals':
      return typeof cond.value === 'number' || typeof cond.value === 'boolean'
        ? `${field}!=${String(cond.value)}`
        : `${field}!=${dq(cond.value)}`;
    case 'contains':
      return `match(${field}, ${dq(`${ci}${regexEscape(String(cond.value))}`)})`;
    case 'not_contains':
      return `NOT match(${field}, ${dq(`${ci}${regexEscape(String(cond.value))}`)})`;
    case 'startswith':
      return `match(${field}, ${dq(`${ci}^${regexEscape(String(cond.value))}`)})`;
    case 'not_startswith':
      return `NOT match(${field}, ${dq(`${ci}^${regexEscape(String(cond.value))}`)})`;
    case 'endswith':
      return `match(${field}, ${dq(`${ci}${regexEscape(String(cond.value))}$`)})`;
    case 'not_endswith':
      return `NOT match(${field}, ${dq(`${ci}${regexEscape(String(cond.value))}$`)})`;
    case 'regex':
      return `match(${field}, ${dq(`${ci}${String(cond.value)}`)})`;
    case 'not_regex':
      return `NOT match(${field}, ${dq(`${ci}${String(cond.value)}`)})`;
    case 'in':
      return `in(${field}, ${(Array.isArray(cond.value) ? cond.value : []).map((v) => (typeof v === 'number' ? String(v) : dq(v))).join(', ')})`;
    case 'not_in':
      return `NOT in(${field}, ${(Array.isArray(cond.value) ? cond.value : []).map((v) => (typeof v === 'number' ? String(v) : dq(v))).join(', ')})`;
    case 'gt':
      return `${field}>${String(cond.value)}`;
    case 'gte':
      return `${field}>=${String(cond.value)}`;
    case 'lt':
      return `${field}<${String(cond.value)}`;
    case 'lte':
      return `${field}<=${String(cond.value)}`;
    case 'exists':
      return `isnotnull(${field})`;
    case 'not_exists':
      return `isnull(${field})`;
    default:
      return '';
  }
}

function stageExpression(ctx: MappingContext, stage: Stage): string {
  const predicates = stage.conditions.map((cond) =>
    evalPredicate(mapFieldOrPlaceholder(ctx, cond.field, stage.telemetry), cond),
  );
  return joinPredicates(predicates, stage.conditionLogic);
}

function baseSearch(ctx: MappingContext, telemetries: readonly TelemetryFamily[]): string {
  const scopes: string[] = [];
  for (const telemetry of telemetries) {
    const scope = sourceScope(telemetry).splunk;
    if (scope === null) {
      const placeholder = mappingPlaceholder(`splunk_scope:${telemetry}`);
      if (!ctx.gaps.some((g) => g.logical === `splunk_scope:${telemetry}`)) {
        ctx.gaps.push({
          logical: `splunk_scope:${telemetry}`,
          note:
            scopeNote(telemetry, 'splunk') ??
            `No documented Splunk index/sourcetype scope for ${telemetry} telemetry.`,
        });
      }
      scopes.push(placeholder);
      continue;
    }
    const note = scopeNote(telemetry, 'splunk');
    if (note) ctx.notes.add(`Splunk scope (${telemetry}): ${note}`);
    scopes.push(scopes.length === 0 && telemetries.length === 1 ? scope : `(${scope})`);
  }
  return scopes.join(' OR ');
}

/** Normalise a pivot field that may have different names per telemetry. */
function pivotProjection(
  ctx: MappingContext,
  logical: string,
  telemetries: readonly TelemetryFamily[],
): { expr: string | null; name: string } {
  const names = [...new Set(telemetries.map((t) => mapField(ctx, logical, t)).filter((n): n is string => n !== null))];
  if (names.length === 0) {
    return { expr: null, name: mappingPlaceholder(logical) };
  }
  if (names.length === 1) return { expr: null, name: names[0] as string };
  const name = alias(logical);
  return { expr: `| eval ${name}=coalesce(${names.join(', ')})`, name };
}

function build(spec: DetectionSpec): PlatformQuery {
  const ctx = createMappingContext('splunk');
  const telemetries = stageTelemetries(spec);
  const lines: string[] = [];
  const configurationGuidance: string[] = [];

  lines.push(`\`\`\` ${spec.name} — ${spec.slug} \`\`\``);
  lines.push(`\`\`\` Objective: ${scrubLiteral(spec.objective)} \`\`\``);
  if (spec.mitre.length > 0) {
    lines.push(
      `\`\`\` MITRE ATT&CK: ${spec.mitre.map((m) => `${m.techniqueId} ${m.techniqueName}`).join('; ')} \`\`\``,
    );
  }

  const search = baseSearch(ctx, telemetries);
  const window = spec.correlation.timeWindowSeconds;

  const pivots = spec.correlation.groupBy.map((g) => pivotProjection(ctx, g, telemetries));
  const pivotExprs = pivots.map((p) => p.expr).filter((e): e is string => e !== null);
  const byClause = pivots.map((p) => p.name);

  if (spec.correlation.type === 'sequence' && spec.stages.length > 1) {
    lines.push(search);
    lines.push(...pivotExprs);
    const caseArms = spec.stages
      .map((stage) => `  ${stageExpression(ctx, stage)}, ${dq(stage.id)}`)
      .join(',\n');
    lines.push(`| eval dfai_stage=case(\n${caseArms},\n  true(), null())`);
    lines.push('| where isnotnull(dfai_stage)');

    const statsParts = [
      'count AS dfai_events',
      'dc(dfai_stage) AS dfai_stage_count',
      'values(dfai_stage) AS dfai_stages',
      'min(_time) AS dfai_first_seen',
      'max(_time) AS dfai_last_seen',
    ];
    for (const stage of spec.stages) {
      statsParts.push(`min(eval(if(dfai_stage==${dq(stage.id)}, _time, null()))) AS ${alias(stage.id)}_time`);
    }
    const by = byClause.length > 0 ? ` by ${byClause.join(', ')}` : '';
    lines.push(`| stats ${statsParts.join(', ')}${by}`);
    lines.push(`| where dfai_stage_count==${spec.stages.length}`);
    lines.push(`| eval dfai_window_seconds=dfai_last_seen-dfai_first_seen`);
    lines.push(`| where dfai_window_seconds<=${window}`);
    if (spec.correlation.ordered) {
      const ordering = spec.stages
        .slice(0, -1)
        .map((stage, i) => `${alias(stage.id)}_time<=${alias(spec.stages[i + 1]!.id)}_time`)
        .join(' AND ');
      if (ordering) lines.push(`| where ${ordering}`);
    }
    if (spec.correlation.eventThreshold !== undefined) {
      lines.push(`| where dfai_events>=${spec.correlation.eventThreshold}`);
    }
    lines.push(
      `| eval dfai_first_seen=strftime(dfai_first_seen, "%F %T"), dfai_last_seen=strftime(dfai_last_seen, "%F %T")`,
    );
    lines.push(`| eval dfai_severity=${dq(spec.severity)}, dfai_use_case=${dq(spec.slug)}`);
    configurationGuidance.push(
      'Save as an Enterprise Security correlation search with the time range set to ' +
        `at least ${humanWindow(window)} and a schedule window that overlaps the search range.`,
    );
    if (spec.correlation.ordered) {
      configurationGuidance.push(
        'Stage ordering is enforced with per-stage earliest timestamps rather than a ' +
          'native sequence operator, because SPL has no sequence primitive.',
      );
    }
  } else if (spec.correlation.type === 'threshold') {
    const stage = spec.stages[0] as Stage;
    lines.push(search);
    lines.push(...pivotExprs);
    lines.push(`| where ${stageExpression(ctx, stage)}`);
    const statsParts = ['count AS dfai_events', 'min(_time) AS dfai_first_seen', 'max(_time) AS dfai_last_seen'];
    if (spec.correlation.thresholdField) {
      const tf = mapFieldOrPlaceholder(ctx, spec.correlation.thresholdField, stage.telemetry);
      statsParts.push(`dc(${tf}) AS dfai_distinct`);
      statsParts.push(`values(${tf}) AS dfai_distinct_values`);
    }
    const by = [`bin(_time, ${window}s) AS dfai_bucket`, ...byClause];
    lines.push(`| bin _time span=${window}s`);
    lines.push(`| stats ${statsParts.join(', ')} by _time${byClause.length > 0 ? `, ${byClause.join(', ')}` : ''}`);
    void by;
    const conditions: string[] = [];
    if (spec.correlation.eventThreshold !== undefined) {
      conditions.push(`dfai_events>=${spec.correlation.eventThreshold}`);
    }
    if (spec.correlation.distinctThreshold !== undefined) {
      conditions.push(`dfai_distinct>=${spec.correlation.distinctThreshold}`);
    }
    if (conditions.length > 0) lines.push(`| where ${conditions.join(' AND ')}`);
    lines.push(`| eval dfai_severity=${dq(spec.severity)}, dfai_use_case=${dq(spec.slug)}`);
    configurationGuidance.push(
      `Threshold is evaluated per ${humanWindow(window)} bucket; align the correlation ` +
        'search schedule to the same span to avoid double counting.',
    );
  } else {
    const stage = spec.stages[0] as Stage;
    lines.push(search);
    lines.push(`| where ${stageExpression(ctx, stage)}`);
    const projected = [
      '_time',
      ...new Set(
        spec.requiredEventFields
          .map((f) => mapField(ctx, f, stage.telemetry))
          .filter((f): f is string => f !== null),
      ),
    ];
    lines.push(`| table ${projected.join(', ')}`);
    lines.push(`| eval dfai_severity=${dq(spec.severity)}, dfai_use_case=${dq(spec.slug)}`);
  }

  configurationGuidance.push(
    'Notable-event title, drill-down search, throttling (window and fields) and risk ' +
      'scoring are Enterprise Security objects configured outside the search string.',
  );

  const query = lines.filter((l) => l.length > 0).join('\n');
  const syntaxMessages: string[] = [];
  if (!/^(?:index=|\(|`|\|)/m.test(query.split('\n').find((l) => !l.startsWith('```')) ?? '')) {
    syntaxMessages.push('Base search does not start with an index or subsearch scope.');
  }

  return finaliseResult({
    platform: 'splunk',
    query,
    ctx,
    syntaxMessages,
    requiresPlatformConfiguration: false,
    configurationGuidance,
    extraNotes: [
      'Literal predicates are applied in a `where` clause for uniform semantics. For ' +
        'large volumes, push index-time-filterable terms into the base search or use a ' +
        'CIM data model (`| tstats`) for acceleration.',
    ],
  });
}

export const splunkAdapter: SiemAdapter = { platform: 'splunk', build };
