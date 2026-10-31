/**
 * Elastic Security adapter — EQL and ES|QL.
 *
 * Sequence logic maps cleanly onto EQL's native `sequence ... with maxspan`
 * operator. Threshold/aggregation logic has no EQL equivalent, so it is emitted
 * as ES|QL. Both assume ECS-normalised source data.
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

/** EQL event categories per telemetry family. `any` is always valid. */
const EQL_CATEGORY: Readonly<Record<TelemetryFamily, string>> = {
  windows_security: 'any',
  windows_sysmon: 'any',
  windows_powershell: 'any',
  edr_process: 'process',
  linux_auditd: 'any',
  identity_signin: 'authentication',
  cloud_audit: 'any',
  network_flow: 'network',
  dns: 'dns',
  web_proxy: 'network',
  firewall: 'network',
  email_security: 'any',
  generic: 'any',
};

function eqlPredicate(field: string, cond: Condition): string {
  const ci = cond.caseSensitive !== true;
  const isNum = typeof cond.value === 'number';
  const isBool = typeof cond.value === 'boolean';
  const lit = isNum || isBool ? String(cond.value) : dq(cond.value);
  const values = Array.isArray(cond.value) ? cond.value : [];
  const numericList = values.length > 0 && values.every((v) => typeof v === 'number');
  const list = values.map((v) => (typeof v === 'number' ? String(v) : dq(v))).join(', ');

  switch (cond.operator) {
    case 'equals':
      return isNum || isBool ? `${field} == ${lit}` : ci ? `${field} : ${lit}` : `${field} == ${lit}`;
    case 'not_equals':
      return `not (${isNum || isBool ? `${field} == ${lit}` : ci ? `${field} : ${lit}` : `${field} == ${lit}`})`;
    case 'contains':
      return `${field} ${ci ? 'like~' : 'like'} ${dq(`*${String(cond.value)}*`)}`;
    case 'not_contains':
      return `not ${field} ${ci ? 'like~' : 'like'} ${dq(`*${String(cond.value)}*`)}`;
    case 'startswith':
      return `${field} ${ci ? 'like~' : 'like'} ${dq(`${String(cond.value)}*`)}`;
    case 'not_startswith':
      return `not ${field} ${ci ? 'like~' : 'like'} ${dq(`${String(cond.value)}*`)}`;
    case 'endswith':
      return `${field} ${ci ? 'like~' : 'like'} ${dq(`*${String(cond.value)}`)}`;
    case 'not_endswith':
      return `not ${field} ${ci ? 'like~' : 'like'} ${dq(`*${String(cond.value)}`)}`;
    case 'regex':
      return `${field} ${ci ? 'regex~' : 'regex'} ${dq(String(cond.value))}`;
    case 'not_regex':
      return `not ${field} ${ci ? 'regex~' : 'regex'} ${dq(String(cond.value))}`;
    case 'in':
      return `${field} ${ci && !numericList ? 'in~' : 'in'} (${list})`;
    case 'not_in':
      return `not ${field} ${ci && !numericList ? 'in~' : 'in'} (${list})`;
    case 'gt':
      return `${field} > ${lit}`;
    case 'gte':
      return `${field} >= ${lit}`;
    case 'lt':
      return `${field} < ${lit}`;
    case 'lte':
      return `${field} <= ${lit}`;
    case 'exists':
      return `${field} != null`;
    case 'not_exists':
      return `${field} == null`;
    default:
      return '';
  }
}

function esqlPredicate(field: string, cond: Condition): string {
  const isNum = typeof cond.value === 'number';
  const isBool = typeof cond.value === 'boolean';
  const lit = isNum || isBool ? String(cond.value) : dq(cond.value);
  const list = (Array.isArray(cond.value) ? cond.value : [])
    .map((v) => (typeof v === 'number' ? String(v) : dq(v)))
    .join(', ');
  switch (cond.operator) {
    case 'equals':
      return `${field} == ${lit}`;
    case 'not_equals':
      return `${field} != ${lit}`;
    case 'contains':
      return `${field} LIKE ${dq(`*${String(cond.value)}*`)}`;
    case 'not_contains':
      return `NOT ${field} LIKE ${dq(`*${String(cond.value)}*`)}`;
    case 'startswith':
      return `${field} LIKE ${dq(`${String(cond.value)}*`)}`;
    case 'not_startswith':
      return `NOT ${field} LIKE ${dq(`${String(cond.value)}*`)}`;
    case 'endswith':
      return `${field} LIKE ${dq(`*${String(cond.value)}`)}`;
    case 'not_endswith':
      return `NOT ${field} LIKE ${dq(`*${String(cond.value)}`)}`;
    case 'regex':
      return `${field} RLIKE ${dq(String(cond.value))}`;
    case 'not_regex':
      return `NOT ${field} RLIKE ${dq(String(cond.value))}`;
    case 'in':
      return `${field} IN (${list})`;
    case 'not_in':
      return `NOT ${field} IN (${list})`;
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

function indexFor(ctx: MappingContext, telemetry: TelemetryFamily): string {
  const pattern = sourceScope(telemetry).elastic;
  if (pattern === null) {
    const logical = `elastic_index:${telemetry}`;
    if (!ctx.gaps.some((g) => g.logical === logical)) {
      ctx.gaps.push({
        logical,
        note: scopeNote(telemetry, 'elastic') ?? `No documented Elastic index pattern for ${telemetry} telemetry.`,
      });
    }
    return mappingPlaceholder(logical);
  }
  const note = scopeNote(telemetry, 'elastic');
  if (note) ctx.notes.add(`Elastic index (${telemetry}): ${note}`);
  return pattern;
}

function eqlStage(ctx: MappingContext, stage: Stage): string {
  const category = EQL_CATEGORY[stage.telemetry];
  const predicates = joinPredicates(
    stage.conditions.map((c) => eqlPredicate(mapFieldOrPlaceholder(ctx, c.field, stage.telemetry), c)),
    stage.conditionLogic,
    { and: 'and', or: 'or' },
  );
  return `  [ ${category} where ${predicates} ]`;
}

function build(spec: DetectionSpec): PlatformQuery {
  const ctx = createMappingContext('elastic');
  const window = spec.correlation.timeWindowSeconds;
  const sections: string[] = [];
  const configurationGuidance: string[] = [];
  const syntaxMessages: string[] = [];

  const header = [
    `// ${spec.name} — ${spec.slug}`,
    `// Objective: ${scrubLiteral(spec.objective)}`,
    spec.mitre.length > 0
      ? `// MITRE ATT&CK: ${spec.mitre.map((m) => `${m.techniqueId} ${m.techniqueName}`).join('; ')}`
      : '',
    `// Index pattern(s): ${[...new Set(spec.stages.map((s) => indexFor(ctx, s.telemetry)))].join(', ')}`,
  ].filter((l) => l.length > 0);

  // ---- EQL -----------------------------------------------------------------
  const eqlLines: string[] = ['// ===== EQL (Elastic Query Language) ====='];
  if (spec.correlation.type === 'sequence' && spec.stages.length > 1) {
    const pivots = spec.correlation.groupBy
      .map((g) => {
        const names = [...new Set(spec.stages.map((s) => mapField(ctx, g, s.telemetry)))];
        if (names.length === 1 && names[0] !== null) return names[0];
        if (names.includes(null)) return mappingPlaceholder(g);
        ctx.notes.add(
          `EQL sequence pivot "${g}" resolves to different ECS fields per stage ` +
            `(${names.join(', ')}); EQL requires one shared field name. Normalise at ingest.`,
        );
        return names[0] as string;
      })
      .filter((n): n is string => n !== null);
    const by = pivots.length > 0 ? ` by ${pivots.join(', ')}` : '';
    if (pivots.length === 0) {
      ctx.notes.add('No correlation pivot supplied; the EQL sequence is time-bounded only.');
    }
    eqlLines.push(`sequence${by} with maxspan=${humanWindow(window)}`);
    eqlLines.push(...spec.stages.map((s) => eqlStage(ctx, s)));
    if (!spec.correlation.ordered) {
      ctx.notes.add(
        'EQL sequences are inherently ordered. An unordered correlation was requested, ' +
          'so the ES|QL variant below (or two separate rules) is the faithful expression.',
      );
    }
  } else {
    const stage = spec.stages[0] as Stage;
    const category = EQL_CATEGORY[stage.telemetry];
    const predicates = joinPredicates(
      stage.conditions.map((c) => eqlPredicate(mapFieldOrPlaceholder(ctx, c.field, stage.telemetry), c)),
      stage.conditionLogic,
      { and: 'and', or: 'or' },
    );
    eqlLines.push(`${category} where ${predicates}`);
    if (spec.correlation.type === 'threshold') {
      eqlLines.push(
        '// Threshold counting is not expressible in EQL. Use the ES|QL variant below, ' +
          'or an Elastic "Threshold" rule type with the same filter.',
      );
    }
  }
  sections.push(eqlLines.join('\n'));

  // ---- ES|QL ---------------------------------------------------------------
  const esqlLines: string[] = ['// ===== ES|QL ====='];
  const primary = spec.stages[0] as Stage;
  esqlLines.push(`FROM ${indexFor(ctx, primary.telemetry)}`);
  const stageFilters = spec.stages.map((stage) =>
    joinPredicates(
      stage.conditions.map((c) => esqlPredicate(mapFieldOrPlaceholder(ctx, c.field, stage.telemetry), c)),
      stage.conditionLogic,
      { and: 'AND', or: 'OR' },
    ),
  );
  if (spec.stages.length > 1) {
    esqlLines.push(`| WHERE ${stageFilters.map((f) => `(${f})`).join(' OR ')}`);
    const caseArms = spec.stages
      .map((stage, i) => `${stageFilters[i]}, ${dq(stage.id)}`)
      .join(', ');
    esqlLines.push(`| EVAL dfai_stage = CASE(${caseArms}, NULL)`);
    esqlLines.push('| WHERE dfai_stage IS NOT NULL');
  } else {
    esqlLines.push(`| WHERE ${stageFilters[0]}`);
  }

  const statsBy = spec.correlation.groupBy
    .map((g) => mapFieldOrPlaceholder(ctx, g, primary.telemetry))
    .filter((f) => f.length > 0);
  const statsParts = ['dfai_events = COUNT(*)', 'dfai_first_seen = MIN(@timestamp)', 'dfai_last_seen = MAX(@timestamp)'];
  if (spec.stages.length > 1) statsParts.push('dfai_stage_count = COUNT_DISTINCT(dfai_stage)');
  if (spec.correlation.thresholdField) {
    statsParts.push(
      `dfai_distinct = COUNT_DISTINCT(${mapFieldOrPlaceholder(ctx, spec.correlation.thresholdField, primary.telemetry)})`,
    );
  }
  esqlLines.push(`| STATS ${statsParts.join(', ')}${statsBy.length > 0 ? ` BY ${statsBy.join(', ')}` : ''}`);
  const having: string[] = [];
  if (spec.stages.length > 1) having.push(`dfai_stage_count == ${spec.stages.length}`);
  if (spec.correlation.eventThreshold !== undefined) having.push(`dfai_events >= ${spec.correlation.eventThreshold}`);
  if (spec.correlation.distinctThreshold !== undefined) having.push(`dfai_distinct >= ${spec.correlation.distinctThreshold}`);
  if (having.length > 0) esqlLines.push(`| WHERE ${having.join(' AND ')}`);
  esqlLines.push('| SORT dfai_events DESC');
  esqlLines.push('| LIMIT 100');
  sections.push(esqlLines.join('\n'));

  configurationGuidance.push(
    'Create as a detection rule in Elastic Security: rule type "EQL" for the sequence ' +
      'variant or "ES|QL" for the aggregation variant. Risk score, severity, ' +
      'investigation guide and the MITRE mapping are rule metadata, not query text.',
  );
  configurationGuidance.push(
    `Set the rule interval and additional look-back so the execution window covers at ` +
      `least ${humanWindow(window)}.`,
  );

  const query = [...header, '', ...sections].join('\n');
  if (!/\bsequence\b|\bwhere\b/.test(query)) syntaxMessages.push('No EQL query body was produced.');
  if (!/^\s*FROM\s+\S+/m.test(query)) syntaxMessages.push('No ES|QL source command was produced.');

  return finaliseResult({
    platform: 'elastic',
    query,
    ctx,
    syntaxMessages,
    requiresPlatformConfiguration: false,
    configurationGuidance,
    extraNotes: [
      'ES|QL LIKE/== comparisons are case sensitive. Where a case-insensitive match is ' +
        'required, switch the predicate to RLIKE with an inline (?i) flag.',
      'Field names follow ECS. If the data is ingested without an ECS-compatible ' +
        'integration, re-map the fields before use.',
    ],
  });
}

export const elasticAdapter: SiemAdapter = { platform: 'elastic', build };
