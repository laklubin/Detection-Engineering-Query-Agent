/**
 * FortiSIEM adapter — event search expressions.
 *
 * FortiSIEM rules are XML/GUI definitions built from sub-patterns with
 * group-by, aggregation and threshold clauses. Those are not expressible as a
 * standalone query string, so this adapter emits valid event-search expressions
 * per sub-pattern and describes the rule structure explicitly.
 */

import type { Condition, DetectionSpec, PlatformQuery, Stage } from '../schemas.js';
import { scopeNote, sourceScope } from '../mappings/sources.js';
import type { SiemAdapter } from './types.js';
import {
  createMappingContext,
  dq,
  finaliseResult,
  humanWindow,
  joinPredicates,
  mapFieldOrPlaceholder,
  mappingPlaceholder,
  type MappingContext,
  scrubLiteral,
} from './common.js';

function fortiPredicate(field: string, cond: Condition): string {
  const isNum = typeof cond.value === 'number';
  const isBool = typeof cond.value === 'boolean';
  const lit = isNum || isBool ? String(cond.value) : dq(cond.value);
  const list = (Array.isArray(cond.value) ? cond.value : [])
    .map((v) => (typeof v === 'number' ? String(v) : dq(v)))
    .join(', ');

  switch (cond.operator) {
    case 'equals':
      return `${field} = ${lit}`;
    case 'not_equals':
      return `${field} != ${lit}`;
    case 'contains':
      return `${field} CONTAIN ${lit}`;
    case 'not_contains':
      return `${field} NOT CONTAIN ${lit}`;
    case 'startswith':
      return `${field} REGEXP ${dq(`^${String(cond.value)}`)}`;
    case 'not_startswith':
      return `NOT ${field} REGEXP ${dq(`^${String(cond.value)}`)}`;
    case 'endswith':
      return `${field} REGEXP ${dq(`${String(cond.value)}$`)}`;
    case 'not_endswith':
      return `NOT ${field} REGEXP ${dq(`${String(cond.value)}$`)}`;
    case 'regex':
      return `${field} REGEXP ${dq(String(cond.value))}`;
    case 'not_regex':
      return `NOT ${field} REGEXP ${dq(String(cond.value))}`;
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
      return `${field} != NULL`;
    case 'not_exists':
      return `${field} = NULL`;
    default:
      return '';
  }
}

function subPattern(ctx: MappingContext, stage: Stage, index: number): string {
  const scope = sourceScope(stage.telemetry).fortisiem;
  if (scope === null) {
    const logical = `fortisiem_eventtype:${stage.telemetry}`;
    if (!ctx.gaps.some((g) => g.logical === logical)) {
      ctx.gaps.push({
        logical,
        note:
          scopeNote(stage.telemetry, 'fortisiem') ??
          `No documented FortiSIEM event-type scope for ${stage.telemetry} telemetry.`,
      });
    }
  } else {
    const note = scopeNote(stage.telemetry, 'fortisiem');
    if (note) ctx.notes.add(`FortiSIEM scope (${stage.telemetry}): ${note}`);
  }

  const predicates = stage.conditions.map((c) =>
    fortiPredicate(mapFieldOrPlaceholder(ctx, c.field, stage.telemetry), c),
  );
  const parts = [
    scope ?? mappingPlaceholder(`fortisiem_eventtype:${stage.telemetry}`),
    joinPredicates(predicates, stage.conditionLogic),
  ].filter((p) => p.length > 0);

  return `# SubPattern ${index + 1} (${stage.id}): ${scrubLiteral(stage.name)}\n${parts.join(' AND ')}`;
}

function build(spec: DetectionSpec): PlatformQuery {
  const ctx = createMappingContext('fortisiem');
  const configurationGuidance: string[] = [];
  const syntaxMessages: string[] = [];

  const blocks: string[] = [
    [
      `# ${spec.name} — ${spec.slug}`,
      `# Objective: ${scrubLiteral(spec.objective)}`,
      '# Expressions below are FortiSIEM Analytics event-search filters, one per',
      '# rule sub-pattern. The rule itself is defined in Resources > Rules.',
    ].join('\n'),
  ];

  for (const [index, stage] of spec.stages.entries()) {
    blocks.push(subPattern(ctx, stage, index));
  }

  const window = humanWindow(spec.correlation.timeWindowSeconds);
  const pivot = spec.correlation.groupBy.join(', ') || 'the correlation entity';

  const ruleOutline: string[] = ['# Rule outline (configure in Resources > Rules):'];
  ruleOutline.push(`#   Severity: ${spec.severity}`);
  ruleOutline.push(`#   Evaluation window: ${window}`);
  spec.stages.forEach((stage, i) => {
    ruleOutline.push(
      `#   SubPattern ${i + 1} "${stage.id}": filter above, GROUP BY ${pivot}` +
        (spec.correlation.type === 'threshold' && spec.correlation.eventThreshold !== undefined
          ? `, HAVING COUNT(*) >= ${spec.correlation.eventThreshold}`
          : ', HAVING COUNT(*) >= 1'),
    );
  });
  if (spec.correlation.type === 'sequence') {
    ruleOutline.push(
      `#   Pattern relationship: ${spec.correlation.ordered ? 'FOLLOWED_BY (ordered)' : 'AND (unordered)'}` +
        ` across sub-patterns, within ${window}`,
    );
  }
  if (spec.correlation.distinctThreshold !== undefined && spec.correlation.thresholdField) {
    ruleOutline.push(
      `#   Additional HAVING: COUNT(DISTINCT ${spec.correlation.thresholdField}) >= ${spec.correlation.distinctThreshold}`,
    );
  }
  blocks.push(ruleOutline.join('\n'));

  configurationGuidance.push(
    'Build the rule with one sub-pattern per stage. Set the group-by attributes to ' +
      `${pivot} and the pattern time window to ${window}.`,
  );
  configurationGuidance.push(
    'Incident title, category, notification policy and remediation action are rule ' +
      'properties configured in the GUI, not part of the search expression.',
  );
  configurationGuidance.push(
    'Verify every attribute exists for the device type in Analytics > Event Attributes; ' +
      'FortiSIEM attribute coverage is parser dependent.',
  );

  const query = blocks.join('\n\n');
  if (!/[=!<>]|CONTAIN|REGEXP|IN \(/.test(query)) {
    syntaxMessages.push('No FortiSIEM filter expression was produced.');
  }

  return finaliseResult({
    platform: 'fortisiem',
    query,
    ctx,
    syntaxMessages,
    requiresPlatformConfiguration: true,
    configurationGuidance,
  });
}

export const fortisiemAdapter: SiemAdapter = { platform: 'fortisiem', build };
