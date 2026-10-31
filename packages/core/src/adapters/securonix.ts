/**
 * Securonix adapter — Spotter search syntax.
 *
 * Spotter is a search/hunting language. Threshold and multi-stage behaviour
 * detection in Securonix is implemented as policies (threshold, rare-event,
 * behaviour-analytics or violation chains) configured in the console. This
 * adapter emits valid Spotter searches per stage and describes the policy
 * configuration instead of inventing policy syntax.
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

function spotterPredicate(field: string, cond: Condition): string {
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
      return `${field} CONTAINS ${lit}`;
    case 'not_contains':
      return `NOT ${field} CONTAINS ${lit}`;
    case 'startswith':
      return `${field} STARTS WITH ${lit}`;
    case 'not_startswith':
      return `NOT ${field} STARTS WITH ${lit}`;
    case 'endswith':
      return `${field} ENDS WITH ${lit}`;
    case 'not_endswith':
      return `NOT ${field} ENDS WITH ${lit}`;
    case 'not_regex':
      return `NOT ${field} CONTAINS ${dq('<<REGEX_UNSUPPORTED>>')}`;
    case 'regex':
      // Spotter has no portable regex operator; degrade honestly to a note.
      return `${field} CONTAINS ${dq('<<REGEX_UNSUPPORTED>>')}`;
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

function stageSearch(ctx: MappingContext, stage: Stage, index: number): { text: string; regexUsed: boolean } {
  const scope = sourceScope(stage.telemetry).securonix;
  if (scope === null) {
    const logical = `securonix_resourcegroup:${stage.telemetry}`;
    if (!ctx.gaps.some((g) => g.logical === logical)) {
      ctx.gaps.push({
        logical,
        note:
          scopeNote(stage.telemetry, 'securonix') ??
          `No documented Securonix resource-group scope for ${stage.telemetry} telemetry.`,
      });
    }
  } else {
    const note = scopeNote(stage.telemetry, 'securonix');
    if (note) ctx.notes.add(`Securonix scope (${stage.telemetry}): ${note}`);
  }

  let regexUsed = false;
  const predicates = stage.conditions.map((c) => {
    if (c.operator === 'regex' || c.operator === 'not_regex') regexUsed = true;
    return spotterPredicate(mapFieldOrPlaceholder(ctx, c.field, stage.telemetry), c);
  });

  const parts = [
    'index = activity',
    scope ?? mappingPlaceholder(`securonix_resourcegroup:${stage.telemetry}`),
    joinPredicates(predicates, stage.conditionLogic),
  ].filter((p) => p.length > 0);

  return {
    text: `// Stage ${index + 1} (${stage.id}): ${scrubLiteral(stage.name)}\n${parts.join(' AND ')}`,
    regexUsed,
  };
}

function build(spec: DetectionSpec): PlatformQuery {
  const ctx = createMappingContext('securonix');
  const configurationGuidance: string[] = [];
  const syntaxMessages: string[] = [];
  const blocks: string[] = [
    [
      `// ${spec.name} — ${spec.slug}`,
      `// Objective: ${scrubLiteral(spec.objective)}`,
      '// Spotter searches below are for hunting and policy validation.',
      '// The production detection is a Securonix policy (see configuration guidance).',
    ].join('\n'),
  ];

  let anyRegex = false;
  for (const [index, stage] of spec.stages.entries()) {
    const { text, regexUsed } = stageSearch(ctx, stage, index);
    anyRegex = anyRegex || regexUsed;
    blocks.push(text);
  }

  if (anyRegex) {
    syntaxMessages.push(
      'One or more conditions use a regular expression. Spotter has no portable regex ' +
        'operator, so the predicate is emitted as a placeholder and must be reworked as ' +
        'a CONTAINS/IN list or implemented in the policy definition.',
    );
  }

  const window = humanWindow(spec.correlation.timeWindowSeconds);
  const pivot = spec.correlation.groupBy.join(', ') || 'the correlation entity';

  switch (spec.correlation.type) {
    case 'threshold':
      configurationGuidance.push(
        `Create an Activity-based Threshold policy: group by ${pivot}, evaluation window ` +
          `${window}, threshold ` +
          `${spec.correlation.eventThreshold ?? spec.correlation.distinctThreshold ?? 'N'}` +
          `${spec.correlation.distinctThreshold !== undefined ? ' distinct values' : ' events'}.`,
      );
      break;
    case 'sequence':
      configurationGuidance.push(
        `Create one policy per stage, then chain them with a Violation Chain / Threat ` +
          `Model so that stage order is enforced within ${window}, correlated on ${pivot}.`,
      );
      break;
    default:
      configurationGuidance.push(
        'Create an Activity-based policy with these conditions; set the violation ' +
          'severity and risk-scoring weight in the policy definition.',
      );
  }

  configurationGuidance.push(
    'Risk scoring, peer-group baselines, whitelists and the threat-model association are ' +
      'console-side configuration and cannot be represented in Spotter query text.',
  );
  configurationGuidance.push(
    'Confirm every attribute name against your import connector normalisation: Securonix ' +
      'field availability is deployment specific.',
  );

  const query = blocks.join('\n\n');
  if (!/index\s*=\s*\w+/.test(query)) syntaxMessages.push('No Spotter index scope was produced.');

  return finaliseResult({
    platform: 'securonix',
    query,
    ctx,
    syntaxMessages,
    requiresPlatformConfiguration: true,
    configurationGuidance,
  });
}

export const securonixAdapter: SiemAdapter = { platform: 'securonix', build };
