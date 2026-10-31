/**
 * Sigma adapter — Sigma YAML, including the v2 correlation specification.
 *
 * Output is a YAML document stream: one rule per detection stage, plus a
 * correlation rule when the specification needs threshold or temporal logic.
 * The emitted YAML is parsed back and structurally validated before it is
 * returned, so malformed output cannot reach the UI.
 */

import { parseAllDocuments, stringify } from 'yaml';
import type { Condition, DetectionSpec, PlatformQuery, Stage } from '../schemas.js';
import { APP_NAME } from '../constants.js';
import { scopeNote, sourceScope } from '../mappings/sources.js';
import type { AdapterOptions, SiemAdapter } from './types.js';
import {
  createMappingContext,
  finaliseResult,
  humanWindow,
  mapField,
  mapFieldOrPlaceholder,
  type MappingContext,
  mitreTags,
  scrubLiteral,
  stableUuid,
} from './common.js';

const SEVERITY_TO_LEVEL: Record<string, string> = {
  informational: 'informational',
  low: 'low',
  medium: 'medium',
  high: 'high',
  critical: 'critical',
};

type SigmaValue = string | number | boolean | (string | number | boolean)[];

interface SigmaTerm {
  /** Map name, e.g. `sel_1` / `flt_1`. */
  readonly name: string;
  readonly map: Record<string, SigmaValue>;
  readonly negated: boolean;
  /** Set when the condition cannot be expressed in Sigma. */
  readonly unsupported?: string;
}

function modifierFor(cond: Condition): { suffix: string; negated: boolean; unsupported?: string } {
  const cased = cond.caseSensitive === true ? '|cased' : '';
  switch (cond.operator) {
    case 'equals':
      return { suffix: cased, negated: false };
    case 'not_equals':
      return { suffix: cased, negated: true };
    case 'contains':
      return { suffix: `|contains${cased}`, negated: false };
    case 'not_contains':
      return { suffix: `|contains${cased}`, negated: true };
    case 'startswith':
      return { suffix: `|startswith${cased}`, negated: false };
    case 'not_startswith':
      return { suffix: `|startswith${cased}`, negated: true };
    case 'endswith':
      return { suffix: `|endswith${cased}`, negated: false };
    case 'not_endswith':
      return { suffix: `|endswith${cased}`, negated: true };
    case 'regex':
      return { suffix: '|re', negated: false };
    case 'not_regex':
      return { suffix: '|re', negated: true };
    case 'in':
      return { suffix: cased, negated: false };
    case 'not_in':
      return { suffix: cased, negated: true };
    case 'gt':
      return { suffix: '|gt', negated: false };
    case 'gte':
      return { suffix: '|gte', negated: false };
    case 'lt':
      return { suffix: '|lt', negated: false };
    case 'lte':
      return { suffix: '|lte', negated: false };
    case 'exists':
      return { suffix: '|exists', negated: false };
    case 'not_exists':
      return { suffix: '|exists', negated: true };
    default:
      return { suffix: '', negated: false, unsupported: `operator ${cond.operator} is not expressible in Sigma` };
  }
}

function valueFor(cond: Condition): SigmaValue {
  if (cond.operator === 'exists' || cond.operator === 'not_exists') return true;
  if (Array.isArray(cond.value)) return cond.value.map((v) => (typeof v === 'boolean' ? String(v) : v));
  if (cond.value === undefined) return '';
  if (typeof cond.value === 'boolean') return String(cond.value);
  if (typeof cond.value === 'string') return scrubLiteral(cond.value);
  return cond.value;
}

function buildTerms(ctx: MappingContext, stage: Stage): { terms: SigmaTerm[]; unsupported: string[] } {
  const terms: SigmaTerm[] = [];
  const unsupported: string[] = [];
  let positive = 0;
  let negative = 0;

  for (const cond of stage.conditions) {
    const field = mapFieldOrPlaceholder(ctx, cond.field, stage.telemetry);
    const mod = modifierFor(cond);
    if (mod.unsupported) {
      unsupported.push(mod.unsupported);
      continue;
    }
    const name = mod.negated ? `flt_${(negative += 1)}` : `sel_${(positive += 1)}`;
    terms.push({
      name,
      negated: mod.negated,
      map: { [`${field}${mod.suffix}`]: valueFor(cond) },
    });
  }
  return { terms, unsupported };
}

function stageRule(
  ctx: MappingContext,
  spec: DetectionSpec,
  stage: Stage,
  index: number,
  date: string,
): { doc: Record<string, unknown>; ruleName: string; unsupported: string[] } {
  const logsource = sourceScope(stage.telemetry).sigma;
  if (logsource === null) {
    const logical = `sigma_logsource:${stage.telemetry}`;
    if (!ctx.gaps.some((g) => g.logical === logical)) {
      ctx.gaps.push({
        logical,
        note:
          scopeNote(stage.telemetry, 'sigma') ??
          `No documented Sigma logsource block for ${stage.telemetry} telemetry.`,
      });
    }
  } else {
    const note = scopeNote(stage.telemetry, 'sigma');
    if (note) ctx.notes.add(`Sigma logsource (${stage.telemetry}): ${note}`);
  }

  const { terms, unsupported } = buildTerms(ctx, stage);
  const detection: Record<string, unknown> = {};
  for (const term of terms) detection[term.name] = term.map;

  const condition =
    terms.length === 0
      ? 'selection'
      : terms
          .map((t) => (t.negated ? `not ${t.name}` : t.name))
          .join(stage.conditionLogic === 'all' ? ' and ' : ' or ');
  if (terms.length === 0) detection['selection'] = { '<<MAPPING_REQUIRED>>': true };
  detection['condition'] = condition;

  const multiStage = spec.stages.length > 1;
  const ruleName = `${spec.slug}_${stage.id}`;
  const projected = [
    ...new Set(
      spec.requiredEventFields
        .map((f) => mapField(ctx, f, stage.telemetry))
        .filter((f): f is string => f !== null),
    ),
  ];

  const doc: Record<string, unknown> = {
    title: multiStage
      ? `${scrubLiteral(spec.name)} — Stage ${index + 1}: ${scrubLiteral(stage.name)}`.slice(0, 256)
      : scrubLiteral(spec.name).slice(0, 256),
    id: stableUuid(`${spec.slug}:${stage.id}`),
    ...(multiStage ? { name: ruleName } : {}),
    status: 'experimental',
    description: scrubLiteral(multiStage ? stage.description : spec.objective).slice(0, 1000),
    author: APP_NAME,
    date,
    tags: mitreTags(spec),
    logsource: logsource ?? { definition: `<<MAPPING_REQUIRED:sigma_logsource:${stage.telemetry}>>` },
    detection,
    ...(projected.length > 0 ? { fields: projected } : {}),
    falsepositives: spec.falsePositives.map((f) => scrubLiteral(f).slice(0, 300)),
    level: SEVERITY_TO_LEVEL[spec.severity] ?? 'medium',
  };
  return { doc, ruleName, unsupported };
}

function correlationDoc(
  ctx: MappingContext,
  spec: DetectionSpec,
  ruleNames: readonly string[],
  date: string,
): Record<string, unknown> | null {
  const { correlation } = spec;
  if (correlation.type === 'single_event') return null;

  const groupBy = correlation.groupBy.map((logical) => {
    const names = [...new Set(spec.stages.map((s) => mapField(ctx, logical, s.telemetry)))];
    if (names.length > 1) {
      ctx.notes.add(
        `Sigma correlation group-by "${logical}" resolves to different field names per ` +
          `stage (${names.filter(Boolean).join(', ')}); the correlation requires one ` +
          'shared field name across referenced rules.',
      );
    }
    return names[0] ?? `<<MAPPING_REQUIRED:${logical}>>`;
  });

  const base: Record<string, unknown> = {
    title: `${scrubLiteral(spec.name)} — Correlation`.slice(0, 256),
    id: stableUuid(`${spec.slug}:correlation`),
    status: 'experimental',
    description: scrubLiteral(spec.correlation.description).slice(0, 1000),
    author: APP_NAME,
    date,
    tags: mitreTags(spec),
    level: SEVERITY_TO_LEVEL[spec.severity] ?? 'medium',
  };

  if (correlation.type === 'threshold') {
    const valueCount = correlation.distinctThreshold !== undefined && correlation.thresholdField !== undefined;
    base['correlation'] = {
      type: valueCount ? 'value_count' : 'event_count',
      rules: [...ruleNames],
      'group-by': groupBy,
      timespan: humanWindow(correlation.timeWindowSeconds),
      condition: valueCount
        ? {
            gte: correlation.distinctThreshold,
            field: mapFieldOrPlaceholder(ctx, correlation.thresholdField as string, spec.stages[0]!.telemetry),
          }
        : { gte: correlation.eventThreshold ?? 1 },
    };
    return base;
  }

  base['correlation'] = {
    type: correlation.ordered ? 'temporal_ordered' : 'temporal',
    rules: [...ruleNames],
    'group-by': groupBy,
    timespan: humanWindow(correlation.timeWindowSeconds),
  };
  return base;
}

function build(spec: DetectionSpec, options: AdapterOptions = {}): PlatformQuery {
  const ctx = createMappingContext('sigma');
  const date = options.generatedDate ?? new Date().toISOString().slice(0, 10);
  const syntaxMessages: string[] = [];
  const docs: Record<string, unknown>[] = [];
  const ruleNames: string[] = [];
  const unsupportedAll: string[] = [];

  spec.stages.forEach((stage, index) => {
    const { doc, ruleName, unsupported } = stageRule(ctx, spec, stage, index, date);
    docs.push(doc);
    ruleNames.push(ruleName);
    unsupportedAll.push(...unsupported);
  });

  const correlation = correlationDoc(ctx, spec, ruleNames, date);
  if (correlation) docs.push(correlation);

  if (unsupportedAll.length > 0) {
    syntaxMessages.push(...[...new Set(unsupportedAll)].map((u) => `Sigma cannot express: ${u}.`));
  }

  const yamlText = docs
    .map((doc) => stringify(doc, { lineWidth: 110, singleQuote: true, nullStr: '' }))
    .join('---\n');

  // Structural validation: parse the emitted stream back.
  const parsed = parseAllDocuments(yamlText);
  for (const [i, doc] of parsed.entries()) {
    if (doc.errors.length > 0) {
      syntaxMessages.push(`Document ${i + 1} failed YAML parsing: ${doc.errors[0]?.message ?? 'unknown error'}`);
      continue;
    }
    const value = doc.toJS() as Record<string, unknown> | null;
    if (!value || typeof value !== 'object') {
      syntaxMessages.push(`Document ${i + 1} is not a mapping.`);
      continue;
    }
    for (const required of ['title', 'id', 'status', 'level']) {
      if (!(required in value)) syntaxMessages.push(`Document ${i + 1} is missing required key "${required}".`);
    }
    const isCorrelation = 'correlation' in value;
    if (!isCorrelation) {
      if (!('logsource' in value)) syntaxMessages.push(`Document ${i + 1} is missing "logsource".`);
      const detection = value['detection'] as Record<string, unknown> | undefined;
      if (!detection || typeof detection !== 'object') {
        syntaxMessages.push(`Document ${i + 1} is missing "detection".`);
      } else {
        const cond = detection['condition'];
        if (typeof cond !== 'string' || cond.length === 0) {
          syntaxMessages.push(`Document ${i + 1} has no detection condition.`);
        } else {
          // Every identifier referenced in the condition must be defined.
          const identifiers = cond.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? [];
          const keywords = new Set(['and', 'or', 'not', 'of', 'all', 'them']);
          for (const id of identifiers) {
            if (keywords.has(id) || /^\d+$/.test(id)) continue;
            if (!(id in detection)) {
              syntaxMessages.push(`Document ${i + 1} condition references undefined selection "${id}".`);
            }
          }
        }
      }
    } else {
      const corr = value['correlation'] as Record<string, unknown>;
      const rules = corr['rules'];
      if (!Array.isArray(rules) || rules.length === 0) {
        syntaxMessages.push('Correlation rule references no base rules.');
      } else {
        for (const r of rules) {
          if (!ruleNames.includes(String(r))) {
            syntaxMessages.push(`Correlation references unknown rule name "${String(r)}".`);
          }
        }
      }
    }
  }

  const configurationGuidance: string[] = [
    'Convert to a backend query with `sigma convert -t <backend> <rule.yml>` ' +
      '(pySigma). Install the matching backend package and a pipeline that matches ' +
      'your field normalisation.',
  ];
  if (docs.length > 1) {
    configurationGuidance.push(
      'This is a multi-document rule set using the Sigma correlation specification. ' +
        'Backend support for correlation rules varies — verify your backend version ' +
        'supports correlations before converting.',
    );
  }

  return finaliseResult({
    platform: 'sigma',
    query: yamlText,
    ctx,
    syntaxMessages,
    requiresPlatformConfiguration: false,
    configurationGuidance,
    extraNotes: [
      'Sigma field names follow the Sigma taxonomy for the selected logsource, which ' +
        'is not identical to ECS. Apply a processing pipeline when converting.',
    ],
  });
}

export const sigmaAdapter: SiemAdapter = { platform: 'sigma', build };
