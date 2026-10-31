import { describe, expect, it } from 'vitest';
import { CONDITION_OPERATORS, DetectionSpecSchema, type Condition, type ConditionOperator } from '../src/schemas.js';
import { PLATFORM_IDS } from '../src/constants.js';
import { buildAllPlatforms } from '../src/adapters/index.js';
import { validateStructure } from '../src/validate/syntax.js';
import { GENERATED_DATE } from './fixtures.js';

/**
 * Every operator must be rendered by every adapter.
 *
 * The predicate joiner drops empty strings, so an operator an adapter forgot to
 * handle would silently disappear from the generated query rather than raise an
 * error — the query would still look valid while detecting the wrong thing.
 * These tests make that failure mode impossible to ship.
 */

/** A condition exercising one operator against a field mapped on every platform. */
function conditionFor(operator: ConditionOperator): Condition {
  switch (operator) {
    case 'exists':
    case 'not_exists':
      return { field: 'user.name', operator };
    case 'in':
    case 'not_in':
      return { field: 'destination.port', operator, value: [80, 443] };
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte':
      return { field: 'destination.port', operator, value: 1024 };
    case 'regex':
    case 'not_regex':
      return { field: 'user.name', operator, value: '^svc-[a-z]+$' };
    default:
      return { field: 'user.name', operator, value: 'administrator' };
  }
}

function specFor(operator: ConditionOperator) {
  return DetectionSpecSchema.parse({
    slug: `operator-${operator.replace(/_/g, '-')}`,
    name: `Operator coverage: ${operator}`,
    objective: `Exercise the ${operator} operator across every adapter.`,
    attackScenario: 'Synthetic specification used only to verify operator rendering.',
    vendorId: 'microsoft',
    logSourceIds: ['windows_security_events'],
    requiredEventFields: ['user.name', 'source.ip', 'destination.port'],
    mappingAssumptions: ['Synthetic test specification.'],
    mitre: [
      { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force' },
    ],
    stages: [
      {
        id: 'only-stage',
        name: 'Single stage',
        description: `Applies the ${operator} operator.`,
        telemetry: 'windows_security',
        conditionLogic: 'all',
        conditions: [conditionFor(operator)],
      },
    ],
    correlation: {
      type: 'single_event',
      groupBy: ['user.name'],
      timeWindowSeconds: 600,
      ordered: true,
      description: 'Single-event detection.',
    },
    severity: 'medium',
    falsePositives: ['Synthetic specification; no real false positives apply.'],
    tuning: ['Synthetic specification; no real tuning applies.'],
    validationRecommendations: ['Synthetic specification; used for adapter coverage only.'],
  });
}

describe('every operator is rendered by every adapter', () => {
  it('covers the full operator set', () => {
    // Guards against an operator being added to the schema without test coverage.
    expect(CONDITION_OPERATORS.length).toBeGreaterThanOrEqual(18);
  });

  for (const operator of CONDITION_OPERATORS) {
    describe(`operator: ${operator}`, () => {
      const results = buildAllPlatforms(specFor(operator), { generatedDate: GENERATED_DATE });

      it('produces output for all seven platforms', () => {
        expect(results).toHaveLength(PLATFORM_IDS.length);
        for (const result of results) {
          expect(result.query, result.platform).toBeTruthy();
        }
      });

      for (const platform of PLATFORM_IDS) {
        it(`${platform} renders a predicate rather than dropping it`, () => {
          const result = results.find((r) => r.platform === platform);
          expect(result).toBeDefined();
          const query = result?.query ?? '';

          // The mapped field must appear in the emitted query. If the adapter
          // returned an empty predicate, the join would have discarded it and
          // the field reference would be absent.
          const fieldNames: Record<string, RegExp> = {
            splunk: /\b(?:user|dest_port)\b/,
            sentinel: /\b(?:TargetUserName|RemotePort)\b/,
            qradar: /\b(?:username|destinationport)\b/,
            elastic: /\b(?:user\.name|destination\.port)\b/,
            securonix: /\b(?:accountname|destinationport)\b/,
            fortisiem: /\b(?:user|destIpPort)\b/,
            sigma: /\b(?:TargetUserName|DestinationPort)\b/,
          };
          const pattern = fieldNames[platform];
          expect(pattern, `no field pattern configured for ${platform}`).toBeDefined();

          // Strip comment lines so a field named only in a header does not count.
          const body = query
            .split('\n')
            .filter((line) => {
              const t = line.trimStart();
              return !(t.startsWith('//') || t.startsWith('--') || t.startsWith('#') || t.startsWith('```'));
            })
            .join('\n');
          expect(pattern?.test(body), `${platform} / ${operator} did not reference the mapped field`).toBe(true);
        });

        it(`${platform} produces no structural errors`, () => {
          const result = results.find((r) => r.platform === platform);
          const query = result?.query ?? '';
          const issues = validateStructure(query, platform).filter((i) => i.severity === 'error');

          // Securonix has no portable regex operator; the adapter marks that
          // honestly with a placeholder, which the validator correctly reports.
          if (platform === 'securonix' && (operator === 'regex' || operator === 'not_regex')) {
            expect(issues.length).toBeGreaterThan(0);
            expect(result?.status).not.toBe('validated_syntax');
            expect(query).toContain('REGEX_UNSUPPORTED');
            return;
          }
          expect(issues, `${platform} / ${operator}: ${JSON.stringify(issues)}`).toEqual([]);
        });
      }

      it('never leaves an unresolved mapping placeholder on fully mapped fields', () => {
        for (const result of results) {
          if (result.mappingGaps.length > 0) continue;
          expect(result.query).not.toContain('<<MAPPING_REQUIRED');
        }
      });

      it('escapes the literal rather than interpolating it raw', () => {
        const splunk = results.find((r) => r.platform === 'splunk')?.query ?? '';
        const qradar = results.find((r) => r.platform === 'qradar')?.query ?? '';
        if (operator === 'exists' || operator === 'not_exists') return;
        if (['in', 'not_in', 'gt', 'gte', 'lt', 'lte'].includes(operator)) {
          // Numeric values are emitted bare, which is correct for every dialect.
          expect(splunk).toMatch(/\b(?:80|443|1024)\b/);
          return;
        }
        expect(splunk).toMatch(/"[^"]*"/);
        expect(qradar).toMatch(/'[^']*'/);
      });
    });
  }
});

describe('quote and metacharacter escaping', () => {
  function specWithValue(value: string) {
    const base = specFor('equals');
    return DetectionSpecSchema.parse({
      ...base,
      slug: 'escaping-case',
      stages: [
        {
          ...base.stages[0],
          conditions: [{ field: 'user.name', operator: 'equals', value }],
        },
      ],
    });
  }

  it('escapes embedded double quotes for double-quoted dialects', () => {
    const results = buildAllPlatforms(specWithValue('admin" OR 1=1 --'), { generatedDate: GENERATED_DATE });
    for (const platform of ['splunk', 'sentinel', 'elastic'] as const) {
      const query = results.find((r) => r.platform === platform)?.query ?? '';
      expect(query, platform).toContain('\\"');
      expect(validateStructure(query, platform).filter((i) => i.severity === 'error'), platform).toEqual([]);
    }
  });

  it('doubles embedded single quotes for AQL', () => {
    const results = buildAllPlatforms(specWithValue("admin' OR '1'='1"), { generatedDate: GENERATED_DATE });
    const query = results.find((r) => r.platform === 'qradar')?.query ?? '';
    expect(query).toContain("''");
    expect(validateStructure(query, 'qradar').filter((i) => i.severity === 'error')).toEqual([]);
  });

  it('strips newlines so a value cannot inject a new pipeline stage', () => {
    const results = buildAllPlatforms(specWithValue('admin\n| delete\n'), { generatedDate: GENERATED_DATE });
    const query = results.find((r) => r.platform === 'splunk')?.query ?? '';
    expect(query).not.toMatch(/^\s*\|\s*delete/m);
    expect(validateStructure(query, 'splunk').filter((i) => i.severity === 'error')).toEqual([]);
  });

  it('strips control characters from values', () => {
    const results = buildAllPlatforms(specWithValue('admin\u0000\u0007test'), { generatedDate: GENERATED_DATE });
    for (const result of results) {
      // eslint-disable-next-line no-control-regex -- asserting control characters were stripped
      expect(result.query ?? '').not.toMatch(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/);
    }
  });
});

describe('the no-execution control still catches real constructs', () => {
  it('flags a side-effecting command in executable position', () => {
    const issues = validateStructure('index=main\n| search user=admin\n| delete', 'splunk');
    expect(issues.some((i) => i.severity === 'error' && /side-effecting/.test(i.message))).toBe(true);
  });

  it('flags KQL externaldata in executable position', () => {
    const issues = validateStructure('externaldata(x: string) [@"https://evil.example/a.csv"]', 'sentinel');
    expect(issues.some((i) => i.severity === 'error' && /externaldata/.test(i.message))).toBe(true);
  });

  it('flags a plugin-execution operator', () => {
    const issues = validateStructure('SecurityEvent\n| evaluate python(typeof(*), "import os")', 'sentinel');
    expect(issues.some((i) => i.severity === 'error')).toBe(true);
  });

  it('does not flag the same text inside a quoted literal', () => {
    const issues = validateStructure('index=main\n| where CommandLine=="| delete everything"', 'splunk');
    expect(issues.filter((i) => i.severity === 'error')).toEqual([]);
  });

  it('does not flag the same text inside an AQL literal', () => {
    const issues = validateStructure(
      "SELECT username FROM events WHERE payload ILIKE '%| collect%' LAST 5 MINUTES",
      'qradar',
    );
    expect(issues.filter((i) => i.severity === 'error')).toEqual([]);
  });
});
