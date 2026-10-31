import { describe, expect, it } from 'vitest';
import { PLATFORMS, PLATFORM_IDS, VALIDATION_STATUSES } from '../src/constants.js';
import { ADAPTERS, buildAllPlatforms } from '../src/adapters/index.js';
import { validateStructure } from '../src/validate/syntax.js';
import {
  GENERATED_DATE,
  parseSigmaDocuments,
  sequenceSpec,
  singleEventSpec,
  thresholdSpec,
  unmappedFieldSpec,
} from './fixtures.js';

const SPECS = {
  sequence: sequenceSpec(),
  threshold: thresholdSpec(),
  single: singleEventSpec(),
};

describe('adapter registry', () => {
  it('has exactly one adapter per supported platform', () => {
    expect(Object.keys(ADAPTERS).sort()).toEqual([...PLATFORM_IDS].sort());
    for (const id of PLATFORM_IDS) {
      expect(ADAPTERS[id].platform).toBe(id);
    }
  });

  it('produces all seven formats for every correlation type', () => {
    for (const [name, spec] of Object.entries(SPECS)) {
      const results = buildAllPlatforms(spec, { generatedDate: GENERATED_DATE });
      expect(results, name).toHaveLength(7);
      expect(results.map((r) => r.platform).sort()).toEqual([...PLATFORM_IDS].sort());
      for (const result of results) {
        expect(VALIDATION_STATUSES).toContain(result.status);
        expect(result.product).toBe(PLATFORMS[result.platform].product);
        expect(result.language).toBe(PLATFORMS[result.platform].language);
        expect(result.query, `${name}/${result.platform}`).toBeTruthy();
      }
    }
  });

  it('is deterministic for the same input', () => {
    const a = buildAllPlatforms(SPECS.sequence, { generatedDate: GENERATED_DATE });
    const b = buildAllPlatforms(SPECS.sequence, { generatedDate: GENERATED_DATE });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

describe('Splunk adapter (SPL)', () => {
  it('scopes the search and enforces the correlation window', () => {
    const q = ADAPTERS.splunk.build(SPECS.sequence).query as string;
    expect(q).toContain('index=sysmon');
    expect(q).toContain('| eval dfai_stage=case(');
    expect(q).toContain('| where dfai_stage_count==2');
    expect(q).toContain('| where dfai_window_seconds<=300');
  });

  it('enforces stage ordering for ordered sequences', () => {
    const q = ADAPTERS.splunk.build(SPECS.sequence).query as string;
    expect(q).toMatch(/dfai_suspicious_powershell_time<=dfai_external_egress_time/);
  });

  it('emits bucketed stats and HAVING logic for thresholds', () => {
    const q = ADAPTERS.splunk.build(SPECS.threshold).query as string;
    expect(q).toContain('| bin _time span=600s');
    expect(q).toContain('dc(user) AS dfai_distinct');
    expect(q).toContain('dfai_events>=25');
    expect(q).toContain('dfai_distinct>=10');
  });

  it('escapes string literals and never emits a bare value', () => {
    const q = ADAPTERS.splunk.build(SPECS.sequence).query as string;
    expect(q).toContain('"powershell.exe"');
    expect(q).not.toMatch(/match\([A-Za-z_]+, [^"]/);
  });

  it('reaches syntax-validated status on mapped telemetry', () => {
    expect(ADAPTERS.splunk.build(SPECS.threshold).status).toBe('validated_syntax');
  });
});

describe('Microsoft Sentinel adapter (KQL)', () => {
  it('builds let-bound stages joined on the pivot entities', () => {
    const q = ADAPTERS.sentinel.build(SPECS.sequence).query as string;
    expect(q).toContain('let correlationWindow = 300s;');
    expect(q).toContain('| join kind=inner');
    expect(q).toContain('between (dfai_suspicious_powershell_time ..');
  });

  it('summarises into time buckets for thresholds', () => {
    const q = ADAPTERS.sentinel.build(SPECS.threshold).query as string;
    expect(q).toContain('| summarize EventCount = count()');
    expect(q).toContain('bin(TimeGenerated, correlationWindow)');
    expect(q).toContain('EventCount >= 25');
    expect(q).toContain('DistinctCount >= 10');
  });

  it('uses case-sensitive in for numeric lists and in~ for strings', () => {
    const numeric = ADAPTERS.sentinel.build(SPECS.threshold).query as string;
    expect(numeric).toContain('LogonType in (3, 10)');
    const strings = ADAPTERS.sentinel.build(SPECS.sequence).query as string;
    expect(strings).toContain('in~ ("powershell.exe"');
  });

  it('resolves the Sentinel table from the telemetry family', () => {
    expect(ADAPTERS.sentinel.build(SPECS.threshold).query).toContain('SecurityEvent');
    expect(ADAPTERS.sentinel.build(SPECS.single).query).toContain('SigninLogs');
  });
});

describe('IBM QRadar adapter (AQL)', () => {
  it('emits valid AQL with an explicit time range', () => {
    const result = ADAPTERS.qradar.build(SPECS.threshold);
    const q = result.query as string;
    expect(q).toMatch(/SELECT [\s\S]*FROM events/);
    expect(q).toMatch(/LAST \d+ MINUTES/);
    expect(q).toContain('GROUP BY sourceip');
    expect(q).toContain('HAVING COUNT(*) >= 25');
  });

  it('uses single-quoted literals', () => {
    const q = ADAPTERS.qradar.build(SPECS.sequence).query as string;
    expect(q).toContain("'powershell.exe'");
  });

  it('never claims a deployable rule for a sequence and explains the Rule Wizard requirement', () => {
    const result = ADAPTERS.qradar.build(SPECS.sequence);
    expect(result.requiresPlatformConfiguration).toBe(true);
    expect(result.configurationGuidance.join(' ')).toMatch(/Rule Wizard|building block/i);
    expect(result.status).not.toBe('validated_syntax');
  });

  it('marks undocumented properties as mapping required rather than inventing a column', () => {
    const result = ADAPTERS.qradar.build(SPECS.sequence);
    expect(result.status).toBe('mapping_required');
    expect(result.mappingGaps.map((g) => g.logical)).toContain('process.command_line');
    expect(result.query).toContain('<<MAPPING_REQUIRED:process.command_line>>');
  });
});

describe('Elastic Security adapter (EQL / ES|QL)', () => {
  it('uses a native EQL sequence with maxspan', () => {
    const q = ADAPTERS.elastic.build(SPECS.sequence).query as string;
    expect(q).toContain('sequence by host.name, user.name with maxspan=5m');
    expect(q).toMatch(/\[ any where /);
  });

  it('emits an ES|QL aggregation variant alongside EQL', () => {
    const q = ADAPTERS.elastic.build(SPECS.threshold).query as string;
    expect(q).toContain('// ===== ES|QL =====');
    expect(q).toMatch(/^FROM /m);
    expect(q).toContain('| STATS dfai_events = COUNT(*)');
    expect(q).toContain('dfai_events >= 25');
  });

  it('uses plain in for numeric lists in EQL', () => {
    const q = ADAPTERS.elastic.build(SPECS.sequence).query as string;
    expect(q).toContain('destination.port in (80, 443');
    expect(q).not.toContain('destination.port in~');
  });

  it('uses ECS field names', () => {
    const q = ADAPTERS.elastic.build(SPECS.sequence).query as string;
    expect(q).toContain('process.command_line');
    expect(q).toContain('destination.ip');
  });
});

describe('Securonix adapter (Spotter)', () => {
  it('emits an index-scoped Spotter search per stage', () => {
    const q = ADAPTERS.securonix.build(SPECS.threshold).query as string;
    expect(q).toContain('index = activity');
    expect(q).toContain('rg_functionality = "Microsoft Windows"');
  });

  it('flags regex predicates as unsupported instead of inventing an operator', () => {
    const result = ADAPTERS.securonix.build(SPECS.sequence);
    expect(result.query).toContain('<<REGEX_UNSUPPORTED>>');
    expect(result.validationMessages.join(' ')).toMatch(/no portable regex operator/i);
    expect(result.status).not.toBe('validated_syntax');
  });

  it('describes the policy configuration required for a sequence', () => {
    const result = ADAPTERS.securonix.build(SPECS.sequence);
    expect(result.requiresPlatformConfiguration).toBe(true);
    expect(result.configurationGuidance.join(' ')).toMatch(/Violation Chain|Threat Model/i);
  });
});

describe('FortiSIEM adapter', () => {
  it('emits one filter expression per sub-pattern', () => {
    const q = ADAPTERS.fortisiem.build(SPECS.sequence).query as string;
    expect(q).toContain('# SubPattern 1');
    expect(q).toContain('# SubPattern 2');
    expect(q).toContain('eventType CONTAIN "Win-Sysmon"');
  });

  it('describes the rule structure including the pattern relationship', () => {
    const result = ADAPTERS.fortisiem.build(SPECS.sequence);
    expect(result.query).toContain('FOLLOWED_BY (ordered)');
    expect(result.requiresPlatformConfiguration).toBe(true);
    expect(result.status).not.toBe('validated_syntax');
  });
});

describe('Sigma adapter', () => {
  it('emits parseable YAML documents with required keys', () => {
    const result = ADAPTERS.sigma.build(SPECS.sequence, { generatedDate: GENERATED_DATE });
    const docs = parseSigmaDocuments(result.query as string);
    expect(docs.length).toBe(3);
    for (const doc of docs) {
      expect(typeof doc['title']).toBe('string');
      expect(String(doc['id'])).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      expect(doc['status']).toBe('experimental');
      expect(doc['level']).toBe('high');
    }
  });

  it('builds a temporal_ordered correlation that references the stage rule names', () => {
    const result = ADAPTERS.sigma.build(SPECS.sequence, { generatedDate: GENERATED_DATE });
    const docs = parseSigmaDocuments(result.query as string);
    const correlation = docs.find((d) => 'correlation' in d)?.['correlation'] as Record<string, unknown>;
    expect(correlation['type']).toBe('temporal_ordered');
    expect(correlation['timespan']).toBe('5m');
    const ruleNames = docs.filter((d) => 'name' in d).map((d) => d['name']);
    expect(correlation['rules']).toEqual(ruleNames);
    expect(result.status).toBe('validated_syntax');
  });

  it('builds a value_count correlation for distinct thresholds', () => {
    const result = ADAPTERS.sigma.build(SPECS.threshold, { generatedDate: GENERATED_DATE });
    const docs = parseSigmaDocuments(result.query as string);
    const correlation = docs.find((d) => 'correlation' in d)?.['correlation'] as Record<string, unknown>;
    expect(correlation['type']).toBe('value_count');
    expect(correlation['condition']).toMatchObject({ gte: 10, field: 'TargetUserName' });
  });

  it('emits a single rule with no correlation block for single-event detections', () => {
    const result = ADAPTERS.sigma.build(SPECS.single, { generatedDate: GENERATED_DATE });
    const docs = parseSigmaDocuments(result.query as string);
    expect(docs).toHaveLength(1);
    expect(docs[0]).not.toHaveProperty('correlation');
  });

  it('maps negated operators into filters referenced by the condition', () => {
    const result = ADAPTERS.sigma.build(SPECS.sequence, { generatedDate: GENERATED_DATE });
    const docs = parseSigmaDocuments(result.query as string);
    const stageTwo = docs[1] as Record<string, unknown>;
    const detection = stageTwo['detection'] as Record<string, unknown>;
    expect(String(detection['condition'])).toContain('not flt_1');
    expect(detection).toHaveProperty('flt_1');
  });

  it('includes MITRE tags derived from the specification', () => {
    const result = ADAPTERS.sigma.build(SPECS.sequence, { generatedDate: GENERATED_DATE });
    const docs = parseSigmaDocuments(result.query as string);
    expect(docs[0]?.['tags']).toContain('attack.t1059.001');
    expect(docs[0]?.['tags']).toContain('attack.execution');
  });
});

describe('mapping honesty', () => {
  it('marks every platform lacking a mapping as mapping_required with a placeholder', () => {
    const results = buildAllPlatforms(unmappedFieldSpec(), { generatedDate: GENERATED_DATE });
    const gapped = results.filter((r) => r.mappingGaps.length > 0);
    expect(gapped.length).toBeGreaterThan(0);
    for (const result of gapped) {
      expect(result.status).toBe('mapping_required');
      expect(result.query).toContain('<<MAPPING_REQUIRED:');
      for (const gap of result.mappingGaps) {
        expect(gap.note.length).toBeGreaterThan(10);
      }
    }
  });

  it('never emits a mapping placeholder on a fully mapped specification', () => {
    for (const result of buildAllPlatforms(SPECS.threshold, { generatedDate: GENERATED_DATE })) {
      if (result.mappingGaps.length === 0) {
        expect(result.query).not.toContain('<<MAPPING_REQUIRED');
      }
    }
  });
});

describe('structural validation of every generated query', () => {
  it('produces no structural errors for fully mapped specifications', () => {
    for (const spec of [SPECS.threshold, SPECS.single]) {
      for (const result of buildAllPlatforms(spec, { generatedDate: GENERATED_DATE })) {
        if (result.mappingGaps.length > 0 || result.query === null) continue;
        const issues = validateStructure(result.query, result.platform).filter((i) => i.severity === 'error');
        expect(issues, `${spec.slug}/${result.platform}: ${JSON.stringify(issues)}`).toEqual([]);
      }
    }
  });

  it('never emits a side-effecting or command-executing construct', () => {
    for (const spec of Object.values(SPECS)) {
      for (const result of buildAllPlatforms(spec, { generatedDate: GENERATED_DATE })) {
        if (!result.query) continue;
        expect(result.query).not.toMatch(/\|\s*(?:script|runshellscript|sendemail|collect|delete)\b/i);
        expect(result.query).not.toMatch(/externaldata\s*\(/i);
      }
    }
  });
});
