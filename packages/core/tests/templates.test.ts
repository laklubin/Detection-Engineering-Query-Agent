import { describe, expect, it } from 'vitest';
import { PLATFORM_IDS, MAX_USE_CASES_PER_REQUEST } from '../src/constants.js';
import { LOG_SOURCES, TELEMETRY_FAMILIES, type TelemetryFamily } from '../src/catalog.js';
import { DetectionSpecSchema, ModelResponseSchema } from '../src/schemas.js';
import { buildAllPlatforms } from '../src/adapters/index.js';
import { validateStructure } from '../src/validate/syntax.js';
import { TEMPLATES, buildSpec, generateFromTemplates, rankTemplates, scoreTemplate } from '../src/templates/engine.js';
import { GENERATED_DATE } from './fixtures.js';

describe('template catalogue integrity', () => {
  it('has a usable number of templates', () => {
    expect(TEMPLATES.length).toBeGreaterThanOrEqual(12);
  });

  it('has unique ids', () => {
    const ids = TEMPLATES.map((t) => t.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('declares only real telemetry families', () => {
    for (const template of TEMPLATES) {
      expect(template.telemetry.length).toBeGreaterThan(0);
      for (const family of template.telemetry) {
        expect(TELEMETRY_FAMILIES, `${template.id}: ${family}`).toContain(family);
      }
    }
  });

  it('declares lowercase keywords only', () => {
    for (const template of TEMPLATES) {
      expect(template.keywords.length).toBeGreaterThan(0);
      for (const keyword of template.keywords) {
        expect(keyword, `${template.id}`).toBe(keyword.toLowerCase());
      }
    }
  });
});

describe('every template produces a valid, renderable detection', () => {
  for (const template of TEMPLATES) {
    describe(template.id, () => {
      // Exercise each template against every telemetry family it claims, and
      // against an incompatible one, so the fallback path is covered too.
      const families: (TelemetryFamily | null)[] = [...template.telemetry, null, 'generic'];

      for (const telemetry of families) {
        it(`builds a schema-valid spec for telemetry=${String(telemetry)}`, () => {
          const logSource = telemetry === null ? undefined : LOG_SOURCES.find((s) => s.telemetry === telemetry);
          const spec = buildSpec(
            template,
            { requirement: 'synthetic', vendorId: undefined, logSourceId: logSource?.id },
            telemetry,
          );
          expect(DetectionSpecSchema.safeParse(spec).success).toBe(true);
          expect(spec.slug.length).toBeGreaterThan(1);
          expect(spec.mitre.length).toBeGreaterThan(0);
        });
      }

      it('renders on all seven platforms with no structural errors on mapped fields', () => {
        const spec = buildSpec(template, { requirement: 'synthetic', vendorId: undefined, logSourceId: undefined }, null);
        const results = buildAllPlatforms(spec, { generatedDate: GENERATED_DATE });
        expect(results).toHaveLength(PLATFORM_IDS.length);

        for (const result of results) {
          expect(result.query, `${template.id}/${result.platform}`).toBeTruthy();
          if (result.mappingGaps.length > 0) continue;
          const errors = validateStructure(result.query as string, result.platform).filter(
            (i) => i.severity === 'error',
          );
          // Securonix cannot express regex; the adapter marks that honestly.
          if (result.platform === 'securonix' && (result.query as string).includes('REGEX_UNSUPPORTED')) continue;
          expect(errors, `${template.id}/${result.platform}: ${JSON.stringify(errors)}`).toEqual([]);
        }
      });

      it('carries real detection-engineering content', () => {
        const spec = buildSpec(template, { requirement: 'synthetic', vendorId: undefined, logSourceId: undefined }, null);
        expect(spec.objective.length).toBeGreaterThan(80);
        expect(spec.attackScenario.length).toBeGreaterThan(120);
        expect(spec.falsePositives.length).toBeGreaterThanOrEqual(3);
        expect(spec.tuning.length).toBeGreaterThanOrEqual(3);
        expect(spec.validationRecommendations.length).toBeGreaterThanOrEqual(2);
        for (const m of spec.mitre) {
          expect(m.techniqueId).toMatch(/^T\d{4}(\.\d{3})?$/);
        }
      });
    });
  }
});

describe('matching behaves sensibly on real phrasing', () => {
  const cases: { query: string; expectTop: string }[] = [
    { query: 'Detect multiple failed logins followed by successful authentication', expectTop: 'failed-then-successful-auth' },
    { query: 'detect password spraying against many accounts from one source', expectTop: 'password-spray' },
    { query: 'suspicious powershell with encoded command', expectTop: 'suspicious-powershell' },
    { query: 'alert on lsass credential dumping with procdump', expectTop: 'credential-dumping' },
    { query: 'detect persistence via registry run key or scheduled task', expectTop: 'persistence-autorun' },
    { query: 'someone disabled defender and cleared the event log', expectTop: 'defense-evasion-tampering' },
    { query: 'find dns tunnelling and beaconing in resolver logs', expectTop: 'dns-beaconing' },
    { query: 'large outbound data transfer exfiltration to external host', expectTop: 'data-exfiltration-volume' },
    { query: 'detect privilege escalation via iam role assignment in cloudtrail', expectTop: 'cloud-privilege-escalation' },
    { query: 'impossible travel and legacy authentication sign-in', expectTop: 'impossible-travel' },
    { query: 'web shell dropped on the iis web server', expectTop: 'web-shell' },
    { query: 'lateral movement using psexec and wmi remote execution', expectTop: 'lateral-movement-remote-exec' },
    { query: 'ransomware deleting shadow copies before encryption', expectTop: 'ransomware-precursor' },
    { query: 'phishing email with a malicious attachment', expectTop: 'phishing-email' },
    { query: 'linux host using curl piped to bash reverse shell', expectTop: 'linux-suspicious-execution' },
  ];

  for (const { query, expectTop } of cases) {
    it(`ranks "${query.slice(0, 44)}" to ${expectTop}`, () => {
      const ranked = rankTemplates(query, null);
      expect(ranked.length, 'no template matched').toBeGreaterThan(0);
      expect(ranked[0]?.template.id).toBe(expectTop);
    });
  }

  it('is deterministic', () => {
    const a = rankTemplates('detect password spraying', null).map((m) => m.template.id);
    const b = rankTemplates('detect password spraying', null).map((m) => m.template.id);
    expect(a).toEqual(b);
  });

  it('scores multi-word phrases above single words', () => {
    const template = TEMPLATES.find((t) => t.id === 'password-spray');
    expect(template).toBeDefined();
    const phrase = scoreTemplate(template!, 'password spray detected', null).score;
    const single = scoreTemplate(template!, 'spray detected', null).score;
    expect(phrase).toBeGreaterThan(single);
  });

  it('does not let telemetry selection alone select a template', () => {
    const template = TEMPLATES.find((t) => t.id === 'dns-beaconing');
    const scored = scoreTemplate(template!, 'something entirely unrelated to security', 'dns');
    expect(scored.score).toBe(0);
  });
});

describe('generateFromTemplates', () => {
  it('returns at most two use cases', () => {
    const response = generateFromTemplates({
      // Deliberately matches several templates at once.
      requirement: 'detect powershell, password spray, lsass credential dumping and dns beaconing',
      vendorId: 'microsoft',
      logSourceId: 'windows_security_events',
    });
    expect(response.status).toBe('ok');
    expect(response.useCases.length).toBeLessThanOrEqual(MAX_USE_CASES_PER_REQUEST);
    expect(response.useCases.length).toBeGreaterThan(0);
  });

  it('emits a schema-valid model response', () => {
    const response = generateFromTemplates({
      requirement: 'detect multiple failed logins followed by successful authentication',
      vendorId: 'microsoft',
      logSourceId: 'windows_security_events',
    });
    expect(ModelResponseSchema.safeParse(response).success).toBe(true);
  });

  it('adapts the detection to the selected log source', () => {
    const windows = generateFromTemplates({
      requirement: 'detect failed logins followed by successful authentication',
      vendorId: 'microsoft',
      logSourceId: 'windows_security_events',
    });
    const okta = generateFromTemplates({
      requirement: 'detect failed logins followed by successful authentication',
      vendorId: 'okta',
      logSourceId: 'okta_system_log',
    });

    expect(windows.useCases[0]?.stages[0]?.telemetry).toBe('windows_security');
    expect(okta.useCases[0]?.stages[0]?.telemetry).toBe('identity_signin');
    // Windows uses event ids; the identity variant uses a result code instead.
    const windowsFields = windows.useCases[0]?.stages[0]?.conditions.map((c) => c.field) ?? [];
    const oktaFields = okta.useCases[0]?.stages[0]?.conditions.map((c) => c.field) ?? [];
    expect(windowsFields).toContain('event.code');
    expect(oktaFields).toContain('event.outcome');
  });

  it('asks for clarification instead of guessing when nothing matches', () => {
    const response = generateFromTemplates({
      requirement: 'detect something unusual happening on the network somewhere',
      vendorId: undefined,
      logSourceId: undefined,
    });
    expect(response.status).toBe('needs_clarification');
    expect(response.useCases).toHaveLength(0);
    expect(response.clarifyingQuestion).toMatch(/no detection template matched/i);
  });

  it('never returns two copies of the same detection', () => {
    const response = generateFromTemplates({
      requirement: 'failed login failed logon failed authentication brute force password guessing',
      vendorId: 'microsoft',
      logSourceId: 'windows_security_events',
    });
    const slugs = response.useCases.map((u) => u.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
  });
});

describe('scoring weights distinctive words above common ones', () => {
  it('matches a single distinctive term such as powershell', () => {
    const ranked = rankTemplates('detect suspicious powershell execution', null);
    expect(ranked.length).toBeGreaterThan(0);
    expect(ranked[0]?.template.id).toBe('suspicious-powershell');
  });

  it('matches other single distinctive terms', () => {
    for (const [term, expected] of [
      ['lsass', 'credential-dumping'],
      ['ransomware', 'ransomware-precursor'],
      ['phishing', 'phishing-email'],
      ['webshell', 'web-shell'],
    ] as const) {
      const ranked = rankTemplates(`detect ${term} activity`, null);
      expect(ranked[0]?.template.id, term).toBe(expected);
    }
  });

  it('does not match on a single common word alone', () => {
    // "beacon" is claimed by more than one template, so it is weak evidence.
    expect(rankTemplates('beacon', null)).toHaveLength(0);
  });

  it('tolerates inflection and filler words', () => {
    expect(rankTemplates('someone disabled defender and cleared the event log', null)[0]?.template.id).toBe(
      'defense-evasion-tampering',
    );
    expect(rankTemplates('detecting failed logons then successful authentication', null).length).toBeGreaterThan(0);
  });

  it('does not match a short prefix loosely', () => {
    // "spray" must not be satisfied by an unrelated word starting with it.
    const spray = TEMPLATES.find((t) => t.id === 'password-spray');
    expect(scoreTemplate(spray!, 'sprayer maintenance schedule', null).matchedTerms).not.toContain('spray');
  });
});

describe('every template is reachable end to end', () => {
  // The catalogue is only useful if a user can actually get to each entry.
  // For every template: its own example phrasing must survive sanitisation,
  // pass the guardrails, and rank that template first.
  for (const template of TEMPLATES) {
    it(`"${template.example.slice(0, 52)}" reaches ${template.id}`, async () => {
      const { sanitiseRequirement } = await import('../src/sanitize.js');
      const { evaluateGuardrails } = await import('../src/guardrails.js');

      const sanitised = sanitiseRequirement(template.example);
      expect(sanitised.ok, `${template.id}: example failed sanitisation`).toBe(true);
      if (!sanitised.ok) return;

      const guardrail = evaluateGuardrails({
        requirement: sanitised.text,
        hasVendor: false,
        hasLogSource: false,
      });
      expect(guardrail.allowed, `${template.id}: example blocked by guardrails`).toBe(true);

      const ranked = rankTemplates(sanitised.text, null);
      expect(ranked[0]?.template.id, `${template.id}: example ranked to ${ranked[0]?.template.id}`).toBe(template.id);
    });
  }

  it('produces a full seven-format result for every example', async () => {
    for (const template of TEMPLATES) {
      const response = generateFromTemplates({
        requirement: template.example,
        vendorId: undefined,
        logSourceId: undefined,
      });
      expect(response.status, template.id).toBe('ok');
      expect(response.useCases.length, template.id).toBeGreaterThan(0);
      const queries = buildAllPlatforms(response.useCases[0]!, { generatedDate: GENERATED_DATE });
      expect(queries, template.id).toHaveLength(PLATFORM_IDS.length);
    }
  });

  it('gives every template a distinct example', () => {
    const examples = TEMPLATES.map((t) => t.example.toLowerCase());
    expect(new Set(examples).size).toBe(examples.length);
  });
});
