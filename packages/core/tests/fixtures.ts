/** Synthetic, non-sensitive test fixtures. */
import { parse } from 'yaml';
import { DetectionSpecSchema, type DetectionSpec } from '../src/schemas.js';
import { DEMO_MODEL_RESPONSE } from '../src/demo/fixtures.js';

export const GENERATED_DATE = '2026-10-31';

export function spec(index: number): DetectionSpec {
  const raw = DEMO_MODEL_RESPONSE.useCases[index];
  if (!raw) throw new Error(`no demo use case at index ${index}`);
  const parsed = DetectionSpecSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`demo fixture ${index} is invalid: ${JSON.stringify(parsed.error.issues)}`);
  }
  return parsed.data;
}

export const sequenceSpec = (): DetectionSpec => spec(0);
export const thresholdCapableSpec = (): DetectionSpec => spec(1);

/** A single-event spec exercising a well-mapped telemetry family. */
export function singleEventSpec(): DetectionSpec {
  return DetectionSpecSchema.parse({
    slug: 'suspicious-signin-legacy-auth',
    name: 'Sign-in Using Legacy Authentication Protocol',
    objective: 'Detect interactive sign-ins that used a legacy authentication client, which bypasses MFA.',
    attackScenario:
      'An adversary with valid credentials authenticates through a legacy protocol endpoint that does not ' +
      'support modern authentication, avoiding the MFA requirement enforced by conditional access.',
    vendorId: 'microsoft',
    logSourceIds: ['entra_id_signin'],
    requiredEventFields: ['user.name', 'source.ip', 'auth.app', 'event.outcome'],
    mappingAssumptions: ['SigninLogs is collected into the workspace.'],
    mitre: [
      { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078.004', techniqueName: 'Valid Accounts: Cloud Accounts' },
    ],
    stages: [
      {
        id: 'legacy-auth-signin',
        name: 'Successful legacy-auth sign-in',
        description: 'A successful sign-in from a legacy authentication client.',
        telemetry: 'identity_signin',
        conditionLogic: 'all',
        conditions: [
          { field: 'event.outcome', operator: 'equals', value: 0 },
          { field: 'auth.app', operator: 'not_contains', value: 'Browser' },
          { field: 'user.name', operator: 'exists' },
        ],
      },
    ],
    correlation: {
      type: 'single_event',
      groupBy: ['user.name'],
      timeWindowSeconds: 3600,
      ordered: true,
      description: 'Single-event detection; no correlation required.',
    },
    severity: 'medium',
    falsePositives: ['Legacy line-of-business applications that have not been migrated.'],
    tuning: ['Allow-list service principals that are known to require legacy auth.'],
    validationRecommendations: ['Confirm SigninLogs ingestion and inspect a known legacy client sign-in.'],
  });
}

/** A threshold spec on well-mapped Windows security telemetry. */
export function thresholdSpec(): DetectionSpec {
  return DetectionSpecSchema.parse({
    slug: 'failed-logon-burst',
    name: 'Failed Logon Burst From A Single Source',
    objective: 'Detect a burst of failed network logons from one source address against many accounts.',
    attackScenario: 'An adversary sprays a small password set across many accounts from a single foothold.',
    vendorId: 'microsoft',
    logSourceIds: ['windows_security_events'],
    requiredEventFields: ['event.code', 'user.name', 'source.ip'],
    mappingAssumptions: ['Audit Logon failure auditing is enabled on domain controllers.'],
    mitre: [
      { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1110.003', techniqueName: 'Brute Force: Password Spraying' },
    ],
    stages: [
      {
        id: 'failures',
        name: 'Failed network logons',
        description: 'Windows 4625 failures for network logon types.',
        telemetry: 'windows_security',
        conditionLogic: 'all',
        conditions: [
          { field: 'event.code', operator: 'equals', value: 4625 },
          { field: 'logon.type', operator: 'in', value: [3, 10] },
        ],
      },
    ],
    correlation: {
      type: 'threshold',
      groupBy: ['source.ip'],
      timeWindowSeconds: 600,
      eventThreshold: 25,
      distinctThreshold: 10,
      thresholdField: 'user.name',
      ordered: false,
      description: 'At least 25 failures against 10 distinct accounts from one source in ten minutes.',
    },
    severity: 'high',
    falsePositives: ['NAT gateways and VPN concentrators aggregating many users behind one address.'],
    tuning: ['Exclude known NAT egress ranges or group by account instead for those sources.'],
    validationRecommendations: ['Replay 25 synthetic failures from a lab host and confirm the threshold fires.'],
  });
}

/** Spec that references a field with no documented mapping anywhere. */
export function unmappedFieldSpec(): DetectionSpec {
  return DetectionSpecSchema.parse({
    ...singleEventSpec(),
    slug: 'unmapped-field-case',
    requiredEventFields: ['user.name', 'process.parent.command_line'],
    stages: [
      {
        id: 'unmapped-stage',
        name: 'Condition on an unmapped field',
        description: 'References a field that has no documented mapping for several platforms.',
        telemetry: 'identity_signin',
        conditionLogic: 'all',
        conditions: [{ field: 'process.parent.command_line', operator: 'contains', value: 'rundll32' }],
      },
    ],
  });
}

export function parseSigmaDocuments(yamlText: string): Record<string, unknown>[] {
  return yamlText
    .split(/^---$/m)
    .map((chunk) => chunk.trim())
    .filter((chunk) => chunk.length > 0)
    .map((chunk) => parse(chunk) as Record<string, unknown>);
}
