/**
 * Immutable product constants for DetectionForge AI.
 *
 * SECURITY: the strings in this module are part of the trusted application
 * surface. They are never derived from, nor modifiable by, user input or model
 * output. Any attempt by a prompt to "change the policy message" or "remove the
 * commercial notice" is a no-op because these values are compiled in and the
 * rendering layer reads them from here, not from the response payload.
 */

export const APP_NAME = 'DetectionForge AI' as const;
export const APP_SUBTITLE = 'From Threat Detection Logic to Multi-SIEM Queries' as const;

/** Version of the detection-engineering system prompt contract. */
export const SYSTEM_PROMPT_VERSION = '1.0.0' as const;

/** Hard commercial guardrail: never more than this many use cases per request. */
export const MAX_USE_CASES_PER_REQUEST = 2 as const;

/**
 * Exact, verbatim rejection message required by the product specification.
 * Must not be reworded, templated or interpolated.
 */
export const OFF_TOPIC_REJECTION_MESSAGE =
  'This platform is exclusively designed for Threat Detection Engineering. ' +
  'Please provide your threat detection logic, vendor, or log source. ' +
  'We will convert your requirement into the relevant SIEM detection query.';

/**
 * Exact, verbatim commercial notice shown beneath every successful result set.
 */
export const COMMERCIAL_NOTICE =
  'This free Detection Engineering Agent supports a maximum of 2 use cases per ' +
  'request. For high-fidelity detection use cases, advanced correlation, custom ' +
  'detection engineering, and enterprise DE solutions, please contact Lubin A.K.';

/** Input size limits enforced server-side before any inference call. */
export const LIMITS = {
  /** Maximum characters accepted in the free-text requirement field. */
  requirementMaxChars: 2000,
  /** Minimum characters required to express a detection intent. */
  requirementMinChars: 12,
  /** Maximum characters in vendor / log-source selector values. */
  selectorMaxChars: 120,
  /** Maximum newline count — more than this looks like a pasted raw log. */
  requirementMaxLines: 25,
  /** Maximum JSON request body size in bytes. */
  maxRequestBytes: 16 * 1024,
  /** Maximum characters of model output accepted for parsing. */
  maxModelOutputChars: 120_000,
} as const;

// ---------------------------------------------------------------------------
// Supported SIEM platforms
// ---------------------------------------------------------------------------

export const PLATFORM_IDS = [
  'splunk',
  'sentinel',
  'qradar',
  'elastic',
  'securonix',
  'fortisiem',
  'sigma',
] as const;

export type PlatformId = (typeof PLATFORM_IDS)[number];

export interface PlatformDescriptor {
  readonly id: PlatformId;
  readonly product: string;
  readonly language: string;
  /** Short language slug used by the frontend syntax highlighter. */
  readonly highlight: 'spl' | 'kql' | 'aql' | 'eql' | 'esql' | 'generic' | 'yaml';
  readonly fileExtension: string;
  /**
   * True when a standalone query string is the natural deliverable. False when
   * the platform additionally requires proprietary rule/policy configuration
   * that cannot be expressed as a query — those outputs are always flagged.
   */
  readonly standaloneQueryIsDeployable: boolean;
  readonly notes: string;
}

export const PLATFORMS: Readonly<Record<PlatformId, PlatformDescriptor>> = {
  splunk: {
    id: 'splunk',
    product: 'Splunk Enterprise Security',
    language: 'SPL',
    highlight: 'spl',
    fileExtension: 'spl',
    standaloneQueryIsDeployable: true,
    notes:
      'Search is expressed in SPL. Correlation searches additionally require ES ' +
      'notable-event configuration (governance, throttling, drilldown) which is ' +
      'emitted as commented guidance, not as executable syntax.',
  },
  sentinel: {
    id: 'sentinel',
    product: 'Microsoft Sentinel',
    language: 'KQL',
    highlight: 'kql',
    fileExtension: 'kql',
    standaloneQueryIsDeployable: true,
    notes:
      'KQL analytics rule query. Entity mappings, incident grouping and ' +
      'scheduling live in the Analytics Rule resource (ARM/Bicep), not in KQL.',
  },
  qradar: {
    id: 'qradar',
    product: 'IBM QRadar',
    language: 'AQL',
    highlight: 'aql',
    fileExtension: 'aql',
    standaloneQueryIsDeployable: false,
    notes:
      'AQL is a search language and cannot express QRadar rule tests, building ' +
      'blocks or offense logic. Multi-stage correlation must be built in the Rule ' +
      'Wizard; custom event properties must exist before field references resolve.',
  },
  elastic: {
    id: 'elastic',
    product: 'Elastic Security',
    language: 'EQL / ES|QL',
    highlight: 'eql',
    fileExtension: 'eql',
    standaloneQueryIsDeployable: true,
    notes:
      'Sequence logic maps cleanly to EQL; threshold and aggregation logic is ' +
      'emitted as ES|QL. Both assume ECS-normalised source data.',
  },
  securonix: {
    id: 'securonix',
    product: 'Securonix',
    language: 'Spotter Query Language',
    highlight: 'generic',
    fileExtension: 'txt',
    standaloneQueryIsDeployable: false,
    notes:
      'Spotter search syntax is supported for hunting. Behaviour analytics ' +
      'policies (RBA, peer-group baselines, violation chains) are console-side ' +
      'configuration and are described, never fabricated as query text.',
  },
  fortisiem: {
    id: 'fortisiem',
    product: 'FortiSIEM',
    language: 'Event Search / Rule Expression',
    highlight: 'generic',
    fileExtension: 'txt',
    standaloneQueryIsDeployable: false,
    notes:
      'Event search expressions are supported. FortiSIEM rules are XML/GUI ' +
      'definitions with sub-patterns and are only described structurally; event ' +
      'type and attribute names must be confirmed against the deployed parser.',
  },
  sigma: {
    id: 'sigma',
    product: 'Sigma',
    language: 'Sigma YAML',
    highlight: 'yaml',
    fileExtension: 'yml',
    standaloneQueryIsDeployable: true,
    notes:
      'Vendor-neutral rule. Correlation uses the Sigma correlation specification ' +
      '(v2); backend support for correlation rules varies.',
  },
};

// ---------------------------------------------------------------------------
// Validation status taxonomy
// ---------------------------------------------------------------------------

/**
 * Honest status taxonomy. "validated_syntax" means structural/syntactic checks
 * passed inside this application — it explicitly does NOT mean the query was
 * executed against a live SIEM, and the UI states so.
 */
export const VALIDATION_STATUSES = [
  'validated_syntax',
  'not_validated',
  'mapping_required',
  'unsupported',
] as const;

export type ValidationStatus = (typeof VALIDATION_STATUSES)[number];

export const VALIDATION_STATUS_LABEL: Readonly<Record<ValidationStatus, string>> = {
  validated_syntax: 'Syntax Validated',
  not_validated: 'Not Validated',
  mapping_required: 'Mapping Required',
  unsupported: 'Unsupported',
};

export const VALIDATION_DISCLAIMER =
  'Syntactic and structural validation only. No query in this output has been ' +
  'executed against a live SIEM, data set or tenant. Validate field availability, ' +
  'data-model acceleration and thresholds in your own environment before use.';

export const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];
