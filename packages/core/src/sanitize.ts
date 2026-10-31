/**
 * Deterministic sanitisation pipeline.
 *
 * Runs server-side, in a fixed order, BEFORE any guardrail classification and
 * long before an LLM request is constructed. It is pure and synchronous so the
 * same input always produces the same decision, and so it can be exhaustively
 * unit tested.
 *
 * Pipeline order:
 *   1. type / size checks
 *   2. Unicode normalisation (NFKC) and invisible-character removal
 *   3. malformed-input rejection
 *   4. raw-log / binary / executable-payload rejection
 *   5. credential, token and PII redaction
 *   6. markup neutralisation
 *   7. whitespace normalisation and final length checks
 */

import { LIMITS } from './constants.js';

export type SanitiseRejectionCode =
  | 'not_a_string'
  | 'empty'
  | 'too_long'
  | 'too_short'
  | 'malformed_encoding'
  | 'raw_log_upload'
  | 'binary_payload'
  | 'excessive_lines'
  | 'low_signal';

export interface SanitiseSuccess {
  readonly ok: true;
  /** Cleaned text that is safe to embed in a structured prompt. */
  readonly text: string;
  /** Human-readable description of every redaction performed. */
  readonly redactions: readonly string[];
  /** True when normalisation changed the input. */
  readonly normalised: boolean;
}

export interface SanitiseFailure {
  readonly ok: false;
  readonly code: SanitiseRejectionCode;
  readonly reason: string;
}

export type SanitiseResult = SanitiseSuccess | SanitiseFailure;

// ---------------------------------------------------------------------------
// Character classes
// ---------------------------------------------------------------------------

/** C0/C1 controls except \n and \t, plus DEL. */
// eslint-disable-next-line no-control-regex -- matching control characters is this module's job
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
/** Zero-width, word-joiner, BOM, bidi overrides, invisible separators. */
const INVISIBLE_CHARS = new RegExp(
  '[' +
    '\\u00AD' + // soft hyphen
    '\\u180E' + // Mongolian vowel separator
    '\\u200B-\\u200F' + // zero-width space/joiners, LRM/RLM
    '\\u202A-\\u202E' + // bidi embedding/override
    '\\u2060-\\u2064' + // word joiner, invisible operators
    '\\u2066-\\u206F' + // bidi isolates, deprecated formatting
    '\\uFEFF' + // BOM / zero-width no-break space
    '\\uFFF9-\\uFFFB' + // interlinear annotation marks
    ']',
  'g',
);
/** Unpaired surrogate halves. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

// ---------------------------------------------------------------------------
// Secret / PII detectors
// ---------------------------------------------------------------------------

interface RedactionRule {
  readonly id: string;
  readonly label: string;
  readonly pattern: RegExp;
  readonly placeholder: string;
}

/**
 * Patterns are intentionally structural. The matched value is never logged,
 * never echoed back and never leaves the process — only the rule label does.
 */
const REDACTION_RULES: readonly RedactionRule[] = [
  {
    id: 'private_key',
    label: 'private key block',
    pattern: /-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END[A-Z ]*PRIVATE KEY-----|$)/g,
    placeholder: '[REDACTED_PRIVATE_KEY]',
  },
  {
    id: 'hf_token',
    label: 'Hugging Face access token',
    pattern: /\bhf_[A-Za-z0-9]{16,}\b/g,
    placeholder: '[REDACTED_TOKEN]',
  },
  {
    id: 'github_token',
    label: 'GitHub token',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
    placeholder: '[REDACTED_TOKEN]',
  },
  {
    id: 'slack_token',
    label: 'Slack token',
    pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
    placeholder: '[REDACTED_TOKEN]',
  },
  {
    id: 'aws_access_key_id',
    label: 'AWS access key id',
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    placeholder: '[REDACTED_AWS_KEY_ID]',
  },
  {
    id: 'google_api_key',
    label: 'Google API key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    placeholder: '[REDACTED_API_KEY]',
  },
  {
    id: 'jwt',
    label: 'JSON web token',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    placeholder: '[REDACTED_JWT]',
  },
  {
    id: 'bearer',
    label: 'bearer/authorization header value',
    pattern: /\b(?:Bearer|Basic|Token)\s+[A-Za-z0-9+/=._~-]{12,}/gi,
    placeholder: '[REDACTED_AUTH_HEADER]',
  },
  {
    id: 'assigned_secret',
    label: 'assigned credential value',
    pattern:
      /\b(?:pass(?:word|wd)?|passphrase|secret|api[_-]?key|apikey|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|private[_-]?key|sas[_-]?token|conn(?:ection)?[_-]?string)\b\s*[:=]\s*(?:"[^"\n]{3,}"|'[^'\n]{3,}'|[^\s,;"']{3,})/gi,
    placeholder: '[REDACTED_CREDENTIAL]',
  },
  {
    id: 'url_basic_auth',
    label: 'credentials embedded in URL',
    pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@/gi,
    placeholder: '[REDACTED_URL_CREDENTIALS]://',
  },
  {
    id: 'azure_storage_key',
    label: 'storage account key',
    pattern: /\bAccountKey\s*=\s*[A-Za-z0-9+/=]{40,}/gi,
    placeholder: 'AccountKey=[REDACTED_KEY]',
  },
  {
    id: 'email',
    label: 'email address (personal data)',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    placeholder: '[REDACTED_EMAIL]',
  },
  {
    id: 'us_ssn',
    label: 'national identification number',
    pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
    placeholder: '[REDACTED_NATIONAL_ID]',
  },
  {
    id: 'payment_card',
    label: 'payment card number',
    pattern: /\b(?:\d[ -]?){13,19}\b/g,
    placeholder: '[REDACTED_PAN]',
  },
  {
    id: 'phone',
    label: 'telephone number (personal data)',
    pattern: /\+\d{1,3}[\s.-]?\(?\d{2,4}\)?(?:[\s.-]?\d{2,4}){2,4}\b/g,
    placeholder: '[REDACTED_PHONE]',
  },
];

/** Luhn check so that generic digit runs are not over-redacted. */
function passesLuhn(digits: string): boolean {
  const cleaned = digits.replace(/\D/g, '');
  if (cleaned.length < 13 || cleaned.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = cleaned.length - 1; i >= 0; i -= 1) {
    let d = cleaned.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

// ---------------------------------------------------------------------------
// Raw-log / binary detectors
// ---------------------------------------------------------------------------

const RAW_LOG_SIGNATURES: readonly RegExp[] = [
  // Syslog priority / RFC3164-ish prefix repeated on multiple lines
  /^<\d{1,3}>\d?\s*[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}/m,
  // Windows EventLog export headers
  /^(?:TimeCreated|TimeGenerated)\s*[,|]\s*(?:EventID|Id)\b/im,
  // CEF / LEEF
  /\bCEF:\d\|/,
  /\bLEEF:\d(?:\.\d)?\|/,
  // Apache/Nginx combined access log
  /^\S+ \S+ \S+ \[\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}/m,
  // Key=value log soup: many pairs on one line
  /(?:\b[a-zA-Z_][\w.-]*=(?:"[^"]*"|\S+)\s+){8,}/,
];

/* eslint-disable no-control-regex -- file magic bytes are control characters by definition */
const BINARY_SIGNATURES: readonly RegExp[] = [
  /^MZ[\s\S]{0,2}/, // PE executable
  /^\x7FELF/, // ELF executable
  /^PK\x03\x04/, // zip / office open xml
  /^%PDF-/, // pdf
  /^\x1F\x8B/, // gzip
  /^data:[a-z]+\/[a-z0-9.+-]+;base64,/i, // inline data URI upload
];
/* eslint-enable no-control-regex */

/**
 * A long uninterrupted base64/hex run is a payload, not a requirement.
 *
 * Checked per whitespace-delimited token so that ordinary multi-line prose is
 * never mistaken for an encoded blob, plus a wrapped-blob heuristic for payloads
 * that were pasted with line breaks.
 */
const OPAQUE_TOKEN_MIN = 200;
const OPAQUE_TOKEN = /^[A-Za-z0-9+/=_-]+$/;

function looksLikeOpaqueBlob(text: string): boolean {
  for (const token of text.split(/\s+/)) {
    if (token.length >= OPAQUE_TOKEN_MIN && OPAQUE_TOKEN.test(token)) return true;
  }
  const lines = text.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
  if (lines.length < 3) return false;
  const blobLines = lines.filter((l) => l.length >= 40 && OPAQUE_TOKEN.test(l)).length;
  return blobLines >= 3 && blobLines / lines.length >= 0.6;
}

function looksLikeRawLog(text: string): boolean {
  if (RAW_LOG_SIGNATURES.some((re) => re.test(text))) return true;
  const lines = text.split('\n').filter((l) => l.trim().length > 0);
  if (lines.length < 4) return false;
  // Many lines each starting with a timestamp => pasted log file.
  const timestamped = lines.filter((l) =>
    /^\s*(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\d{2}\/\d{2}\/\d{4}[ ,]\d{1,2}:\d{2}|[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})/.test(
      l,
    ),
  ).length;
  return timestamped >= Math.max(3, Math.ceil(lines.length * 0.5));
}

function looksLikeStructuredDump(text: string): boolean {
  const trimmed = text.trim();
  if (trimmed.length < 400) return false;
  const jsonish = (trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'));
  if (!jsonish) return false;
  try {
    JSON.parse(trimmed);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Markup neutralisation
// ---------------------------------------------------------------------------

const DANGEROUS_MARKUP: readonly { pattern: RegExp; label: string }[] = [
  { pattern: /<\s*script\b[\s\S]*?(?:<\s*\/\s*script\s*>|$)/gi, label: 'inline script element' },
  { pattern: /<\s*(?:iframe|object|embed|svg|math|link|meta|style|base)\b[^>]*>/gi, label: 'embedded markup element' },
  { pattern: /\bon[a-z]{3,20}\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, label: 'inline event handler' },
  // eslint-disable-next-line no-script-url -- this is the detector for the scheme, not a use of it
  { pattern: /\bjavascript\s*:/gi, label: 'javascript: URI' },
  { pattern: /\bvbscript\s*:/gi, label: 'vbscript: URI' },
  { pattern: /<\s*\/?\s*[a-z][a-z0-9-]*\b[^>]*>/gi, label: 'HTML tag' },
];

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export interface SanitiseOptions {
  readonly maxChars?: number;
  readonly minChars?: number;
  readonly maxLines?: number;
  /** Set false for short selector values where raw-log checks do not apply. */
  readonly applyCorpusChecks?: boolean;
}

export function sanitiseRequirement(input: unknown, options: SanitiseOptions = {}): SanitiseResult {
  const maxChars = options.maxChars ?? LIMITS.requirementMaxChars;
  const minChars = options.minChars ?? LIMITS.requirementMinChars;
  const maxLines = options.maxLines ?? LIMITS.requirementMaxLines;
  const applyCorpusChecks = options.applyCorpusChecks ?? true;

  // 1. Type and size ---------------------------------------------------------
  if (typeof input !== 'string') {
    return { ok: false, code: 'not_a_string', reason: 'Requirement must be a text value.' };
  }
  if (input.length === 0) {
    return { ok: false, code: 'empty', reason: 'Requirement is empty.' };
  }
  if (input.length > maxChars * 4) {
    return {
      ok: false,
      code: 'too_long',
      reason: `Requirement exceeds the ${maxChars}-character limit.`,
    };
  }

  // 2. Unicode normalisation -------------------------------------------------
  const original = input;
  let text = input.normalize('NFKC');
  text = text.replace(/\r\n?/g, '\n');
  text = text.replace(INVISIBLE_CHARS, '');
  text = text.replace(CONTROL_CHARS, ' ');

  // 3. Malformed encoding ----------------------------------------------------
  if (LONE_SURROGATE.test(text)) {
    return { ok: false, code: 'malformed_encoding', reason: 'Requirement contains malformed Unicode.' };
  }
  const replacementCount = (text.match(/�/g) ?? []).length;
  if (replacementCount > 2) {
    return { ok: false, code: 'malformed_encoding', reason: 'Requirement contains undecodable characters.' };
  }

  // 4. Raw-log / binary payloads --------------------------------------------
  if (applyCorpusChecks) {
    if (BINARY_SIGNATURES.some((re) => re.test(text))) {
      return {
        ok: false,
        code: 'binary_payload',
        reason:
          'Binary or encoded file content is not accepted. Describe the detection ' +
          'requirement in words instead of uploading a file or payload.',
      };
    }
    if (looksLikeOpaqueBlob(text)) {
      return {
        ok: false,
        code: 'binary_payload',
        reason:
          'An encoded blob was detected. Submit a written detection requirement, ' +
          'not encoded payload data.',
      };
    }
    const lineCount = text.split('\n').length;
    if (lineCount > maxLines) {
      return {
        ok: false,
        code: 'excessive_lines',
        reason: `Requirement spans ${lineCount} lines; the limit is ${maxLines}. Summarise the detection logic.`,
      };
    }
    if (looksLikeRawLog(text) || looksLikeStructuredDump(text)) {
      return {
        ok: false,
        code: 'raw_log_upload',
        reason:
          'Raw log data is not accepted. Describe the behaviour you want to detect ' +
          'and select the log source instead of pasting events.',
      };
    }
  }

  // 5. Credential / PII redaction -------------------------------------------
  const redactions = new Set<string>();
  for (const rule of REDACTION_RULES) {
    rule.pattern.lastIndex = 0;
    if (rule.id === 'payment_card') {
      text = text.replace(rule.pattern, (match) => {
        if (!passesLuhn(match)) return match;
        redactions.add(rule.label);
        return rule.placeholder;
      });
      continue;
    }
    const replaced = text.replace(rule.pattern, rule.placeholder);
    if (replaced !== text) {
      redactions.add(rule.label);
      text = replaced;
    }
  }

  // 6. Markup neutralisation -------------------------------------------------
  for (const { pattern, label } of DANGEROUS_MARKUP) {
    pattern.lastIndex = 0;
    const replaced = text.replace(pattern, ' ');
    if (replaced !== text) {
      redactions.add(label);
      text = replaced;
    }
  }
  // Remove any orphaned angle brackets so nothing can be reassembled downstream.
  if (/[<>]/.test(text)) {
    text = text.replace(/[<>]/g, ' ');
    redactions.add('angle brackets');
  }

  // 7. Whitespace + final bounds --------------------------------------------
  text = text
    .split('\n')
    .map((line) => line.replace(/[ \t]+/g, ' ').trim())
    .filter((line, idx, arr) => !(line === '' && arr[idx - 1] === ''))
    .join('\n')
    .trim();

  if (text.length === 0) {
    return { ok: false, code: 'empty', reason: 'Requirement is empty after sanitisation.' };
  }
  if (text.length > maxChars) {
    return { ok: false, code: 'too_long', reason: `Requirement exceeds the ${maxChars}-character limit.` };
  }
  if (text.length < minChars) {
    return {
      ok: false,
      code: 'too_short',
      reason: `Requirement must contain at least ${minChars} characters of detection logic.`,
    };
  }
  // Guard against inputs that are only placeholders after redaction.
  const alphaRatio = (text.match(/[A-Za-z]/g) ?? []).length / text.length;
  if (alphaRatio < 0.35) {
    return {
      ok: false,
      code: 'low_signal',
      reason:
        'The requirement does not contain enough descriptive text. Describe the ' +
        'behaviour to detect in plain language.',
    };
  }

  return {
    ok: true,
    text,
    redactions: [...redactions].sort(),
    normalised: text !== original,
  };
}

/** Narrow sanitiser for short allowlisted selector values. */
export function sanitiseSelector(input: unknown): SanitiseResult {
  if (input === undefined || input === null || input === '') {
    return { ok: false, code: 'empty', reason: 'Selector is empty.' };
  }
  return sanitiseRequirement(input, {
    maxChars: LIMITS.selectorMaxChars,
    minChars: 2,
    maxLines: 1,
    applyCorpusChecks: false,
  });
}

/**
 * Redact secrets from a string destined for a log sink. Used by the backend
 * logger so that an unexpected error message can never carry a credential.
 */
export function redactForLogging(value: string): string {
  let out = value;
  for (const rule of REDACTION_RULES) {
    if (rule.id === 'email' || rule.id === 'phone' || rule.id === 'payment_card') continue;
    rule.pattern.lastIndex = 0;
    out = out.replace(rule.pattern, rule.placeholder);
  }
  return out.slice(0, 2000);
}
