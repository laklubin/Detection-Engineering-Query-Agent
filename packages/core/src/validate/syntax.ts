/**
 * Cross-platform structural validation.
 *
 * These checks are syntactic only. They prove that a query is well formed —
 * balanced delimiters, no unresolved placeholders, no stray markers — and
 * nothing more. They never execute a query and never contact a SIEM.
 */

import type { PlatformId } from '../constants.js';

export interface StructuralIssue {
  readonly severity: 'error' | 'warning';
  readonly message: string;
}

const MAPPING_PLACEHOLDER_RE = /<<MAPPING_REQUIRED:([^>]*)>>|<<MAPPING_REQUIRED>>/g;
const UNSUPPORTED_PLACEHOLDER_RE = /<<([A-Z_]+)>>/g;

/** Verify brackets and quotes are balanced outside of comments. */
export function checkBalanced(query: string, platform: PlatformId): StructuralIssue[] {
  const issues: StructuralIssue[] = [];
  const stack: string[] = [];
  const pairs: Record<string, string> = { '(': ')', '[': ']', '{': '}' };
  const closers = new Set([')', ']', '}']);

  let inDouble = false;
  let inSingle = false;
  let escaped = false;

  // YAML is validated by a real parser in the Sigma adapter.
  if (platform === 'sigma') return issues;

  const lines = query.split('\n');
  for (const [lineNo, line] of lines.entries()) {
    const trimmed = line.trimStart();
    // Skip comment lines per platform conventions.
    if (
      trimmed.startsWith('//') ||
      trimmed.startsWith('--') ||
      trimmed.startsWith('#') ||
      (trimmed.startsWith('```') && trimmed.endsWith('```'))
    ) {
      continue;
    }
    for (const ch of line) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch === '\\') {
        escaped = true;
        continue;
      }
      if (inDouble) {
        if (ch === '"') inDouble = false;
        continue;
      }
      if (inSingle) {
        if (ch === "'") inSingle = false;
        continue;
      }
      if (ch === '"') {
        inDouble = true;
        continue;
      }
      if (ch === "'") {
        inSingle = true;
        continue;
      }
      if (ch in pairs) {
        stack.push(pairs[ch] as string);
        continue;
      }
      if (closers.has(ch)) {
        const expected = stack.pop();
        if (expected !== ch) {
          issues.push({
            severity: 'error',
            message: `Unbalanced "${ch}" on line ${lineNo + 1}.`,
          });
          return issues;
        }
      }
    }
    if (inDouble || inSingle) {
      // Literals do not span lines in any supported language.
      issues.push({ severity: 'error', message: `Unterminated string literal on line ${lineNo + 1}.` });
      inDouble = false;
      inSingle = false;
      escaped = false;
    }
  }
  if (stack.length > 0) {
    issues.push({ severity: 'error', message: `${stack.length} unclosed bracket(s).` });
  }
  return issues;
}

/** Report unresolved placeholders emitted by the mapping layer. */
export function checkPlaceholders(query: string): StructuralIssue[] {
  const issues: StructuralIssue[] = [];
  MAPPING_PLACEHOLDER_RE.lastIndex = 0;
  const mapping = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = MAPPING_PLACEHOLDER_RE.exec(query)) !== null) {
    mapping.add(m[1] ?? 'unnamed');
  }
  for (const name of mapping) {
    issues.push({
      severity: 'error',
      message: `Unresolved field/scope mapping for "${name}" — supply the vendor field before use.`,
    });
  }
  UNSUPPORTED_PLACEHOLDER_RE.lastIndex = 0;
  while ((m = UNSUPPORTED_PLACEHOLDER_RE.exec(query)) !== null) {
    const token = m[1] as string;
    if (token.startsWith('MAPPING_REQUIRED')) continue;
    issues.push({
      severity: 'error',
      message: `Unsupported construct marker "${token}" present — this predicate must be reworked manually.`,
    });
  }
  return issues;
}

/** Reject any query containing an executable shell/host escape marker. */
export function checkNoExecution(query: string): StructuralIssue[] {
  const issues: StructuralIssue[] = [];
  const dangerous: readonly { re: RegExp; what: string }[] = [
    { re: /\|\s*script\b/i, what: 'Splunk `script` command' },
    { re: /\|\s*(?:runshellscript|sendemail|outputlookup|collect|delete)\b/i, what: 'side-effecting SPL command' },
    { re: /\bexternaldata\s*\(/i, what: 'KQL `externaldata` operator' },
    { re: /\b(?:evaluate\s+python|evaluate\s+r)\b/i, what: 'KQL plugin execution' },
    { re: /\bhttp_request\b/i, what: 'outbound request function' },
  ];
  for (const { re, what } of dangerous) {
    if (re.test(query)) {
      issues.push({
        severity: 'error',
        message: `${what} is not permitted in generated output: queries are read-only by policy.`,
      });
    }
  }
  return issues;
}

/** Platform-specific smoke checks. */
export function checkPlatformShape(query: string, platform: PlatformId): StructuralIssue[] {
  const issues: StructuralIssue[] = [];
  const body = query
    .split('\n')
    .filter((l) => {
      const t = l.trimStart();
      return !(t.startsWith('//') || t.startsWith('--') || t.startsWith('#') || t.startsWith('```'));
    })
    .join('\n')
    .trim();

  if (body.length === 0) {
    issues.push({ severity: 'error', message: 'Query body is empty.' });
    return issues;
  }

  switch (platform) {
    case 'splunk':
      if (!/^(?:index=|\(|\||search\b|tstats\b)/.test(body)) {
        issues.push({ severity: 'warning', message: 'SPL does not begin with an index scope or pipeline command.' });
      }
      break;
    case 'sentinel':
      if (!/\|\s*(?:where|summarize|project|join|extend|union)\b/.test(body)) {
        issues.push({ severity: 'warning', message: 'KQL contains no recognised tabular operator.' });
      }
      break;
    case 'qradar':
      if (!/\bSELECT\b[\s\S]*\bFROM\b/.test(body)) {
        issues.push({ severity: 'error', message: 'AQL is missing a SELECT ... FROM statement.' });
      }
      if (!/\bLAST\s+\d+\s+(?:SECONDS|MINUTES|HOURS|DAYS)\b/i.test(body)) {
        issues.push({ severity: 'warning', message: 'AQL has no explicit time range; QRadar will apply a default.' });
      }
      break;
    case 'elastic':
      if (!/\bsequence\b|\bwhere\b/.test(body)) {
        issues.push({ severity: 'warning', message: 'No EQL body detected.' });
      }
      if (!/^\s*FROM\s+\S+/m.test(body)) {
        issues.push({ severity: 'warning', message: 'No ES|QL source command detected.' });
      }
      break;
    case 'securonix':
      if (!/index\s*=\s*\w+/.test(body)) {
        issues.push({ severity: 'warning', message: 'Spotter search has no index scope.' });
      }
      break;
    case 'fortisiem':
      if (!/[=!<>]|CONTAIN|REGEXP|IN\s*\(/.test(body)) {
        issues.push({ severity: 'warning', message: 'No FortiSIEM filter expression detected.' });
      }
      break;
    case 'sigma':
      if (!/\bdetection\b/.test(body) && !/\bcorrelation\b/.test(body)) {
        issues.push({ severity: 'error', message: 'Sigma YAML has neither a detection nor a correlation block.' });
      }
      break;
    default:
      break;
  }
  return issues;
}

/** Run every structural check for a platform query. */
export function validateStructure(query: string, platform: PlatformId): StructuralIssue[] {
  return [
    ...checkPlaceholders(query),
    ...checkNoExecution(query),
    ...checkBalanced(query, platform),
    ...checkPlatformShape(query, platform),
  ];
}
