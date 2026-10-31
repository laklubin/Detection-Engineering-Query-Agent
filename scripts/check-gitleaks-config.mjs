#!/usr/bin/env node
/**
 * Guard against RE2-incompatible patterns in .gitleaks.toml.
 *
 * gitleaks compiles its regexes with Go's regexp package (RE2), which has no
 * lookahead, lookbehind, backreferences, atomic groups or possessive
 * quantifiers. A pattern using any of them does not produce a scan error — it
 * panics the binary at config-translation time, which in CI looks like an
 * unexplained exit code 2 and leaves the repository unscanned.
 *
 * This check runs before gitleaks so the failure is named rather than guessed.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const file = resolve(process.cwd(), process.argv[2] ?? '.gitleaks.toml');
const content = readFileSync(file, 'utf8');

const UNSUPPORTED = [
  { re: /\(\?=/, what: 'lookahead (?=...)' },
  { re: /\(\?!/, what: 'negative lookahead (?!...)' },
  { re: /\(\?<=/, what: 'lookbehind (?<=...)' },
  { re: /\(\?<!/, what: 'negative lookbehind (?<!...)' },
  { re: /\(\?>/, what: 'atomic group (?>...)' },
  { re: /\\[1-9]\d*/, what: 'backreference' },
  { re: /[*+?}]\+/, what: 'possessive quantifier' },
];

const findings = [];
content.split('\n').forEach((line, index) => {
  // Only regex-bearing lines matter; comments explain the restriction.
  const trimmed = line.trim();
  if (trimmed.startsWith('#')) return;
  if (!/^(?:regex|regexes|paths)\s*=/.test(trimmed) && !trimmed.startsWith("'''")) {
    if (!/'''/.test(line)) return;
  }
  for (const { re, what } of UNSUPPORTED) {
    if (re.test(line)) findings.push({ line: index + 1, what, text: trimmed.slice(0, 100) });
  }
});

if (findings.length > 0) {
  console.error(`FAIL: ${file} contains pattern syntax that Go's RE2 engine cannot compile.`);
  console.error('gitleaks would panic at startup and the repository would go unscanned.\n');
  for (const f of findings) console.error(`  line ${f.line}: ${f.what}\n    ${f.text}`);
  process.exit(1);
}

console.log(`OK: ${file} uses only RE2-compatible pattern syntax.`);
