#!/usr/bin/env node
/**
 * Build-artifact secret scanner.
 *
 * Fails the build if anything credential-shaped is found in a shipped bundle,
 * or if a secret-bearing environment file was packaged. This is the last gate
 * before a frontend bundle is published to GitHub Pages, where it is world
 * readable and cached indefinitely.
 *
 * Usage: node scripts/scan-build-artifacts.mjs [dir ...]
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';

const ROOT = process.cwd();

const TEXT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.json', '.html', '.css', '.map',
  '.txt', '.md', '.yml', '.yaml', '.svg', '.webmanifest',
]);

/** Patterns that must never appear in a shipped artifact. */
const RULES = [
  { id: 'hf-token', label: 'Hugging Face access token', re: /\bhf_[A-Za-z0-9]{20,}\b/g },
  { id: 'github-token', label: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b/g },
  { id: 'aws-key', label: 'AWS access key id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'google-key', label: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'slack-token', label: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{20,}\b/g },
  { id: 'private-key', label: 'private key block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: 'jwt', label: 'JSON web token', re: /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g },
  { id: 'cf-api-token', label: 'Cloudflare API token assignment', re: /CLOUDFLARE_API_TOKEN\s*[:=]\s*["']?[A-Za-z0-9_-]{30,}/g },
  {
    id: 'assigned-secret',
    label: 'assigned credential literal',
    // Deliberately narrow: only flags a long opaque value assigned to a
    // secret-shaped name, which placeholders and code identifiers never match.
    re: /\b(?:HF_TOKEN|SESSION_SIGNING_KEY|API_ACCESS_KEYS|apiKey|accessToken|clientSecret)\s*[:=]\s*["'][A-Za-z0-9+/_-]{24,}["']/g,
  },
];

/** Values that look like secrets but are documented placeholders. */
const ALLOWED = [
  /hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/,
  /AKIAIOSFODNN7EXAMPLE/,
  /0{32,}/,
  /x{20,}/i,
  /placeholder/i,
  /your-?[a-z-]*(?:token|key|id|secret)/i,
  /example/i,
];

const FORBIDDEN_FILENAMES = [/^\.env$/, /^\.env\.(?!example$)/, /^\.dev\.vars$/, /\.pem$/, /\.p12$/, /^id_rsa$/];

function walk(dir, files = []) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return files;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    const stats = statSync(full);
    if (stats.isDirectory()) {
      if (entry === 'node_modules' || entry === '.git') continue;
      walk(full, files);
    } else {
      files.push(full);
    }
  }
  return files;
}

const targets = (process.argv.slice(2).length > 0 ? process.argv.slice(2) : ['packages/web/dist']).map((d) =>
  resolve(ROOT, d),
);

const findings = [];
let scanned = 0;

for (const target of targets) {
  try {
    statSync(target);
  } catch {
    console.error(`! build artifact directory not found: ${relative(ROOT, target)}`);
    process.exitCode = 1;
    continue;
  }

  for (const file of walk(target)) {
    const name = file.split('/').pop() ?? '';
    if (FORBIDDEN_FILENAMES.some((re) => re.test(name))) {
      findings.push({ file: relative(ROOT, file), rule: 'packaged secret file', line: 0, hint: name });
      continue;
    }
    if (!TEXT_EXTENSIONS.has(extname(file))) continue;

    scanned += 1;
    const content = readFileSync(file, 'utf8');
    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      let match;
      while ((match = rule.re.exec(content)) !== null) {
        const value = match[0];
        if (ALLOWED.some((re) => re.test(value))) continue;
        const line = content.slice(0, match.index).split('\n').length;
        findings.push({
          file: relative(ROOT, file),
          rule: rule.label,
          line,
          // The value itself is NEVER printed — only its shape and location.
          hint: `${value.length} chars, starts "${value.slice(0, 4)}…"`,
        });
      }
    }
  }
}

if (findings.length > 0) {
  console.error(`\nFAIL: ${findings.length} potential credential(s) found in build artifacts.`);
  console.error('The matched values are intentionally not printed. Rotate anything real, then remove it.\n');
  for (const finding of findings) {
    console.error(`  ${finding.file}:${finding.line}  ${finding.rule}  (${finding.hint})`);
  }
  process.exit(1);
}

console.log(`OK: scanned ${scanned} file(s) across ${targets.length} target(s); no credential-shaped content found.`);
