#!/usr/bin/env node
/**
 * Writes the Sigma rules generated for the synthetic demo fixtures to disk so
 * they can be validated with real Sigma tooling (`sigma check`, pySigma).
 *
 * Usage: node scripts/export-sigma-rules.mjs <output-directory>
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const core = await import('../packages/core/dist/index.js');
const { DEMO_MODEL_RESPONSE, DetectionSpecSchema, ADAPTERS } = core;

const outDir = resolve(process.cwd(), process.argv[2] ?? 'sigma-out');
mkdirSync(outDir, { recursive: true });

let written = 0;
for (const raw of DEMO_MODEL_RESPONSE.useCases) {
  const spec = DetectionSpecSchema.parse(raw);
  const result = ADAPTERS.sigma.build(spec, { generatedDate: '2026-10-31' });
  if (result.query === null) continue;
  const file = resolve(outDir, `${spec.slug}.yml`);
  writeFileSync(file, `${result.query}\n`);
  written += 1;
  console.log(`wrote ${file} (status: ${result.status})`);
}
console.log(`${written} Sigma rule file(s) written to ${outDir}`);
