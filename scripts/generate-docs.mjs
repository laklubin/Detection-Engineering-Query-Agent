#!/usr/bin/env node
/**
 * Generates documentation directly from the shipped code so it cannot drift:
 *
 *   docs/FIELD-MAPPINGS.md  — the full logical-field -> vendor-field registry
 *   docs/SAMPLE-QUERIES.md  — real adapter output for the synthetic fixtures
 *
 * Run `npm run docs` after changing the mapping registry or any adapter.
 * CI re-runs it and fails if the committed docs differ.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const core = await import('../packages/core/dist/index.js');
const {
  APP_NAME,
  DEMO_MODEL_RESPONSE,
  DetectionSpecSchema,
  LOGICAL_FIELDS,
  LOG_SOURCES,
  PLATFORMS,
  PLATFORM_IDS,
  TELEMETRY_FAMILIES,
  VALIDATION_STATUS_LABEL,
  buildAllPlatforms,
  describeLogicalField,
  resolveField,
  scopeNote,
  sourceScope,
} = core;

const GENERATED_DATE = '2026-10-31';
const ROOT = resolve(import.meta.dirname, '..');
mkdirSync(resolve(ROOT, 'docs'), { recursive: true });

const NOTE = '<!-- GENERATED FILE — run `npm run docs` to regenerate. Do not edit by hand. -->';

function escapeCell(value) {
  return String(value).replace(/\|/g, '\\|').replace(/\n+/g, ' ').trim();
}

// ---------------------------------------------------------------------------
// FIELD-MAPPINGS.md
// ---------------------------------------------------------------------------

function fieldMappings() {
  const out = [];
  out.push(NOTE, '');
  out.push(`# Supported SIEM field mappings`);
  out.push('');
  out.push(
    `${APP_NAME} never invents a vendor field name. Every logical field below is resolved ` +
      'through a documented registry entry. Where a platform has no documented mapping for a ' +
      'telemetry family, the adapter emits a `<<MAPPING_REQUIRED:field>>` placeholder, records ' +
      'the gap, and marks that platform output **Mapping Required** — it does not guess a ' +
      'plausible column name.',
  );
  out.push('');
  out.push('## Legend');
  out.push('');
  out.push('| Symbol | Meaning |');
  out.push('| --- | --- |');
  out.push('| `field` | Documented vendor field used directly in generated queries |');
  out.push('| — | No documented mapping; output is marked Mapping Required |');
  out.push('| ⚠ | A mapping exists but carries a caveat; the caveat is shown in the UI and exports |');
  out.push('');
  out.push('## Platforms');
  out.push('');
  out.push('| Platform | Query language | Standalone query deployable? |');
  out.push('| --- | --- | --- |');
  for (const id of PLATFORM_IDS) {
    const p = PLATFORMS[id];
    out.push(
      `| ${p.product} | ${escapeCell(p.language)} | ${p.standaloneQueryIsDeployable ? 'Yes' : 'No — proprietary rule configuration also required'} |`,
    );
  }
  out.push('');

  out.push('## Telemetry source scopes');
  out.push('');
  out.push('The search scope applied per telemetry family.');
  out.push('');
  for (const telemetry of TELEMETRY_FAMILIES) {
    const scope = sourceScope(telemetry);
    out.push(`### \`${telemetry}\``);
    out.push('');
    out.push('| Platform | Scope |');
    out.push('| --- | --- |');
    for (const id of PLATFORM_IDS) {
      const value = scope[id];
      const rendered =
        value === null || value === undefined
          ? '—'
          : typeof value === 'object'
            ? `\`${escapeCell(JSON.stringify(value))}\``
            : `\`${escapeCell(value)}\``;
      const note = scopeNote(telemetry, id);
      out.push(`| ${PLATFORMS[id].product} | ${rendered}${note ? ` ⚠ ${escapeCell(note)}` : ''} |`);
    }
    out.push('');
  }

  out.push('## Logical field registry');
  out.push('');
  out.push(
    'Mappings are shown per telemetry family because the same logical field resolves to ' +
      'different vendor columns depending on the source table (for example, a process command ' +
      'line in Windows Security auditing versus a Defender XDR device table).',
  );
  out.push('');

  for (const telemetry of TELEMETRY_FAMILIES) {
    if (telemetry === 'generic') continue;
    out.push(`### Telemetry family: \`${telemetry}\``);
    out.push('');
    out.push(`| Logical field | ${PLATFORM_IDS.map((id) => PLATFORMS[id].product).join(' | ')} |`);
    out.push(`| --- |${PLATFORM_IDS.map(() => ' --- |').join('')}`);
    for (const logical of LOGICAL_FIELDS) {
      const cells = PLATFORM_IDS.map((id) => {
        const resolved = resolveField(logical, id, telemetry);
        if (resolved.status === 'mapping_required') return '—';
        return `\`${escapeCell(resolved.physical)}\`${resolved.note ? ' ⚠' : ''}`;
      });
      out.push(`| \`${logical}\` | ${cells.join(' | ')} |`);
    }
    out.push('');
  }

  out.push('## Field definitions');
  out.push('');
  out.push('| Logical field | Meaning |');
  out.push('| --- | --- |');
  for (const logical of LOGICAL_FIELDS) {
    out.push(`| \`${logical}\` | ${escapeCell(describeLogicalField(logical)?.description ?? '')} |`);
  }
  out.push('');

  out.push('## Allowlisted log sources');
  out.push('');
  out.push('| Log source id | Name | Vendor | Telemetry family |');
  out.push('| --- | --- | --- | --- |');
  for (const source of LOG_SOURCES) {
    out.push(`| \`${source.id}\` | ${escapeCell(source.name)} | ${source.vendorId} | \`${source.telemetry}\` |`);
  }
  out.push('');
  out.push('## Adding a mapping');
  out.push('');
  out.push('1. Add or extend the entry in `packages/core/src/mappings/fields.ts`.');
  out.push('2. Add a caveat in `notes` if the field needs parser, data-model or extraction work.');
  out.push('3. Add a test in `packages/core/tests/adapters.test.ts`.');
  out.push('4. Run `npm run docs` so this file is regenerated, then commit both changes.');
  out.push('');
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// SAMPLE-QUERIES.md
// ---------------------------------------------------------------------------

function sampleQueries() {
  const out = [];
  out.push(NOTE, '');
  out.push('# Sample detection queries');
  out.push('');
  out.push(
    'Generated by running the shipped adapters over the synthetic demo fixtures in ' +
      '`packages/core/src/demo/fixtures.ts`. The input data is fictional and contains no ' +
      'customer telemetry, credentials or personal data.',
  );
  out.push('');
  out.push(
    '> **None of these queries has been executed against a live SIEM.** The validation status ' +
      'on each block refers to structural checks performed inside this application only.',
  );
  out.push('');

  for (const raw of DEMO_MODEL_RESPONSE.useCases) {
    const spec = DetectionSpecSchema.parse(raw);
    const queries = buildAllPlatforms(spec, { generatedDate: GENERATED_DATE });

    out.push(`## ${spec.name}`);
    out.push('');
    out.push(`**Objective.** ${spec.objective}`);
    out.push('');
    out.push(`**Attack scenario.** ${spec.attackScenario}`);
    out.push('');
    out.push(
      `**Telemetry.** ${spec.vendorId} / ${spec.logSourceIds.join(', ')} · ` +
        `**Correlation.** ${spec.correlation.type}, window ${spec.correlation.timeWindowSeconds}s` +
        (spec.correlation.eventThreshold ? `, threshold ${spec.correlation.eventThreshold}` : '') +
        ` · **Severity.** ${spec.severity}`,
    );
    out.push('');
    if (spec.mitre.length > 0) {
      out.push(
        `**MITRE ATT&CK.** ${spec.mitre.map((m) => `${m.techniqueId} (${m.techniqueName})`).join(', ')}`,
      );
      out.push('');
    }

    out.push('| Platform | Validation status | Mapping gaps |');
    out.push('| --- | --- | --- |');
    for (const query of queries) {
      out.push(
        `| ${query.product} | ${VALIDATION_STATUS_LABEL[query.status]} | ${
          query.mappingGaps.length === 0 ? 'none' : query.mappingGaps.map((g) => `\`${g.logical}\``).join(', ')
        } |`,
      );
    }
    out.push('');

    for (const query of queries) {
      out.push(`### ${query.product} — ${query.language}`);
      out.push('');
      out.push(`Status: **${VALIDATION_STATUS_LABEL[query.status]}**`);
      out.push('');
      out.push('```' + (query.platform === 'sigma' ? 'yaml' : 'text'));
      out.push(query.query ?? '(this platform cannot express the detection as a standalone query)');
      out.push('```');
      out.push('');
      if (query.mappingGaps.length > 0) {
        out.push('**Mapping required**');
        out.push('');
        for (const gap of query.mappingGaps) out.push(`- \`${gap.logical}\` — ${gap.note}`);
        out.push('');
      }
      if (query.requiresPlatformConfiguration && query.configurationGuidance.length > 0) {
        out.push('**Platform configuration required**');
        out.push('');
        for (const guidance of query.configurationGuidance) out.push(`- ${guidance}`);
        out.push('');
      }
    }
  }
  return out.join('\n');
}

writeFileSync(resolve(ROOT, 'docs/FIELD-MAPPINGS.md'), `${fieldMappings().trimEnd()}\n`);
writeFileSync(resolve(ROOT, 'docs/SAMPLE-QUERIES.md'), `${sampleQueries().trimEnd()}\n`);
console.log('Wrote docs/FIELD-MAPPINGS.md and docs/SAMPLE-QUERIES.md');
