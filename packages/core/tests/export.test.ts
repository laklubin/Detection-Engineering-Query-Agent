import { describe, expect, it } from 'vitest';
import { COMMERCIAL_NOTICE, VALIDATION_STATUS_LABEL } from '../src/constants.js';
import {
  exportFilename,
  platformFileExtension,
  queryFileHeader,
  renderBundleJson,
  renderBundleMarkdown,
  renderQueryFile,
  renderUseCaseMarkdown,
} from '../src/export.js';
import { generateDetections } from '../src/llm/generate.js';
import { DEMO_MODEL_RESPONSE } from '../src/demo/fixtures.js';
import { GENERATED_DATE } from './fixtures.js';

async function buildResponse() {
  const { response } = await generateDetections(
    {
      requirement: 'Detect suspicious PowerShell execution followed by external network communication',
      vendorId: 'microsoft',
      logSourceId: 'windows_sysmon',
    },
    { mode: 'live', huggingFace: undefined, generatedDate: GENERATED_DATE },
    { modelOverride: async () => DEMO_MODEL_RESPONSE, requestId: 'export-test' },
  );
  return response;
}

describe('renderUseCaseMarkdown', () => {
  it('documents all required detection-engineering elements', async () => {
    const response = await buildResponse();
    const useCase = response.useCases[0]!;
    const md = renderUseCaseMarkdown(useCase, response.generatedAt);

    for (const heading of [
      '## 1. Detection objective',
      '## 2. Attack scenario',
      '## 3. Required vendor and log sources',
      '## 4. Required event fields and mapping assumptions',
      '## 5. MITRE ATT&CK',
      '## 6. Detection logic and correlation conditions',
      '## 7. Time window and threshold',
      '## 8. False-positive considerations',
      '## 9. Tuning and whitelisting recommendations',
      '## 10. Validation and test recommendations',
      '## 11. Query output per platform',
    ]) {
      expect(md, heading).toContain(heading);
    }
    expect(md).toContain(useCase.useCaseId);
    expect(md).toContain('T1059.001');
  });

  it('renders a section for every platform with its validation status', async () => {
    const response = await buildResponse();
    const useCase = response.useCases[0]!;
    const md = renderUseCaseMarkdown(useCase, response.generatedAt);
    for (const query of useCase.queries) {
      expect(md).toContain(query.product);
      expect(md).toContain(VALIDATION_STATUS_LABEL[query.status]);
    }
  });

  it('surfaces mapping gaps and configuration requirements', async () => {
    const response = await buildResponse();
    const md = renderUseCaseMarkdown(response.useCases[0]!, response.generatedAt);
    expect(md).toContain('**Mapping required**');
    expect(md).toContain('**Platform configuration required**');
  });

  it('states that nothing was executed against a live SIEM', async () => {
    const response = await buildResponse();
    const md = renderUseCaseMarkdown(response.useCases[0]!, response.generatedAt);
    expect(md).toMatch(/has been executed against a live SIEM/i);
  });
});

describe('renderBundleMarkdown', () => {
  it('includes provenance, both use cases and the commercial notice', async () => {
    const response = await buildResponse();
    const md = renderBundleMarkdown(response);
    expect(md).toContain('DetectionForge AI — detection export');
    expect(md).toContain(response.requestId);
    expect(md).toContain('live inference');
    expect(md).toContain(COMMERCIAL_NOTICE);
    for (const useCase of response.useCases) {
      expect(md).toContain(useCase.spec.name);
    }
  });

  it('labels demo output as synthetic', async () => {
    const { response } = await generateDetections(
      {
        requirement: 'Detect suspicious PowerShell execution in Sysmon process creation events',
        vendorId: 'microsoft',
        logSourceId: 'windows_sysmon',
      },
      { mode: 'demo', generatedDate: GENERATED_DATE },
      { requestId: 'demo-export' },
    );
    const md = renderBundleMarkdown(response);
    expect(md).toMatch(/DEMO \(synthetic fixture, not model generated\)/);
  });
});

describe('renderBundleJson', () => {
  it('produces parseable JSON preserving use cases and notices', async () => {
    const response = await buildResponse();
    const parsed = JSON.parse(renderBundleJson(response)) as Record<string, unknown>;
    expect(parsed['application']).toBe('DetectionForge AI');
    expect(parsed['commercialNotice']).toBe(COMMERCIAL_NOTICE);
    expect((parsed['useCases'] as unknown[]).length).toBe(2);
  });
});

describe('renderQueryFile', () => {
  it('stamps a platform-appropriate comment header onto the query', async () => {
    const response = await buildResponse();
    const useCase = response.useCases[0]!;

    const sigma = useCase.queries.find((q) => q.platform === 'sigma')!;
    const sigmaFile = renderQueryFile(useCase, sigma, response.generatedAt);
    expect(sigmaFile.startsWith('# ')).toBe(true);
    expect(sigmaFile).toContain(sigma.query as string);

    const qradar = useCase.queries.find((q) => q.platform === 'qradar')!;
    expect(renderQueryFile(useCase, qradar, response.generatedAt).startsWith('-- ')).toBe(true);

    const splunk = useCase.queries.find((q) => q.platform === 'splunk')!;
    expect(renderQueryFile(useCase, splunk, response.generatedAt).startsWith('``` ')).toBe(true);
  });

  it('records the validation status and the live-SIEM caveat in the header', async () => {
    const response = await buildResponse();
    const useCase = response.useCases[0]!;
    const header = queryFileHeader(useCase, useCase.queries[0]!, response.generatedAt);
    expect(header).toContain(useCase.useCaseId);
    expect(header).toMatch(/Not executed against a live SIEM/);
  });

  it('lists mapping gaps in the header when present', async () => {
    const response = await buildResponse();
    const useCase = response.useCases[0]!;
    const gapped = useCase.queries.find((q) => q.mappingGaps.length > 0)!;
    expect(queryFileHeader(useCase, gapped, response.generatedAt)).toMatch(/Mapping required for:/);
  });
});

describe('exportFilename', () => {
  it('builds a safe filename from untrusted-looking parts', () => {
    expect(exportFilename(['../../etc/passwd', 'Splunk ES'], 'spl')).toBe('etc-passwd_splunk-es.spl');
  });

  it('strips path separators, quotes and shell metacharacters', () => {
    const name = exportFilename(['a/b\\c;rm -rf ~', '"quoted"'], 'json');
    expect(name).not.toMatch(/[/\\;"'~ ]/);
    expect(name.endsWith('.json')).toBe(true);
  });

  it('falls back to a default stem when every part is stripped', () => {
    expect(exportFilename(['///', '***'], 'md')).toBe('detectionforge-export.md');
  });

  it('caps the stem length', () => {
    expect(exportFilename(['x'.repeat(400)], 'md').length).toBeLessThanOrEqual(124);
  });

  it('maps each platform to its documented file extension', () => {
    expect(platformFileExtension('sigma')).toBe('yml');
    expect(platformFileExtension('splunk')).toBe('spl');
    expect(platformFileExtension('sentinel')).toBe('kql');
    expect(platformFileExtension('qradar')).toBe('aql');
    expect(platformFileExtension('elastic')).toBe('eql');
  });
});
