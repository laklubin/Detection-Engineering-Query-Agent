import { describe, expect, it } from 'vitest';
import { redactForLogging, sanitiseRequirement, sanitiseSelector } from '../src/sanitize.js';

const BASE = 'Detect suspicious PowerShell execution followed by external network communication.';

function ok(input: string) {
  const result = sanitiseRequirement(input);
  if (!result.ok) throw new Error(`expected success, got ${result.code}: ${result.reason}`);
  return result;
}

describe('sanitiseRequirement — happy path', () => {
  it('accepts a normal detection requirement unchanged in substance', () => {
    const result = ok(BASE);
    expect(result.text).toBe(BASE);
    expect(result.redactions).toEqual([]);
  });

  it('normalises CRLF, tabs and repeated spaces', () => {
    const result = ok(`Detect   failed\tlogons\r\n\r\n\r\nthen success for the same account`);
    expect(result.text).not.toContain('\r');
    expect(result.text).not.toContain('\t');
    expect(result.text).not.toMatch(/ {2}/);
    expect(result.normalised).toBe(true);
  });

  it('strips zero-width and bidi characters used to hide instructions', () => {
    const result = ok('Detect\u200b password\u202e spray against Entra ID sign-in logs');
    expect(result.text).not.toMatch(/[\u200b\u202e]/);
  });

  it('applies NFKC normalisation to full-width look-alikes', () => {
    const result = ok('Ｄetect ｓuspicious ＰowerShell execution in Sysmon logs');
    expect(result.text).toContain('Detect');
    expect(result.text).toContain('PowerShell');
  });
});

describe('sanitiseRequirement — credential and PII redaction', () => {
  const cases: { name: string; input: string; label: RegExp }[] = [
    {
      name: 'Hugging Face token',
      input: `${BASE} token hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123`,
      label: /Hugging Face access token/,
    },
    {
      name: 'AWS access key id',
      input: `${BASE} key AKIAIOSFODNN7EXAMPLE`,
      label: /AWS access key id/,
    },
    {
      name: 'GitHub token',
      input: `${BASE} ghp_0123456789abcdefghijklmnopqrstuvwx`,
      label: /GitHub token/,
    },
    {
      name: 'JWT',
      input: `${BASE} eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
      label: /JSON web token/,
    },
    {
      name: 'assigned password',
      input: `${BASE} with password=Sup3rSecretValue!`,
      label: /assigned credential value/,
    },
    {
      name: 'api key assignment',
      input: `${BASE} api_key: "abcd1234efgh5678"`,
      label: /assigned credential value/,
    },
    {
      name: 'bearer header',
      input: `${BASE} Authorization Bearer abcdef1234567890xyz`,
      label: /bearer\/authorization header value/,
    },
    {
      name: 'URL basic auth',
      input: `${BASE} source https://admin:hunter2@siem.internal/api`,
      label: /credentials embedded in URL/,
    },
    {
      name: 'email address',
      input: `${BASE} reported by analyst.one@example.com`,
      label: /email address/,
    },
    {
      name: 'private key block',
      input: `${BASE}\n-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----`,
      label: /private key block/,
    },
  ];

  for (const testCase of cases) {
    it(`redacts ${testCase.name} and records it`, () => {
      const result = ok(testCase.input);
      expect(result.redactions.some((r) => testCase.label.test(r))).toBe(true);
      expect(result.text).toMatch(/\[REDACTED_/);
    });
  }

  it('does not leak the secret value into the sanitised text', () => {
    const result = ok(`${BASE} token hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123`);
    expect(result.text).not.toContain('hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123');
  });

  it('redacts a Luhn-valid card number but leaves an ordinary digit run alone', () => {
    const carded = ok(`${BASE} card 4111111111111111 observed`);
    expect(carded.redactions.some((r) => /payment card/.test(r))).toBe(true);

    const plain = ok(`${BASE} correlate over 1234567890123 event ids`);
    expect(plain.redactions.some((r) => /payment card/.test(r))).toBe(false);
  });

  it('keeps generic IP indicators, which are legitimate detection content', () => {
    const result = ok('Detect outbound connections to 203.0.113.42 in firewall logs');
    expect(result.text).toContain('203.0.113.42');
    expect(result.redactions).toEqual([]);
  });
});

describe('sanitiseRequirement — markup neutralisation', () => {
  it('removes script elements', () => {
    const result = ok(`${BASE} <script>alert(1)</script>`);
    expect(result.text.toLowerCase()).not.toContain('<script');
    expect(result.text).not.toContain('<');
    expect(result.redactions.some((r) => /script element/.test(r))).toBe(true);
  });

  it('removes img onerror payloads', () => {
    const result = ok(`${BASE} <img src=x onerror=alert('xss')>`);
    expect(result.text).not.toMatch(/onerror/i);
  });

  it('removes javascript: URIs', () => {
    const result = ok(`${BASE} see javascript:alert(document.cookie)`);
    expect(result.text).not.toMatch(/javascript:/i);
  });

  it('strips stray angle brackets so markup cannot be reassembled', () => {
    const result = ok(`${BASE} compare a < b and c > d values`);
    expect(result.text).not.toMatch(/[<>]/);
  });
});

describe('sanitiseRequirement — rejections', () => {
  it('rejects non-string input', () => {
    expect(sanitiseRequirement({ requirement: 'x' })).toMatchObject({ ok: false, code: 'not_a_string' });
  });

  it('rejects empty input', () => {
    expect(sanitiseRequirement('')).toMatchObject({ ok: false, code: 'empty' });
  });

  it('rejects input that is too short to be a requirement', () => {
    expect(sanitiseRequirement('detect')).toMatchObject({ ok: false, code: 'too_short' });
  });

  it('rejects oversized input', () => {
    expect(sanitiseRequirement('detect powershell '.repeat(2000))).toMatchObject({ ok: false, code: 'too_long' });
  });

  it('rejects malformed Unicode', () => {
    expect(sanitiseRequirement(`${BASE} \uD800 broken`)).toMatchObject({ ok: false, code: 'malformed_encoding' });
  });

  it('rejects a pasted CEF log line', () => {
    const cef =
      'CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232';
    expect(sanitiseRequirement(`Detect this: ${cef}`)).toMatchObject({ ok: false, code: 'raw_log_upload' });
  });

  it('rejects a multi-line timestamped log paste', () => {
    const lines = Array.from(
      { length: 6 },
      (_, i) => `2026-10-31 12:0${i}:00 host sshd[123]: Failed password for root from 10.0.0.${i}`,
    ).join('\n');
    expect(sanitiseRequirement(`Detect these events\n${lines}`)).toMatchObject({ ok: false, code: 'raw_log_upload' });
  });

  it('rejects a large JSON event dump', () => {
    const dump = JSON.stringify({ events: Array.from({ length: 40 }, (_, i) => ({ id: i, message: 'logon failure' })) });
    expect(sanitiseRequirement(dump)).toMatchObject({ ok: false, code: 'raw_log_upload' });
  });

  it('rejects base64 payload blobs', () => {
    expect(sanitiseRequirement(`Detect this payload ${'QUJDREVG'.repeat(60)}`)).toMatchObject({
      ok: false,
      code: 'binary_payload',
    });
  });

  it('rejects an executable file header', () => {
    expect(sanitiseRequirement('MZ\u0090\u0000\u0003 detect this binary please')).toMatchObject({
      ok: false,
      code: 'binary_payload',
    });
  });

  it('rejects a data: URI upload', () => {
    expect(sanitiseRequirement('data:application/zip;base64,UEsDBAoAAAAAAA detect it')).toMatchObject({
      ok: false,
      code: 'binary_payload',
    });
  });

  it('rejects excessive line counts', () => {
    const many = Array.from({ length: 40 }, (_, i) => `detect condition number ${i}`).join('\n');
    expect(sanitiseRequirement(many)).toMatchObject({ ok: false, code: 'excessive_lines' });
  });

  it('rejects low-signal input that is mostly punctuation and digits', () => {
    expect(sanitiseRequirement('4625 4624 4688 ;;; 10.0.0.1 ::: 192.168.1.1 >>> 443 445')).toMatchObject({
      ok: false,
      code: 'low_signal',
    });
  });
});

describe('sanitiseSelector', () => {
  it('rejects empty selectors', () => {
    expect(sanitiseSelector('')).toMatchObject({ ok: false, code: 'empty' });
    expect(sanitiseSelector(undefined)).toMatchObject({ ok: false, code: 'empty' });
  });

  it('accepts a short allowlisted-looking value', () => {
    expect(sanitiseSelector('windows_security_events')).toMatchObject({ ok: true });
  });
});

describe('redactForLogging', () => {
  it('redacts credentials but leaves ordinary text', () => {
    const out = redactForLogging('upstream failed with Bearer abcdef1234567890xyz while calling the router');
    expect(out).not.toContain('abcdef1234567890xyz');
    expect(out).toContain('upstream failed');
  });

  it('caps length so a log line cannot be flooded', () => {
    expect(redactForLogging('x'.repeat(5000)).length).toBeLessThanOrEqual(2000);
  });
});
