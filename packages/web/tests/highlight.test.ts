import { describe, expect, it } from 'vitest';
import { tokenize, tokenizeLine } from '../src/lib/highlight.js';

function reassemble(code: string, language: Parameters<typeof tokenize>[1]): string {
  return tokenize(code, language)
    .map((line) => line.map((token) => token.text).join(''))
    .join('\n');
}

describe('tokeniser integrity', () => {
  const samples: { lang: Parameters<typeof tokenize>[1]; code: string }[] = [
    { lang: 'spl', code: 'index=wineventlog\n| where EventCode==4625\n| stats count AS c by user' },
    { lang: 'kql', code: 'SecurityEvent\n| where EventID == 4625\n| summarize c = count() by Account' },
    { lang: 'aql', code: "SELECT username FROM events WHERE sourceip = '10.0.0.1' LAST 5 MINUTES" },
    { lang: 'eql', code: 'sequence by user.name with maxspan=5m\n  [ any where process.name : "cmd.exe" ]' },
    { lang: 'yaml', code: 'title: Test\ndetection:\n  sel_1:\n    EventID: 4625\n  condition: sel_1' },
    { lang: 'generic', code: 'index = activity AND accountname = "svc" AND destinationport IN (443)' },
  ];

  for (const sample of samples) {
    it(`never loses or duplicates a character for ${sample.lang}`, () => {
      expect(reassemble(sample.code, sample.lang)).toBe(sample.code);
    });
  }

  it('is lossless for adversarial input containing markup', () => {
    const hostile = `| where x=="<script>alert('xss')</script>" AND y=='</pre><img onerror=1>'`;
    expect(reassemble(hostile, 'spl')).toBe(hostile);
  });

  it('terminates on pathological input', () => {
    const pathological = '('.repeat(2000);
    expect(reassemble(pathological, 'kql')).toBe(pathological);
  });

  it('handles empty input', () => {
    expect(tokenize('', 'spl')).toEqual([[]]);
  });

  it('produces plain token objects with no HTML', () => {
    for (const token of tokenizeLine('| where a=="<b>"', 'spl')) {
      expect(typeof token.text).toBe('string');
      expect(Object.keys(token).sort()).toEqual(['cls', 'text']);
    }
  });
});

describe('token classification', () => {
  it('marks mapping placeholders as warnings so they are visually obvious', () => {
    const tokens = tokenizeLine('WHERE <<MAPPING_REQUIRED:process.command_line>> IS NOT NULL', 'aql');
    expect(tokens.some((t) => t.cls === 'tok-warn' && t.text.includes('MAPPING_REQUIRED'))).toBe(true);
  });

  it('marks comments for each language', () => {
    expect(tokenizeLine('// a comment', 'kql')[0]?.cls).toBe('tok-comment');
    expect(tokenizeLine('-- a comment', 'aql')[0]?.cls).toBe('tok-comment');
    expect(tokenizeLine('# a comment', 'yaml')[0]?.cls).toBe('tok-comment');
    expect(tokenizeLine('``` a comment ```', 'spl')[0]?.cls).toBe('tok-comment');
  });

  it('marks string literals and numbers', () => {
    const tokens = tokenizeLine('| where CommandLine=="powershell.exe" AND EventCode==4688', 'spl');
    expect(tokens.some((t) => t.cls === 'tok-string' && t.text === '"powershell.exe"')).toBe(true);
    expect(tokens.some((t) => t.cls === 'tok-number' && t.text === '4688')).toBe(true);
  });

  it('marks YAML keys', () => {
    const tokens = tokenizeLine('  condition: sel_1 and not flt_1', 'yaml');
    expect(tokens.some((t) => t.cls === 'tok-key' && t.text === 'condition')).toBe(true);
  });
});
