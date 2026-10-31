/**
 * Minimal, dependency-free tokeniser used for syntax highlighting.
 *
 * SECURITY: this produces an array of {text, className} tokens that the UI
 * renders as React text children. No HTML string is ever constructed and
 * `dangerouslySetInnerHTML` is never used, so query text cannot inject markup.
 */

export type TokenClass =
  | 'tok-comment'
  | 'tok-string'
  | 'tok-number'
  | 'tok-keyword'
  | 'tok-command'
  | 'tok-field'
  | 'tok-op'
  | 'tok-key'
  | 'tok-warn'
  | '';

export interface Token {
  readonly text: string;
  readonly cls: TokenClass;
}

export type HighlightLanguage = 'spl' | 'kql' | 'aql' | 'eql' | 'esql' | 'yaml' | 'generic';

interface Rule {
  readonly re: RegExp;
  readonly cls: TokenClass;
}

const MAPPING_WARN = String.raw`<<[A-Z_]+(?::[^>]*)?>>`;

const COMMON: Rule[] = [
  { re: new RegExp(MAPPING_WARN), cls: 'tok-warn' },
  { re: /^"(?:[^"\\\n]|\\.)*"/, cls: 'tok-string' },
  { re: /^'(?:[^'\\\n]|\\.)*'/, cls: 'tok-string' },
  { re: /^\b\d+(?:\.\d+)?\b/, cls: 'tok-number' },
];

const KEYWORDS: Readonly<Record<HighlightLanguage, RegExp | null>> = {
  spl: /^\b(?:index|sourcetype|source|host|search|where|eval|stats|tstats|bin|table|values|count|dc|min|max|case|isnotnull|isnull|match|in|strftime|coalesce|if|true|by|AS|as|NOT|AND|OR)\b/,
  kql: /^\b(?:let|where|summarize|project|extend|join|union|kind|inner|leftouter|bin|ago|count|dcount|make_set|min|max|between|and|or|not|in|isnotempty|isempty|contains|startswith|endswith|matches|regex|datetime_diff|abs|has)\b/,
  aql: /^\b(?:SELECT|FROM|WHERE|GROUP|BY|HAVING|ORDER|LAST|MINUTES|HOURS|DAYS|AND|OR|NOT|IN|LIKE|ILIKE|MATCHES|IMATCHES|IS|NULL|COUNT|DISTINCT|AS|DESC|ASC|QIDNAME|DATEFORMAT|LOGSOURCENAME|PROTOCOLNAME|events|flows)\b/,
  eql: /^\b(?:sequence|by|with|maxspan|where|and|or|not|in|like|regex|any|process|network|file|registry|authentication|dns|null|FROM|WHERE|STATS|EVAL|SORT|LIMIT|BY|CASE|COUNT|COUNT_DISTINCT|MIN|MAX|LIKE|RLIKE|IS|AND|OR|NOT|DESC|TO_LOWER)\b/,
  esql: /^\b(?:FROM|WHERE|STATS|EVAL|SORT|LIMIT|BY|CASE|COUNT|COUNT_DISTINCT|MIN|MAX|LIKE|RLIKE|IS|NULL|AND|OR|NOT|DESC|ASC)\b/,
  yaml: null,
  generic: /^\b(?:index|AND|OR|NOT|IN|CONTAINS|CONTAIN|STARTS|ENDS|WITH|REGEXP|IS|NULL|eventType|rg_functionality)\b/,
};

const COMMENT: Readonly<Record<HighlightLanguage, RegExp | null>> = {
  spl: /^```[^\n]*```|^```[^\n]*/,
  kql: /^\/\/[^\n]*/,
  aql: /^--[^\n]*/,
  eql: /^\/\/[^\n]*/,
  esql: /^\/\/[^\n]*/,
  yaml: /^#[^\n]*/,
  generic: /^(?:\/\/|#)[^\n]*/,
};

const OPERATOR = /^(?:<=|>=|==|!=|=~|!~|\|>|[|=<>!+\-*/,;:()[\]{}])/;

/** Tokenise one line of code. Always returns tokens covering the whole input. */
export function tokenizeLine(line: string, language: HighlightLanguage): Token[] {
  const tokens: Token[] = [];
  let rest = line;
  const commentRule = COMMENT[language];
  const keywordRule = KEYWORDS[language];

  if (commentRule) {
    const match = commentRule.exec(rest);
    if (match && match.index === 0) {
      return [{ text: match[0], cls: 'tok-comment' }];
    }
  }

  // YAML: highlight `key:` prefixes and list markers.
  if (language === 'yaml') {
    const keyMatch = /^(\s*)(-\s+)?([A-Za-z0-9_.|-]+)(:)(\s|$)/.exec(rest);
    if (keyMatch) {
      const [full, indent, dash, key, colon, trail] = keyMatch as unknown as string[];
      if (indent) tokens.push({ text: indent, cls: '' });
      if (dash) tokens.push({ text: dash, cls: 'tok-op' });
      tokens.push({ text: key as string, cls: 'tok-key' });
      tokens.push({ text: colon as string, cls: 'tok-op' });
      if (trail) tokens.push({ text: trail, cls: '' });
      rest = rest.slice((full as string).length);
    }
  }

  let guard = 0;
  while (rest.length > 0 && guard < 4000) {
    guard += 1;

    const whitespace = /^\s+/.exec(rest);
    if (whitespace) {
      tokens.push({ text: whitespace[0], cls: '' });
      rest = rest.slice(whitespace[0].length);
      continue;
    }

    let matched = false;
    for (const rule of COMMON) {
      const m = rule.re.exec(rest);
      if (m && m.index === 0) {
        tokens.push({ text: m[0], cls: rule.cls });
        rest = rest.slice(m[0].length);
        matched = true;
        break;
      }
    }
    if (matched) continue;

    if (keywordRule) {
      const m = keywordRule.exec(rest);
      if (m && m.index === 0) {
        tokens.push({ text: m[0], cls: /^[A-Z]/.test(m[0]) && language === 'esql' ? 'tok-command' : 'tok-keyword' });
        rest = rest.slice(m[0].length);
        continue;
      }
    }

    const op = OPERATOR.exec(rest);
    if (op) {
      tokens.push({ text: op[0], cls: 'tok-op' });
      rest = rest.slice(op[0].length);
      continue;
    }

    const word = /^[A-Za-z_@$][A-Za-z0-9_.@$-]*/.exec(rest);
    if (word) {
      tokens.push({ text: word[0], cls: 'tok-field' });
      rest = rest.slice(word[0].length);
      continue;
    }

    tokens.push({ text: rest[0] as string, cls: '' });
    rest = rest.slice(1);
  }

  if (rest.length > 0) tokens.push({ text: rest, cls: '' });
  return tokens;
}

export function tokenize(code: string, language: HighlightLanguage): Token[][] {
  return code.split('\n').map((line) => tokenizeLine(line, language));
}
