import { useMemo, type ReactNode } from 'react';
import { tokenize, type HighlightLanguage } from '../lib/highlight.js';

/**
 * Renders query text with syntax highlighting.
 *
 * Tokens are emitted as React text children inside <span> elements, so every
 * character is escaped by React. The component never uses
 * dangerouslySetInnerHTML, which keeps model-derived text inert.
 */
export function CodeBlock({
  code,
  language,
  maxHeight = '28rem',
}: {
  code: string;
  language: HighlightLanguage;
  maxHeight?: string;
}): ReactNode {
  const lines = useMemo(() => tokenize(code, language), [code, language]);

  return (
    <div
      className="overflow-auto rounded-lg border border-[var(--color-forge-border)] bg-[#060a12]"
      style={{ maxHeight }}
    >
      <pre className="dfai-code m-0 p-3">
        <code>
          {lines.map((tokens, lineIndex) => (
            <span key={lineIndex} className="grid grid-cols-[2.5rem_1fr]">
              <span aria-hidden="true" className="select-none pr-3 text-right text-[var(--color-forge-muted)]/40">
                {lineIndex + 1}
              </span>
              <span>
                {tokens.map((token, tokenIndex) => (
                  <span key={tokenIndex} className={token.cls}>
                    {token.text}
                  </span>
                ))}
                {'\n'}
              </span>
            </span>
          ))}
        </code>
      </pre>
    </div>
  );
}
