/**
 * Structured logging with mandatory secret redaction.
 *
 * Raw prompt content is never logged: only lengths, counts and classification
 * labels. Every string field passes through the core redactor as a backstop so
 * an unexpected upstream message cannot carry a credential into the log sink.
 */

import { redactForLogging } from '@detectionforge/core';

export type LogLevel = 'info' | 'warn' | 'error';

export interface LogFields {
  readonly [key: string]: string | number | boolean | null | undefined;
}

function sanitiseFields(fields: LogFields): Record<string, string | number | boolean | null> {
  const out: Record<string, string | number | boolean | null> = {};
  for (const [key, value] of Object.entries(fields)) {
    if (value === undefined) continue;
    out[key] = typeof value === 'string' ? redactForLogging(value) : value;
  }
  return out;
}

export function log(level: LogLevel, event: string, fields: LogFields = {}): void {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    event,
    ...sanitiseFields(fields),
  });
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}
