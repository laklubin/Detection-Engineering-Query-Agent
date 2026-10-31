/**
 * Per-subject rate limiting and daily cost quota.
 *
 * Two independent controls:
 *   - a sliding window limiter that caps burst usage
 *   - a daily quota that caps inference spend per session
 *
 * When a KV namespace is bound the counters are durable across isolates and
 * colos. Without it the limiter degrades to per-isolate in-memory counters,
 * which are best-effort; the health endpoint reports which mode is active so
 * the deployment posture is never misrepresented.
 */

export interface RateDecision {
  readonly allowed: boolean;
  readonly remaining: number;
  readonly retryAfterSeconds: number;
  readonly limit: number;
}

export interface QuotaDecision {
  readonly allowed: boolean;
  readonly used: number;
  readonly limit: number;
  readonly resetsAt: string;
}

export interface LimiterOptions {
  readonly requests: number;
  readonly windowSeconds: number;
  readonly dailyQuota: number;
}

interface WindowRecord {
  count: number;
  resetAt: number;
}

interface QuotaRecord {
  count: number;
  day: string;
}

/** Process-local fallback store. Bounded so it cannot grow without limit. */
const MAX_LOCAL_KEYS = 5000;
const localWindows = new Map<string, WindowRecord>();
const localQuotas = new Map<string, QuotaRecord>();

function pruneLocal<T>(store: Map<string, T>): void {
  if (store.size <= MAX_LOCAL_KEYS) return;
  const excess = store.size - MAX_LOCAL_KEYS;
  let removed = 0;
  for (const key of store.keys()) {
    store.delete(key);
    removed += 1;
    if (removed >= excess) break;
  }
}

function dayKey(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

function endOfDayIso(now: number): string {
  const date = new Date(now);
  date.setUTCHours(23, 59, 59, 999);
  return date.toISOString();
}

export class Limiter {
  constructor(
    private readonly options: LimiterOptions,
    private readonly kv?: KVNamespace | undefined,
  ) {}

  get durable(): boolean {
    return this.kv !== undefined;
  }

  /** Consume one slot in the sliding window. */
  async checkRate(subject: string, now = Date.now()): Promise<RateDecision> {
    const limit = this.options.requests;
    const windowMs = this.options.windowSeconds * 1000;
    const key = `rate:${subject}`;

    if (this.kv) {
      const raw = await this.kv.get(key, 'json');
      const record = (raw as WindowRecord | null) ?? { count: 0, resetAt: now + windowMs };
      const active = record.resetAt > now ? record : { count: 0, resetAt: now + windowMs };
      if (active.count >= limit) {
        return {
          allowed: false,
          remaining: 0,
          retryAfterSeconds: Math.max(1, Math.ceil((active.resetAt - now) / 1000)),
          limit,
        };
      }
      active.count += 1;
      await this.kv.put(key, JSON.stringify(active), {
        expirationTtl: Math.max(60, Math.ceil((active.resetAt - now) / 1000) + 10),
      });
      return { allowed: true, remaining: limit - active.count, retryAfterSeconds: 0, limit };
    }

    const existing = localWindows.get(key);
    const record = existing && existing.resetAt > now ? existing : { count: 0, resetAt: now + windowMs };
    if (record.count >= limit) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: Math.max(1, Math.ceil((record.resetAt - now) / 1000)),
        limit,
      };
    }
    record.count += 1;
    localWindows.set(key, record);
    pruneLocal(localWindows);
    return { allowed: true, remaining: limit - record.count, retryAfterSeconds: 0, limit };
  }

  /** Consume one unit of the daily inference quota. */
  async checkQuota(subject: string, now = Date.now()): Promise<QuotaDecision> {
    const limit = this.options.dailyQuota;
    const day = dayKey(now);
    const key = `quota:${day}:${subject}`;

    if (this.kv) {
      const raw = await this.kv.get(key, 'json');
      const record = (raw as QuotaRecord | null) ?? { count: 0, day };
      if (record.count >= limit) {
        return { allowed: false, used: record.count, limit, resetsAt: endOfDayIso(now) };
      }
      record.count += 1;
      record.day = day;
      await this.kv.put(key, JSON.stringify(record), { expirationTtl: 172_800 });
      return { allowed: true, used: record.count, limit, resetsAt: endOfDayIso(now) };
    }

    const existing = localQuotas.get(key);
    const record = existing && existing.day === day ? existing : { count: 0, day };
    if (record.count >= limit) {
      return { allowed: false, used: record.count, limit, resetsAt: endOfDayIso(now) };
    }
    record.count += 1;
    localQuotas.set(key, record);
    pruneLocal(localQuotas);
    return { allowed: true, used: record.count, limit, resetsAt: endOfDayIso(now) };
  }
}

/** Test helper: clear the in-memory fallback counters. */
export function resetLocalCounters(): void {
  localWindows.clear();
  localQuotas.clear();
}
