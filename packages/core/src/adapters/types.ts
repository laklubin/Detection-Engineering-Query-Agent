import type { PlatformId } from '../constants.js';
import type { DetectionSpec, PlatformQuery } from '../schemas.js';

export interface AdapterOptions {
  /** ISO date (YYYY-MM-DD) stamped into rule metadata. Injectable for tests. */
  readonly generatedDate?: string;
}

/**
 * One adapter per SIEM platform. Adapters are pure functions over the
 * normalised detection specification. They never see raw user input or raw
 * model text, and they never execute anything.
 */
export interface SiemAdapter {
  readonly platform: PlatformId;
  build(spec: DetectionSpec, options?: AdapterOptions): PlatformQuery;
}
