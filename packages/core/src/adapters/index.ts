import { PLATFORM_IDS, type PlatformId } from '../constants.js';
import type { DetectionSpec, PlatformQuery } from '../schemas.js';
import type { AdapterOptions, SiemAdapter } from './types.js';
import { splunkAdapter } from './splunk.js';
import { sentinelAdapter } from './sentinel.js';
import { qradarAdapter } from './qradar.js';
import { elasticAdapter } from './elastic.js';
import { securonixAdapter } from './securonix.js';
import { fortisiemAdapter } from './fortisiem.js';
import { sigmaAdapter } from './sigma.js';

export const ADAPTERS: Readonly<Record<PlatformId, SiemAdapter>> = {
  splunk: splunkAdapter,
  sentinel: sentinelAdapter,
  qradar: qradarAdapter,
  elastic: elasticAdapter,
  securonix: securonixAdapter,
  fortisiem: fortisiemAdapter,
  sigma: sigmaAdapter,
};

/** Build every supported platform output for one detection specification. */
export function buildAllPlatforms(spec: DetectionSpec, options?: AdapterOptions): PlatformQuery[] {
  return PLATFORM_IDS.map((id) => ADAPTERS[id].build(spec, options));
}

export type { AdapterOptions, SiemAdapter } from './types.js';
export { splunkAdapter, sentinelAdapter, qradarAdapter, elasticAdapter, securonixAdapter, fortisiemAdapter, sigmaAdapter };
