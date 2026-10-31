/**
 * Route constants.
 *
 * Kept out of the Worker entry module on purpose: workerd requires the entry
 * module's exports to be handlers (or other recognised bindings), so a plain
 * named constant exported from `src/index.ts` prevents the Worker from booting.
 */
export const API_PREFIX = '/api/v1';

export const ROUTES = {
  health: `${API_PREFIX}/health`,
  catalog: `${API_PREFIX}/catalog`,
  session: `${API_PREFIX}/session`,
  generate: `${API_PREFIX}/generate`,
} as const;
