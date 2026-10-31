/**
 * Deterministic detection-template engine.
 *
 * This is how the application answers a query when no language model is
 * available — on a static host such as GitHub Pages, or when the backend has
 * no `HF_TOKEN`. It is NOT a language model and is never presented as one.
 *
 * Each template is a hand-written detection-engineering pattern by a human
 * author. The engine scores the sanitised requirement against the template
 * catalogue, adapts the best matches to the telemetry the user selected, and
 * emits the same `DetectionSpec` the model layer would produce. Everything
 * downstream — schema validation, all seven adapters, mapping resolution and
 * the structural checks — is identical.
 *
 * The honest trade-off, stated in the UI and in every export: templates give
 * real, relevant, reviewable detection logic for common use cases, but they
 * cannot reason about a novel requirement the way a model can. Where the
 * requirement does not match a template well, the engine says so rather than
 * returning something that merely looks plausible.
 */

import type { TelemetryFamily } from '../catalog.js';

export interface TemplateContext {
  /** Sanitised requirement text, lowercased for matching. */
  readonly needle: string;
  /** Telemetry family the detection should target. */
  readonly telemetry: TelemetryFamily;
  /** Allowlisted vendor id. */
  readonly vendorId: string;
  /** Allowlisted log source ids backing this telemetry. */
  readonly logSourceIds: readonly string[];
}

export interface DetectionTemplate {
  readonly id: string;
  readonly title: string;
  /** Lowercase match terms. Multi-word phrases score higher than single words. */
  readonly keywords: readonly string[];
  /**
   * A requirement, phrased as a user would phrase it, that this template is
   * the right answer to. Tests assert it passes the guardrails and ranks first,
   * which proves every template stays reachable; the UI offers them as
   * suggestions so visitors can see what the catalogue covers.
   */
  readonly example: string;
  /** Telemetry families this pattern is valid for. The first is the default. */
  readonly telemetry: readonly TelemetryFamily[];
  /**
   * Build the specification. Returns a plain object that the caller validates
   * with `DetectionSpecSchema`, so a malformed template fails loudly in tests
   * rather than reaching a user.
   */
  build(ctx: TemplateContext): Record<string, unknown>;
}

export interface TemplateMatch {
  readonly template: DetectionTemplate;
  readonly score: number;
  readonly matchedTerms: readonly string[];
}
