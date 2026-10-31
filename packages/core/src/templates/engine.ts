/**
 * Template matching and offline detection generation.
 *
 * Scores the sanitised requirement against the template catalogue, adapts the
 * best matches to the selected telemetry, and emits a `ModelResponse` in
 * exactly the shape the language-model layer produces — so everything
 * downstream (schema validation, the seven adapters, mapping resolution,
 * structural checks, the two-use-case cap) is identical.
 *
 * When nothing matches well enough, the engine returns `needs_clarification`
 * rather than the closest template. Returning a confident-looking detection
 * for a requirement it did not understand would be the one genuinely harmful
 * failure mode here.
 */

import { MAX_USE_CASES_PER_REQUEST } from '../constants.js';
import { findLogSource, LOG_SOURCES, type TelemetryFamily } from '../catalog.js';
import { DetectionSpecSchema, type DetectionSpec, type ModelResponse } from '../schemas.js';
import { TEMPLATES } from './catalogue.js';
import type { DetectionTemplate, TemplateContext, TemplateMatch } from './types.js';

/** Minimum score for a template to be considered a real match. */
export const MATCH_THRESHOLD = 4;

const SCORE_PHRASE = 5;
const SCORE_DISTINCTIVE_WORD = 4;
const SCORE_COMMON_WORD = 2;
const SCORE_TELEMETRY_BONUS = 3;

/**
 * How many templates claim each single-word keyword.
 *
 * A word claimed by exactly one template is distinctive — "powershell",
 * "lsass", "ransomware" — and naming it is on its own a clear statement of
 * intent. A word several templates share, such as "beacon" or "log", is weak
 * evidence and must be corroborated. Deriving this from the catalogue rather
 * than hand-labelling it means the weighting stays correct as templates are
 * added.
 */
const WORD_OWNERS: ReadonlyMap<string, number> = (() => {
  const counts = new Map<string, number>();
  for (const template of TEMPLATES) {
    const seen = new Set<string>();
    for (const keyword of template.keywords) {
      const parts = keyword.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 0);
      if (parts.length !== 1) continue;
      seen.add(parts[0] as string);
    }
    for (const word of seen) counts.set(word, (counts.get(word) ?? 0) + 1);
  }
  return counts;
})();

function singleWordScore(word: string): number {
  const distinctive = word.length >= 5 && (WORD_OWNERS.get(word) ?? 0) === 1;
  return distinctive ? SCORE_DISTINCTIVE_WORD : SCORE_COMMON_WORD;
}

const WORD_BOUNDARY = /[^a-z0-9]+/g;

/** Suffixes that turn a keyword into an ordinary inflected form of itself. */
const INFLECTIONS: ReadonlySet<string> = new Set([
  's', 'es', 'd', 'ed', 'ing', 'ion', 'ions', 'ment', 'ments',
]);

/** Filler words a user naturally inserts between the words of a concept. */
const SKIPPABLE = new Set(['the', 'a', 'an', 'of', 'to', 'in', 'on', 'for', 'and', 'our', 'their', 'its', 'any']);

function words(text: string): string[] {
  return text.toLowerCase().replace(WORD_BOUNDARY, ' ').trim().split(' ').filter((w) => w.length > 0);
}

/**
 * Does the haystack contain this term, allowing ordinary English inflection
 * and filler words?
 *
 * "disable defender" matches "someone disabled defender", and
 * "clear event log" matches "cleared the event log". A haystack word satisfies
 * a term word when it starts with it, which covers -s, -ed, -ing and -ment
 * without a stemmer. The prefix rule only applies from four characters so that
 * short words cannot match loosely.
 */
function containsTerm(haystack: readonly string[], term: readonly string[]): boolean {
  if (term.length === 0) return false;

  const wordMatches = (candidate: string, wanted: string): boolean => {
    if (candidate === wanted) return true;
    if (wanted.length < 4 || !candidate.startsWith(wanted)) return false;
    // Only real English inflections count. An arbitrary prefix rule would let
    // "spray" match "sprayer" and return a password-spray detection for a
    // requirement about irrigation equipment.
    return INFLECTIONS.has(candidate.slice(wanted.length));
  };

  for (let start = 0; start + term.length <= haystack.length + 2; start += 1) {
    let cursor = start;
    let termIndex = 0;
    let skips = 0;

    while (termIndex < term.length && cursor < haystack.length) {
      const candidate = haystack[cursor] as string;
      if (wordMatches(candidate, term[termIndex] as string)) {
        termIndex += 1;
        cursor += 1;
        continue;
      }
      // Allow a bounded number of filler words between the term's words.
      if (termIndex > 0 && skips < 2 && SKIPPABLE.has(candidate)) {
        skips += 1;
        cursor += 1;
        continue;
      }
      break;
    }
    if (termIndex === term.length) return true;
  }
  return false;
}

/**
 * Score one template against the requirement.
 *
 * Multi-word phrases score higher than single words because they are far less
 * likely to match incidentally: "password spray" is strong evidence, "spray"
 * on its own is not.
 */
export function scoreTemplate(
  template: DetectionTemplate,
  needle: string,
  telemetry: TelemetryFamily | null,
): TemplateMatch {
  const haystack = words(needle);
  const matchedTerms: string[] = [];
  let score = 0;

  for (const keyword of template.keywords) {
    const term = words(keyword);
    if (term.length === 0) continue;
    if (!containsTerm(haystack, term)) continue;
    matchedTerms.push(keyword);
    score += term.length >= 2 ? SCORE_PHRASE : singleWordScore(term[0] as string);
  }

  // A telemetry match is meaningful evidence, but never enough on its own:
  // otherwise selecting a log source would return an arbitrary template.
  if (telemetry !== null && matchedTerms.length > 0 && template.telemetry.includes(telemetry)) {
    score += SCORE_TELEMETRY_BONUS;
  }

  return { template, score, matchedTerms };
}

export function rankTemplates(
  requirement: string,
  telemetry: TelemetryFamily | null,
): TemplateMatch[] {
  return TEMPLATES.map((template) => scoreTemplate(template, requirement, telemetry))
    .filter((match) => match.score >= MATCH_THRESHOLD)
    // Deterministic: score descending, then catalogue order.
    .sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return TEMPLATES.indexOf(a.template) - TEMPLATES.indexOf(b.template);
    });
}

export interface OfflineGenerationInput {
  /** Sanitised requirement text. */
  readonly requirement: string;
  readonly vendorId: string | undefined;
  readonly logSourceId: string | undefined;
  readonly maxUseCases?: number;
}

function contextFor(
  template: DetectionTemplate,
  input: OfflineGenerationInput,
  telemetry: TelemetryFamily | null,
): TemplateContext {
  const chosen = telemetry !== null && template.telemetry.includes(telemetry)
    ? telemetry
    : (template.telemetry[0] as TelemetryFamily);

  // Prefer the log source the user selected when it matches the telemetry the
  // template will actually use; otherwise pick a documented source for it.
  const selected = input.logSourceId ? findLogSource(input.logSourceId) : undefined;
  const logSourceIds =
    selected && selected.telemetry === chosen
      ? [selected.id]
      : LOG_SOURCES.filter((s) => s.telemetry === chosen)
          .slice(0, 2)
          .map((s) => s.id);

  return {
    needle: input.requirement.toLowerCase(),
    telemetry: chosen,
    vendorId:
      selected && (!input.vendorId || input.vendorId === 'multi_vendor')
        ? selected.vendorId
        : (input.vendorId && input.vendorId !== 'multi_vendor'
            ? input.vendorId
            : (LOG_SOURCES.find((s) => s.id === logSourceIds[0])?.vendorId ?? 'multi_vendor')),
    logSourceIds: logSourceIds.length > 0 ? logSourceIds : ['windows_security_events'],
  };
}

export class TemplateValidationError extends Error {
  constructor(templateId: string, issues: string) {
    super(`Template "${templateId}" produced an invalid specification: ${issues}`);
    this.name = 'TemplateValidationError';
  }
}

/** Build and validate the specification for one template. */
export function buildSpec(
  template: DetectionTemplate,
  input: OfflineGenerationInput,
  telemetry: TelemetryFamily | null,
): DetectionSpec {
  const raw = template.build(contextFor(template, input, telemetry));
  const parsed = DetectionSpecSchema.safeParse(raw);
  if (!parsed.success) {
    throw new TemplateValidationError(
      template.id,
      parsed.error.issues.map((i) => `${i.path.join('.') || 'root'}: ${i.message}`).join('; '),
    );
  }
  return parsed.data;
}

/**
 * Produce a model-shaped response from the template catalogue.
 *
 * This never contacts a network service and never needs a credential.
 */
export function generateFromTemplates(input: OfflineGenerationInput): ModelResponse {
  const selected = input.logSourceId ? findLogSource(input.logSourceId) : undefined;
  const telemetry = selected?.telemetry ?? null;
  const limit = Math.min(input.maxUseCases ?? MAX_USE_CASES_PER_REQUEST, MAX_USE_CASES_PER_REQUEST);

  const ranked = rankTemplates(input.requirement, telemetry);

  if (ranked.length === 0) {
    return {
      status: 'needs_clarification',
      clarifyingQuestion:
        'No detection template matched that requirement closely enough to answer it honestly. ' +
        'Name the behaviour and the telemetry — for example "failed logons followed by a success in ' +
        'Windows Security Events" or "DNS beaconing in resolver logs".',
      useCases: [],
    };
  }

  const useCases: DetectionSpec[] = [];
  const seen = new Set<string>();
  for (const match of ranked) {
    if (useCases.length >= limit) break;
    const spec = buildSpec(match.template, input, telemetry);
    if (seen.has(spec.slug)) continue;
    seen.add(spec.slug);
    useCases.push(spec);
  }

  return { status: 'ok', useCases };
}

export { TEMPLATES } from './catalogue.js';
export type { DetectionTemplate, TemplateContext, TemplateMatch } from './types.js';
