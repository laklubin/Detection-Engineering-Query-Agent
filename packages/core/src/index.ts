/** Public surface of @detectionforge/core. */

export * from './constants.js';
export * from './catalog.js';
export * from './schemas.js';
export * from './sanitize.js';
export * from './guardrails.js';
export * from './export.js';
export { resolveField, resolveFields, LOGICAL_FIELDS, isKnownLogicalField, describeLogicalField } from './mappings/fields.js';
export type { ResolvedField, MappingStatus } from './mappings/fields.js';
export { sourceScope, scopeNote } from './mappings/sources.js';
export type { SourceScope, SigmaLogSource } from './mappings/sources.js';
export { ADAPTERS, buildAllPlatforms } from './adapters/index.js';
export type { SiemAdapter, AdapterOptions } from './adapters/types.js';
export { validateStructure, checkBalanced, checkPlaceholders, checkNoExecution, checkPlatformShape } from './validate/syntax.js';
export type { StructuralIssue } from './validate/syntax.js';
export { buildSystemPrompt, buildUserPrompt, PROMPT_VERSION } from './llm/prompt.js';
export {
  createChatCompletion,
  extractJsonObject,
  InferenceError,
} from './llm/client.js';
export type { ChatMessage, ClientDeps, FetchLike, HuggingFaceConfig, InferenceResult } from './llm/client.js';
export { generateDetections, GenerationError, inferTelemetryHints } from './llm/generate.js';
export type { GenerationConfig, GenerationDeps, GenerationOutcome } from './llm/generate.js';
export { DEMO_MODEL_RESPONSE, DEMO_CLARIFICATION_RESPONSE } from './demo/fixtures.js';
