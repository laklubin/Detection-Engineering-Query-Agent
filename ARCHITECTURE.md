# Architecture

## Design principle

The model is a **reasoning component, not a text generator for queries**.

A language model is good at translating an informal detection requirement into structured
detection logic. It is unreliable at emitting exact vendor syntax, and if it emitted query
text directly then its output would flow straight into something the user copies into a
production SIEM — an injection channel and a correctness risk at once.

So the model produces a vendor-neutral **detection specification**, and seven
deterministic adapters render it into query text. Three consequences follow:

1. **Correctness is testable.** Adapter output is a pure function of the specification,
   so it can be unit tested exhaustively. The same specification always produces the same
   query.
2. **Mappings cannot be hallucinated.** Vendor field names come from a registry, never
   from the model. An undocumented mapping produces an explicit placeholder.
3. **The model has no path into query text.** It cannot smuggle arbitrary strings into
   something a user will paste into a SIEM.

## Component map

```
┌────────────────────────────────── browser ──────────────────────────────────┐
│  packages/web — React 19 + TypeScript + Vite + Tailwind                     │
│  · requirement input, vendor select, searchable log-source combobox          │
│  · results with syntax highlighting, copy / download, status + notifications │
│  · session token held IN MEMORY ONLY                                         │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │ HTTPS, Authorization + X-DFAI-CSRF headers
                                │ CORS: exact-match origin allowlist
┌───────────────────────────────▼──────────────────────────────────────────────┐
│  packages/worker — Cloudflare Worker (the only holder of HF_TOKEN)           │
│  security.ts  CORS allowlist, CSP, security headers                          │
│  auth.ts      HMAC session tokens, API keys, constant-time comparison        │
│  ratelimit.ts sliding window + daily quota (KV-backed when bound)            │
│  log.ts       structured logging with mandatory redaction                    │
│  index.ts     routing, body limits, error mapping                            │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │ in-process call
┌───────────────────────────────▼──────────────────────────────────────────────┐
│  packages/core — pure, platform-agnostic, no I/O except the HF client        │
│                                                                              │
│  sanitize.ts   deterministic sanitisation pipeline                           │
│  guardrails.ts scope classification (pre-inference) + output safety           │
│  schemas.ts    Zod schemas for every trust boundary + the detection IR        │
│  catalog.ts    vendor / log-source / telemetry allowlists                     │
│  mappings/     field registry + telemetry source scopes                       │
│  llm/prompt.ts versioned system prompt (trusted constants only)               │
│  llm/client.ts HF Inference Providers client: timeout, retries, fallbacks     │
│  llm/generate.ts the orchestrator                                             │
│  adapters/     splunk · sentinel · qradar · elastic · securonix · fortisiem   │
│                · sigma                                                        │
│  validate/     structural + platform syntax checks                            │
│  export.ts     Markdown / JSON / per-query file rendering                     │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │ HTTPS, Bearer HF_TOKEN
                  ┌─────────────▼─────────────┐
                  │ Hugging Face Inference    │
                  │ Providers (OpenAI-compat) │
                  └───────────────────────────┘
```

## Request lifecycle

```
1  POST /api/v1/generate
2  ├─ CORS origin allowlist ................... 403 forbidden_origin
3  ├─ Content-Type + body size ................ 400 / 413
4  ├─ authenticate (session token or API key) . 401 unauthorized
5  ├─ sliding-window rate limit ............... 429 rate_limited
6  ├─ daily quota ............................. 429 quota_exceeded
7  ├─ GenerateRequestSchema (Zod, .strict()) .. 400 bad_request
8  ├─ sanitiseRequirement() ................... 422 unsafe_input / 413
9  ├─ evaluateGuardrails() .................... 422 off_topic   ← no model call
10 ├─ identify vendor + log source
11 │   └─ unknown telemetry? ................. 200 + clarifying question, no model call
12 ├─ buildSystemPrompt() + buildUserPrompt()
13 ├─ createChatCompletion() ................. 401/503/504/502 on failure
14 ├─ evaluateModelOutputSafety() ............ 502 invalid_model_output
15 ├─ extractJsonObject() + JSON.parse ....... 502 invalid_model_output
16 ├─ ModelResponseSchema.safeParse() ........ 502 invalid_model_output
17 ├─ dedupe + cap at 2 use cases
18 ├─ buildAllPlatforms() × 7 adapters
19 ├─ validateStructure() per query
20 └─ 200 GenerateResponse
```

Steps 2–9 are all cheaper than an inference call and all run first: a rejected or
throttled request never costs credits.

## The detection IR

The contract between the model and the adapters.

```ts
DetectionSpec {
  slug, name, objective, attackScenario
  vendorId, logSourceIds[]           // allowlisted ids only
  requiredEventFields[]              // logical field names only
  mappingAssumptions[]
  mitre[]                            // validated TA####/T####(.###)
  stages[1..4] {
    id, name, description
    telemetry                        // telemetry family — enables cross-source correlation
    conditionLogic: all | any
    conditions[1..16] {
      field                          // logical field, strict grammar
      operator                       // 18 operators
      value?, caseSensitive?, rationale?
    }
  }
  correlation {
    type: single_event | threshold | sequence
    groupBy[], timeWindowSeconds
    eventThreshold?, distinctThreshold?, thresholdField?
    ordered, description
  }
  severity, falsePositives[], tuning[], validationRecommendations[]
}
```

Cross-field invariants are enforced by Zod refinements: a sequence needs ≥ 2 stages, a
single-event correlation needs exactly 1, a threshold needs a threshold, `distinctThreshold`
needs `thresholdField`, valueless operators must omit their value, list operators require
an array, comparison operators require a number, and regex values must compile.

## Mapping resolution

```
resolveField(logical, platform, telemetry)
  → overrides[telemetry][platform]      // most specific
  → defaults[platform]                  // family-independent
  → { physical: null, status: 'mapping_required', note }
```

The telemetry dimension matters: `process.command_line` is `CommandLine` on Windows
Security auditing, `ProcessCommandLine` on a Defender XDR device table, and has no
normalised AQL column at all. A two-dimensional registry models that honestly; a flat
one would force a wrong answer.

`sourceScope(telemetry)` does the same for search scope: Splunk index/sourcetype,
Sentinel table, QRadar log-source type, Elastic index pattern, Securonix resource group,
FortiSIEM event type, Sigma `logsource` block.

## Adapters

Each adapter is `(DetectionSpec, AdapterOptions) => PlatformQuery` — pure, no I/O.

The interesting work is in what each platform *cannot* do:

| Platform | Sequence support | How the adapter handles it |
| --- | --- | --- |
| Splunk | No sequence primitive | `eval … case()` stage tagging, `stats` with per-stage `min(eval(if(…)))`, then explicit ordering predicates |
| Sentinel | No sequence operator | `let`-bound stages joined on the pivot entities with a `between` window |
| QRadar | None — AQL is a search language | Per-stage hunting searches plus Rule Wizard guidance; never fabricates rule syntax |
| Elastic | Native | `sequence by … with maxspan`, plus an ES\|QL aggregation variant |
| Securonix | Policy-side only | Spotter searches per stage plus violation-chain guidance |
| FortiSIEM | Rule sub-patterns | One filter per sub-pattern plus a structural rule outline |
| Sigma | v2 correlations | Multi-document stream: one rule per stage plus `temporal_ordered` / `event_count` / `value_count` |

Unrepresentable constructs are marked, not faked. Securonix has no portable regex
operator, so a regex predicate emits `<<REGEX_UNSUPPORTED>>`, raises a validation
message, and the status drops below `Syntax Validated`.

### Status derivation

```
query === null                      → unsupported
mapping gaps present                → mapping_required
structural errors present           → not_validated
standalone query not deployable     → not_validated  (+ configuration guidance)
otherwise                           → validated_syntax
```

`requiresPlatformConfiguration` tracks whether a *standalone query* is the deployable
artefact. Splunk, Sentinel, Elastic and Sigma can reach `validated_syntax`; QRadar,
Securonix and FortiSIEM cannot, because the query alone is not the detection.

## Validation

Structural checks are platform-aware and run over every generated query: unresolved
mapping placeholders, unsupported-construct markers, balanced brackets and string
literals outside comments, absence of side-effecting commands, and platform shape
(SPL base search, KQL tabular operator, AQL `SELECT … FROM … LAST`, EQL/ES\|QL bodies,
Spotter index scope, FortiSIEM filter expression, Sigma detection or correlation block).

Sigma additionally round-trips: emitted YAML is re-parsed, required keys are checked, and
every identifier referenced by a `condition` must be a defined selection.

CI goes one step further for Sigma: `scripts/export-sigma-rules.mjs` writes the
generated rules to disk and `scripts/validate-sigma.py` parses them with **pySigma**,
the reference implementation, resolving every condition against the selections it
references. That is third-party validation of the emitted YAML, not a self-check.

None of this executes a query. The taxonomy is deliberately `validated_syntax`, not
`validated`.

## Frontend

React 19 + Vite + Tailwind 4, no UI component library.

Syntax highlighting is a ~200-line tokeniser that returns `{text, className}` objects
rendered as React text children. A third-party highlighter would have meant either
`dangerouslySetInnerHTML` or a much larger dependency surface for untrusted text; the
tokeniser is round-trip tested to be lossless, including on markup payloads.

When no backend is reachable the UI offers an explicitly-labelled local demo that runs
the identical core pipeline in the browser against the synthetic fixture. The core
package contains no secrets, so this is safe — and it keeps a GitHub Pages deployment
useful before the Worker exists.

## Extension points

| Goal | Change |
| --- | --- |
| New SIEM platform | Add an adapter in `packages/core/src/adapters/`, register it, add mappings and tests |
| New log source | Add to `catalog.ts`, add a scope in `mappings/sources.ts` |
| New field | Add to `mappings/fields.ts` with per-platform entries and notes |
| Different model | Set `HF_MODEL` / `HF_MODEL_FALLBACKS`; no code change |
| Different backend host | Reimplement the thin Worker layer; `core` has no platform coupling |
| Durable rate limits | Bind a KV namespace as `RATE_LIMIT_KV` |

Run `npm run docs` after changing mappings or adapters — `docs/FIELD-MAPPINGS.md` and
`docs/SAMPLE-QUERIES.md` are generated from the code.
