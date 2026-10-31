# DetectionForge AI

**From Threat Detection Logic to Multi-SIEM Queries**

A web application for detection engineers. Describe a defensive detection requirement in
natural language — or pick a vendor and log source — and get a complete detection
engineering package rendered for **six SIEM platforms plus Sigma**, with explicit field
mappings, honest validation status, false-positive analysis and tuning guidance.

```
Detection requirement
  → validate → guardrails → sanitise → identify vendor/log source
  → structured detection specification → Hugging Face inference
  → schema validation → 7 platform adapters → syntax + mapping checks
  → up to 2 use cases → copy / download
```

---

## What it produces

For every detection use case, all seven formats are generated:

| Platform | Language | Notes |
| --- | --- | --- |
| Splunk Enterprise Security | SPL | Deployable search; ES notable configuration described separately |
| Microsoft Sentinel | KQL | Analytics-rule query; entity mapping described separately |
| IBM QRadar | AQL | Hunting searches + Rule Wizard guidance (AQL has no sequence operator) |
| Elastic Security | EQL **and** ES\|QL | Native `sequence … maxspan` plus an aggregation variant |
| Securonix | Spotter | Hunting searches + policy / violation-chain guidance |
| FortiSIEM | Event search | Per-sub-pattern filters + rule structure outline |
| Sigma | Sigma YAML | Multi-document rules using the v2 correlation specification |

Each use case carries all fourteen required elements: identifier, objective, attack
scenario, required vendor and log sources, required fields with mapping assumptions,
MITRE ATT&CK mapping, detection logic and correlation conditions, time window and
threshold, severity, false positives, tuning and whitelisting, every platform query,
validation and test recommendations, and a per-platform validation status.

See [`docs/SAMPLE-QUERIES.md`](docs/SAMPLE-QUERIES.md) for real generated output.

## Honesty guarantees

These are enforced in code and covered by tests, not just stated:

- **Field mappings are never invented.** Every vendor field comes from a documented
  registry entry ([`docs/FIELD-MAPPINGS.md`](docs/FIELD-MAPPINGS.md)). An undocumented
  combination emits a `<<MAPPING_REQUIRED:field>>` placeholder and marks the output
  **Mapping Required**.
- **"Validated" means syntax only.** A `Syntax Validated` badge means structural checks
  passed *inside this application*. No query has ever been executed against a live SIEM,
  data set or tenant, and the UI and every export say so.
- **Platform limits are stated, not papered over.** Where a platform cannot express a
  detection as a standalone query, the output is marked **Not Validated** and the
  proprietary rule configuration is described instead of being fabricated.
- **Inference failure is never faked.** If Hugging Face is unavailable, out of credits or
  returns schema-invalid output, the request fails with a specific error. No fallback
  content is passed off as model output.
- **Demo mode is labelled.** With no `HF_TOKEN` configured the backend serves a synthetic
  fixture through the identical pipeline, and the response and UI both say it was *not*
  produced by a language model.

## Security posture

- The Hugging Face token lives **only** in the backend Worker environment as `HF_TOKEN`.
  It is never in frontend code, never in a response body, never in a log line, and the
  build pipeline fails if anything credential-shaped reaches a published bundle.
- Guardrails run in backend application logic **before** inference. Rejected requests are
  never forwarded to the model.
- A deterministic sanitisation pipeline normalises Unicode, rejects raw log and binary
  uploads, redacts credentials and personal data, and strips markup before the prompt is
  built. Secrets are redacted before anything leaves the process.
- Model output is treated as untrusted: it is safety-scanned, schema-validated, and can
  only express detection *logic*. Query text is rendered deterministically by the
  adapters, so the model cannot inject arbitrary text into an exported query.
- Generated content is strictly read-only. Nothing deploys a query to a SIEM, and the
  application holds no SIEM credentials.

Full details: [`SECURITY.md`](SECURITY.md). Design: [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Repository layout

```
packages/
  core/     Guardrails, sanitiser, detection IR, field registry,
            7 SIEM adapters, validators, prompt, HF client, orchestrator
  worker/   Cloudflare Worker API: auth, CORS, rate limits, quotas, headers
  web/      React + TypeScript + Vite + Tailwind frontend
scripts/    Doc generation and build-artifact secret scanning
docs/       Generated field mappings and sample queries
.github/    CI, CodeQL, gitleaks, Pages and Worker deployment workflows
```

## Quick start

```bash
npm install
```

```bash
npm run verify
```

`verify` runs typecheck, lint, tests and builds across all packages.

### Run it locally

Start the API (demo mode, no token needed):

```bash
cp .env.example packages/worker/.dev.vars
```

Edit `packages/worker/.dev.vars` — set `SESSION_SIGNING_KEY` to a random value, and
either set a real `HF_TOKEN` for live inference or leave it out for demo mode. Then:

```bash
npm run dev:api
```

In a second terminal, start the frontend:

```bash
VITE_API_BASE_URL=http://127.0.0.1:8787 npm run dev:web
```

Open the printed URL. The header shows whether the backend is in **live inference** or
**demo mode**.

### Configure the Hugging Face token securely

Never put the token in a file that git tracks.

Local development — `packages/worker/.dev.vars` (git-ignored):

```bash
echo 'HF_TOKEN=hf_your_token_here' >> packages/worker/.dev.vars
```

Production — a Cloudflare Worker secret, stored encrypted and never echoed:

```bash
npx wrangler secret put HF_TOKEN --env production
```

Create the token at <https://huggingface.co/settings/tokens> as a **fine-grained** token
with only the *Make calls to Inference Providers* permission.

## Model configuration

The model is backend configuration, not a hardcoded constant:

| Variable | Purpose | Default |
| --- | --- | --- |
| `HF_MODEL` | Primary instruction-following model | `meta-llama/Llama-3.3-70B-Instruct` |
| `HF_MODEL_FALLBACKS` | Comma-separated models tried when the primary is unavailable | two alternates |
| `HF_PROVIDER` | Inference provider pin, or `auto` to let Hugging Face route | `auto` |
| `HF_BASE_URL` | OpenAI-compatible Inference Providers router | `https://router.huggingface.co/v1` |
| `HF_TIMEOUT_MS` / `HF_MAX_RETRIES` / `HF_MAX_OUTPUT_TOKENS` | Request budget guards | 45000 / 2 / 4096 |

Calls go to the official Inference Providers chat-completions route with a hard timeout,
bounded retries with jitter, automatic fallback on model unavailability, and distinct
error codes for exhausted credits, rate limiting, timeouts and invalid output.

## Usage limits

A free generation request returns **at most two detection use cases**. This is a
commercial guardrail enforced server-side and cannot be changed by a prompt. It is
independent of the seven query formats — each use case still gets all seven.

> This free Detection Engineering Agent supports a maximum of 2 use cases per request.
> For high-fidelity detection use cases, advanced correlation, custom detection
> engineering, and enterprise DE solutions, please contact Lubin A.K.

## Out of scope

The platform serves defensive detection engineering only. Unrelated programming requests,
offensive tooling, prompt-injection attempts and configuration-extraction attempts are
rejected before inference with a fixed message. Describing attacker behaviour, commands
and indicators *in order to detect them* is explicitly supported — the classifier
evaluates the requested action, not the mere presence of adversarial vocabulary.

## Testing

```bash
npm test
```

Generated Sigma rules are additionally validated in CI by **pySigma**, the Sigma
reference implementation: the emitted YAML is parsed, and every detection condition is
resolved against the selections it references (`scripts/validate-sigma.py`).

Covers valid requirements, vendor and log-source selection, missing log-source handling,
the two-use-case cap, all seven adapters, unrelated and prohibited requests, prompt
injection, secret extraction, PII and credential sanitisation, malformed and oversized
input, XSS payloads, Hugging Face failures, quota exhaustion, rate limiting, missing
credentials, schema validation and export functionality.

## Deployment

The frontend is a static site on GitHub Pages; the API is a Cloudflare Worker, because
GitHub Pages cannot run server-side handlers or hold a runtime secret. Both live in this
repository and deploy from GitHub Actions. See [`DEPLOYMENT.md`](DEPLOYMENT.md).

Two one-time steps need a repository admin and cannot be automated:

1. **Settings → Pages → Source: GitHub Actions** — the Actions token is not permitted to
   create a Pages site, so the deploy workflow fails at `configure-pages` until this is set.
2. **Cloudflare Worker secrets** — `wrangler secret put HF_TOKEN` and
   `wrangler secret put SESSION_SIGNING_KEY`. Without `HF_TOKEN` the backend runs in
   labelled demo mode rather than performing live inference.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).
