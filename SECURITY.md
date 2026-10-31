# Security policy

## Reporting a vulnerability

Report security issues privately through GitHub Security Advisories
(**Security → Report a vulnerability**) on this repository. Please do not open a public
issue for an unfixed vulnerability.

Include: affected component, reproduction steps, impact, and — if a credential was
exposed — the fact of exposure, **not** the credential value.

Expect an acknowledgement within 5 working days and a status update within 15.

## If a credential is exposed

1. **Stop the release.** Do not deploy or publish.
2. **Revoke and rotate first.** Revoke the Hugging Face token at
   <https://huggingface.co/settings/tokens>, rotate `SESSION_SIGNING_KEY`, and roll any
   Cloudflare API token. Rotation precedes cleanup: history rewriting does not
   un-leak anything already fetched.
3. **Remove from history** with `git filter-repo` and force-push, then invalidate caches
   and forks where possible.
4. **Report without disclosing.** Reference the finding by file and line; never paste the
   value into an issue, PR, log or chat.
5. **Re-run the scans** (`gitleaks`, CodeQL, `scripts/scan-build-artifacts.mjs`) and only
   then resume the release.

This project treats "the secret was already rotated" as the only acceptable end state
after exposure. Deployment is never marked secure while a scan is failing.

## Threat model

### Assets

| Asset | Where it lives | Exposure if lost |
| --- | --- | --- |
| `HF_TOKEN` | Cloudflare Worker secret only | Attacker spends inference credits under the project's account |
| `SESSION_SIGNING_KEY` | Cloudflare Worker secret only | Attacker mints session tokens and bypasses rate limits and quotas |
| `CLOUDFLARE_API_TOKEN` | GitHub Actions secret only | Attacker redeploys or alters the backend |
| User-submitted requirement text | Transient, in-process only | Prompt content is never stored or logged |

### Trust boundaries

1. **Browser → Worker.** All input untrusted. Schema-validated, size-limited,
   sanitised and guardrail-classified before use.
2. **Worker → Hugging Face.** Only sanitised, redacted content is transmitted. The
   system prompt is assembled entirely from compiled constants.
3. **Hugging Face → Worker.** Model output is untrusted. Safety-scanned, then
   schema-validated, then discarded if it fails either.
4. **Worker → Browser.** Responses carry no secrets, no raw upstream error bodies and no
   echo of the raw requirement.

### Explicit non-goals

The application holds no SIEM credentials, never connects to a SIEM, and never deploys a
generated query anywhere. Generated content is a read-only presentation and export
workflow.

## Controls

### Secret management

- `HF_TOKEN` is read only from the Worker environment and used only as an `Authorization`
  header value. It is never placed in a request body, response body, log line or error.
- `.gitignore` excludes `.env`, `.env.*` (except `.env.example`), `.dev.vars`, `*.pem`
  and `*.key`. CI fails if such a file becomes tracked.
- `.env.example` contains placeholders only.
- `scripts/scan-build-artifacts.mjs` fails the build if anything credential-shaped
  reaches a shipped bundle. It reports shape and location, never the value.
- The logger routes every string field through a redactor as a backstop.

### Authentication and authorisation

- Inference requires either a short-lived HMAC-signed session bearer token (issued by
  `POST /api/v1/session`) or a configured shared API key.
- Session tokens are signed with HMAC-SHA256 via WebCrypto, carry an expiry, and are
  verified with a length-independent comparison.
- The frontend holds the token **in memory only** — never in `localStorage`,
  `sessionStorage` or a cookie — so it cannot be read after a refresh or replayed
  cross-site.
- Because credentials travel in headers rather than cookies, CSRF is structurally not
  applicable; a session-bound `X-DFAI-CSRF` header is still required as defence in depth.

### Rate limiting and cost control

- Sliding-window rate limit per session or API key (`RATE_LIMIT_REQUESTS` /
  `RATE_LIMIT_WINDOW_SECONDS`).
- Independent daily inference quota per subject (`DAILY_QUOTA_PER_SESSION`).
- Both are checked **before** an inference call, so a throttled request costs nothing.
- With a KV namespace bound the counters are durable; without one they are per-isolate
  and best-effort, and `GET /api/v1/health` reports which mode is active.

### CORS and HTTP headers

- Exact-match origin allowlist. No wildcards and no suffix matching, so a look-alike
  origin cannot pass.
- Every response carries `Content-Security-Policy: default-src 'none'`,
  `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Strict-Transport-Security`, `Permissions-Policy` and `Cache-Control: no-store`.
- The frontend ships its own CSP: no inline scripts, no remote script origins, no
  objects, no frames.

### Input validation and sanitisation

Deterministic, ordered, and run before any prompt is constructed:

1. Type and size checks (`maxRequestBytes`, requirement length bounds).
2. Unicode NFKC normalisation; removal of control, zero-width and bidi characters.
3. Rejection of malformed encoding (lone surrogates, undecodable sequences).
4. Rejection of raw log pastes (syslog, CEF, LEEF, access logs, timestamped multi-line
   dumps, large JSON event dumps), binary file headers and encoded payload blobs.
5. Redaction of credentials and personal data: private keys, Hugging Face / GitHub /
   Slack / AWS / Google keys, JWTs, authorization headers, assigned credential values,
   URL-embedded credentials, email addresses, national identifiers, Luhn-valid payment
   cards and telephone numbers.
6. Markup neutralisation: script and embedded elements, inline event handlers,
   `javascript:` / `vbscript:` URIs, all HTML tags, then all residual angle brackets.
7. Whitespace normalisation and a final low-signal check.

Vendor and log-source values are **allowlisted ids**, not free text. Logical field names
are constrained to a lowercase dotted-path grammar, so no value that reaches generated
query text can terminate a literal or inject a pipeline operator.

### Guardrails

Scope enforcement lives in backend application logic, before inference — not only in the
system prompt. Rejected requests are never forwarded to the model.

Blocked categories: prompt injection and instruction override, secret extraction, policy
and commercial-guardrail tampering, offensive tooling authoring, non-security software
development, and anything with no detection intent. All return a single fixed message.

Defensive descriptions of attacker behaviour are explicitly permitted: the classifier
evaluates the requested action within its clause, so "write a ransomware script" is
blocked while "write a Sigma rule to detect ransomware" is allowed.

Model output is independently re-checked for injected instructions and credential-shaped
strings before it is parsed.

### Prompt-injection resistance

- The system prompt is assembled entirely from compiled constants.
- Sanitised user text is passed in a separate user message inside an explicit
  `<<<USER_DATA>>>` fence that the system prompt defines as data.
- The model emits detection **logic**, never query strings. Query text is rendered
  deterministically by the adapters, so the model has no channel into exported query
  text.
- The commercial notice, rejection message and use-case cap are compiled constants read
  by the renderer, not fields of the model response, so no prompt can alter them.

### Output handling

- All rendering goes through React text children. `dangerouslySetInnerHTML` is not used
  anywhere, and the syntax highlighter emits token objects rather than HTML.
- Generated queries are checked for side-effecting constructs (`| script`,
  `| runshellscript`, `| collect`, `externaldata(`, plugin execution) and rejected if
  present — generated output is read-only by policy.
- Model output cannot invoke tools, run commands, change settings or reach secrets: the
  model layer returns a string that is parsed into a validated data structure and nothing
  else.

## Repository security automation

| Control | Where |
| --- | --- |
| Dependency updates | `.github/dependabot.yml` (npm + GitHub Actions, weekly) |
| Static analysis | `.github/workflows/codeql.yml` (`security-extended`, weekly + on PR) |
| History secret scanning | `.github/workflows/secret-scan.yml` (gitleaks, `fetch-depth: 0`) |
| Build artifact scanning | `scripts/scan-build-artifacts.mjs` in CI and before Pages deploy |
| Dependency audit | `npm audit --audit-level=high` in CI |
| Sigma rule validation | `scripts/validate-sigma.py` (pySigma reference implementation) in CI |
| Workflow least privilege | `permissions: contents: read` by default; elevated only where required |
| Action pinning | All third-party actions pinned to a commit SHA |

Enable **Secret scanning** and **Push protection** in the repository settings
(Settings → Code security). They are account-level settings and cannot be enabled from
a committed file.

## Supported versions

The `main` branch is the supported version. Fixes are applied forward.
