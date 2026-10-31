# Deployment guide

The frontend is a static site on **GitHub Pages**. The API is a **Cloudflare Worker**.

GitHub Pages serves static files only: it cannot execute a server-side handler and cannot
hold a runtime secret. Putting `HF_TOKEN` in the frontend would publish it to every
visitor. So the token lives in a small authenticated Worker, and the Pages site calls it.

Do not try to use GitHub Actions as a public real-time API. A workflow is not an HTTP
endpoint, runs are queued and logged, and exposing one would mean handing anonymous
callers the ability to trigger authenticated runs.

```
Browser ──► GitHub Pages (static)  ──► Cloudflare Worker ──► Hugging Face
            no secrets                 holds HF_TOKEN         Inference Providers
```

---

## 0. Before you publish

Keep the repository **private** until the security review passes:

```bash
npm run verify
```

```bash
node scripts/scan-build-artifacts.mjs packages/web/dist
```

Then enable, in **Settings → Code security**: Secret scanning, Push protection,
Dependabot alerts and Dependabot security updates. These are account settings and cannot
be turned on from a committed file.

Run the checklist in [`SECURITY.md`](SECURITY.md#repository-security-automation) and
confirm CI, CodeQL and gitleaks are green. Do not mark a deployment secure while any of
them is failing.

---

## 1. Create the Hugging Face token

1. Go to <https://huggingface.co/settings/tokens>.
2. Create a **fine-grained** token.
3. Grant **only** *Make calls to Inference Providers*. Nothing else.
4. Copy it once. Do not paste it into a file in this repository, an issue, or a chat.

Free Inference Providers credits are limited. The Worker enforces a per-session daily
quota so a single visitor cannot exhaust them, and reports `credits_exhausted` clearly
rather than silently degrading.

---

## 2. Deploy the API Worker

### 2.1 Authenticate

```bash
npx wrangler login
```

### 2.2 Set the secrets

Secrets are stored encrypted by Cloudflare and are never written to this repository.

```bash
npx wrangler secret put HF_TOKEN --env production
```

```bash
openssl rand -hex 32
```

```bash
npx wrangler secret put SESSION_SIGNING_KEY --env production
```

Paste the generated hex value when prompted. Optionally, for machine-to-machine callers:

```bash
npx wrangler secret put API_ACCESS_KEYS --env production
```

### 2.3 Set the CORS allowlist

Edit `packages/worker/wrangler.toml` under `[env.production.vars]` and set
`ALLOWED_ORIGINS` to the **exact** origin of your Pages site, for example:

```
ALLOWED_ORIGINS = "https://laklubin.github.io"
```

Origin matching is exact. No wildcards, no suffix matching.

### 2.4 (Recommended) Durable rate limiting

Without a KV namespace the limiter is per-isolate and best effort.

```bash
npx wrangler kv namespace create DFAI_RATE_LIMIT
```

Uncomment the `[[kv_namespaces]]` block in `wrangler.toml` and paste the returned id.

### 2.5 Deploy

```bash
npm run deploy -w @detectionforge/worker
```

Note the printed URL, for example `https://detectionforge-api.<subdomain>.workers.dev`.

### 2.6 Verify

```bash
curl -s https://detectionforge-api.<subdomain>.workers.dev/api/v1/health
```

Check that `"mode"` is `"live"` and `"model"` names your configured model. If it says
`"demo"`, `HF_TOKEN` is not set on that environment.

---

## 3. Deploy the frontend to GitHub Pages

### 3.1 Enable Pages (required, one time, by a repository admin)

**Settings → Pages → Build and deployment → Source: GitHub Actions.**

This step cannot be automated. The Actions token is not permitted to create a Pages
site, so until someone flips this setting the deploy workflow fails at `configure-pages`
with:

```
Get Pages site failed. Please verify that the repository has Pages enabled
```

Everything before that step — typecheck, tests, build and the bundle secret scan — still
runs and must pass.

### 3.2 Publish the API URL

**Settings → Secrets and variables → Actions → Variables → New repository variable:**

| Name | Value |
| --- | --- |
| `VITE_API_BASE_URL` | `https://detectionforge-api.<subdomain>.workers.dev` |

This is a **variable**, not a secret: it is a public URL containing no credential, and it
is compiled into the published bundle.

### 3.3 Deploy

Push to `main`, or run **Actions → Deploy frontend to GitHub Pages → Run workflow**.

The workflow typechecks, tests, builds with the correct base path, **fails if the bundle
contains anything credential-shaped**, and only then publishes.

Your site: `https://<owner>.github.io/<repository>/`

### 3.4 Verify end to end

1. Open the site. The header should read **live inference**.
2. Enter: *Detect multiple failed logins followed by successful authentication.*
3. Select vendor **Microsoft** and log source **Windows Security Events**.
4. Generate. You should get up to two use cases, each with seven formats.
5. Confirm the commercial notice appears beneath the results.
6. Enter *Create a Python program* and confirm the rejection message.
7. Open DevTools → Sources and search the bundle for `hf_`. There must be no match.

---

## 4. Automating the Worker deploy

To deploy the Worker from CI as well:

1. Create a Cloudflare API token scoped to **Edit Cloudflare Workers** only.
2. Add repository secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.
3. Push a change under `packages/worker/**` or `packages/core/**`.

`deploy-worker.yml` skips with a warning when the token is absent, so a fork without
credentials does not fail CI. `HF_TOKEN` and `SESSION_SIGNING_KEY` remain Worker secrets
set via `wrangler`; the workflow never handles them.

---

## 5. Running without a backend

If you cannot deploy a Worker, the Pages site still works in a clearly-labelled local
demo mode: the same validation, guardrail and adapter pipeline runs in the browser
against a synthetic fixture, and the UI states that the output was not produced by a
language model.

Do **not** attempt to make this live by putting a token in the frontend. Anything in a
Pages bundle is public.

---

## 6. Alternative hosts

`packages/core` has no platform coupling. The Worker layer is thin and can be ported to
any free-tier serverless host that supports `fetch`, environment secrets and custom
response headers, for example Vercel Functions, Netlify Functions or Deno Deploy. You
must reimplement: CORS allowlisting, bearer-token auth, rate limiting, daily quota,
security headers and safe error mapping.

---

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| UI shows "Backend unreachable" | `VITE_API_BASE_URL` unset, or origin not allowlisted | Set the Actions variable; add the Pages origin to `ALLOWED_ORIGINS` and redeploy the Worker |
| `403 forbidden_origin` | Origin not in the allowlist | Use the exact scheme + host, no trailing slash |
| `401 unauthorized` | `SESSION_SIGNING_KEY` not set | `wrangler secret put SESSION_SIGNING_KEY --env production` |
| Health reports `"mode":"demo"` in production | `HF_TOKEN` missing on that environment | Set it with `--env production` |
| `503 credits_exhausted` | Free Inference Providers credits used up | Wait for the reset or enable billing; lower `DAILY_QUOTA_PER_SESSION` |
| `503 model_unavailable` | Model not served by any provider | Change `HF_MODEL`, or rely on `HF_MODEL_FALLBACKS` |
| `502 invalid_model_output` | Model ignored the schema | Try a stronger instruction-following model; the app refuses malformed output by design |
| `429 rate_limited` | Burst limit hit | Expected; tune `RATE_LIMIT_REQUESTS` |
| Pages site 404s on assets | Wrong base path | The workflow sets `VITE_BASE_PATH` from the repository name; override for a custom domain |
