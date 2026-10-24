# Mailroom Action Gate (ga5-mailroom-action-gate/v2)

A public HTTPS endpoint that reads mail dossiers, proposes one safe action each, and
records an action as executed only after a valid Ed25519-signed receipt.

Everything runs on **free tiers**:

| Part | Free service |
|---|---|
| HTTPS hosting | Vercel Hobby (Python serverless function) |
| Durable storage | Upstash Redis free plan (added from Vercel Marketplace) |
| AI model | Google Gemini API free tier (`gemini-2.5-flash`, falls back to `gemini-2.5-flash-lite` on rate limits) |

## How it works

```
POST (any path) ─► strict validation (400/422, no AI) ─► replay / 409 conflict check (Redis)
   propose: cached decision by dossier content? ─ yes ─► reuse (no model call)
                                               └ no ──► Gemini (batches of 8, parallel)
                                                        └► safety gate in code:
                                                           • builds the frozen target/payload shapes
                                                           • every value must be copied verbatim from the dossier
                                                           • blocks vault/canary values
                                                           • send_approved_notice only if trusted approval names
                                                             the exact recipient + reference + status
                                                           • invalid → re-ask that dossier with the validator's reason
                                                           • model down → conservative fallback (never sends, not cached)
            ─► persist proposals + verifier key ─► 200 awaiting_receipts
   commit:  stored evaluation? digest + callId + action + proposalDigest match? every signature valid?
            (any failure → whole commit rejected, nothing recorded) ─► persist ─► 200 completed
```

`callId` = hash of dossier id + content, so core dossiers keep the same proposal and callId
across evaluations and Checks.

## Deploy (about 15 minutes)

1. **Gemini key** – open <https://aistudio.google.com/apikey>, sign in, *Create API key*. Copy it.
2. **Code on GitHub** – create a new (private is fine) GitHub repo and upload this folder's
   contents (`api/`, `mailroom/`, `tests/`, `tools/`, `requirements.txt`, `vercel.json`).
3. **Vercel project** – at <https://vercel.com> sign in with GitHub → *Add New… → Project* →
   import the repo → Framework preset **Other** → *Deploy*.
4. **Storage** – in the project: *Storage → Create Database → Upstash for Redis (Marketplace)* →
   free plan → connect it to the project (all environments). This adds `KV_REST_API_URL` and
   `KV_REST_API_TOKEN` automatically.
5. **Model key** – *Settings → Environment Variables* → add `LLM_API_KEY` = your Gemini key.
6. **Redeploy** – *Deployments → ⋯ → Redeploy* (env vars apply only to new deployments).
7. **Check health** – open `https://<your-project>.vercel.app/v1/mailroom/actions` in a browser.
   You must see `"store":"upstash"` and `"modelConfigured":true`.
   If it says `sqlite`, storage is not connected — do **not** submit yet.
8. **Submit** `https://<your-project>.vercel.app/v1/mailroom/actions` (any path works; no query,
   no fragment). Use the production `*.vercel.app` domain, not a preview URL — previews are
   behind Vercel login.

## Test before spending a Check

```bash
pip install fastapi uvicorn httpx cryptography pytest
python -m pytest -q tests                                   # local grader simulator, no model
python tools/smoke_remote.py https://<your-project>.vercel.app/v1/mailroom/actions
```

The smoke test sends 8 invented dossiers to your live endpoint and checks propose, replay,
409 conflict, malformed input, tampered receipts, commit, and caching. All lines should say PASS.

## After your first Check

The first Check fills the cache with the 58 core decisions. Review them before Check 2:

```bash
export KV_REST_API_URL=...  KV_REST_API_TOKEN=...   # Vercel → Storage → your DB → .env.local tab
python tools/review.py > review.txt
```

Each decision is printed with the dossier lines, the cited lines marked `>>`, and the model's
reason. If a category looks wrong, improve `SYSTEM_PROMPT` in `mailroom/decide.py`, redeploy,
and purge only the affected dossiers (`python tools/review.py --purge <dossierId>`).

## Settings (environment variables, all optional except the key)

| Variable | Default | Meaning |
|---|---|---|
| `LLM_API_KEY` | — | Model API key (required) |
| `LLM_BASE_URL` | Gemini OpenAI-compatible URL | Any OpenAI-compatible provider, e.g. `https://api.groq.com/openai/v1` |
| `LLM_MODEL` | `gemini-2.5-flash` | Main model |
| `LLM_FALLBACK_MODEL` | `gemini-2.5-flash-lite` | Used after a 429 rate limit |
| `LLM_REASONING_EFFORT` | `low` | `low` / `medium` / `high` / `off` |
| `LLM_BATCH` | `8` | Dossiers per model call |
| `LLM_CONCURRENCY` | `8` | Parallel model calls (keep ≤ free-tier requests/minute) |
| `PROPOSE_BUDGET_SECONDS` | `46` | Time budget for a propose (grader limit is 55 s) |

## Notes

* Free-tier Gemini prompts may be used by Google to improve its products. The exam dossiers are
  synthetic; never send real customer data through this service.
* Status codes: 400/422 malformed (before any AI work), 404 unknown evaluation on commit,
  409 changed content / mismatched receipt, 422 bad/missing/duplicated/moved signature.
