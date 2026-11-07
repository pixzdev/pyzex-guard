# PYZEX GUARD

> **Catch the leak. Understand the risk. Fix it before it ships.**
> *Deteksi kebocoran. Pahami risikonya. Cegah sebelum terlanjur.*

A privacy-first autonomous **SecOps Office Agent** built for the
**Tencent Cloud AI CAN DO IT Hackathon Indonesia 2026 — Challenge B: The Office Agent**.
Created by **Muhammad Rafif Rianto — PIXZ.DEV**.

- **Live demo:** <https://pyzex-guard.vercel.app> (runs in `DEMO_MODE` with the
  clearly-labeled deterministic fallback; add a provider API key in the
  environment to switch the same deployment to live GLM triage)
- **Repository:** <https://github.com/pixzdev/pyzex-guard>

---

## 1. Pengantar (Bahasa Indonesia)

Tim — terutama developer junior, kontraktor, dan karyawan yang menangani file
konfigurasi — sangat sering secara tidak sengaja membocorkan kredensial: API
key, secret cloud, password database, atau JWT secret yang tertanam di dalam
kode dan diff. Review manual membutuhkan waktu dan sering terlewat.

**Pyzex Guard** adalah agen keamanan operasional (SecOps Office Agent) yang:

1. **Mendeteksi** nilai sensitif secara **lokal** di server (tanpa mengirimnya ke mana pun),
2. **Menyamarkan** (redact) nilai tersebut **sebelum** materi dikirim ke AI,
3. Melakukan **triage kontekstual** menggunakan model GLM melalui endpoint
   OpenAI-compatible bawaan sponsor (SumoPod),
4. **Memvalidasi** keluaran AI terhadap kebijakan sisi aplikasi (PYGUARD),
5. Menyusun **usulan perbaikan (patch)** yang hanya bisa diterapkan setelah
   **persetujuan manusia**,
6. Menyimpan **catatan audit tersanitasi** ke Neon PostgreSQL.

Prinsip intinya: **AI boleh menganalisis dan mengusulkan — tidak pernah
men-deploy, commit, push, atau menerapkan perubahan tanpa persetujuan manusia.**

## 2. English Summary

Pyzex Guard ingests code snippets, git diffs, and configuration files; detects
potential credential exposure **locally**; redacts every sensitive value
**before** any external AI call; runs contextual security triage with a
GLM-class model via an OpenAI-compatible endpoint; validates the model's
findings against deterministic server-side policies; computes a deterministic
risk index; drafts a minimal remediation patch; and persists a sanitized audit
record to Neon PostgreSQL.

It is an **autonomous triage and remediation-drafting agent** — deliberately
*not* an unrestricted production operator. Human approval is structurally
enforced, not suggested.

## 3. Problem Statement

| Reality | Consequence |
| --- | --- |
| Credentials routinely appear in git diffs, `.env` files, and config snippets | One accidental push can expose cloud infrastructure |
| Manual security review is slow and creates delivery friction | Developers bypass or delay reviews under deadline pressure |
| Sending raw code to external AI services leaks secrets to third parties | "AI-powered" security tooling can itself become the breach channel |
| AI outputs are probabilistic | Unvalidated AI findings can mislead incident response |

## 4. Solution Overview

Pyzex Guard places a **deterministic privacy boundary between the scanner and
the AI**. The model reasons about *credential types and structure*, never about
actual secret values:

```text
Before (raw input)                              After (what the AI receives)
─────────────────────────────                   ─────────────────────────────
TENCENT_SECRET_ID=AKID…                   TENCENT_SECRET_ID=[REDACTED:CLOUD_SECRET_ID]
DATABASE_URL=postgresql://u:p@host/db           DATABASE_URL=postgresql://[REDACTED:DATABASE_CONNECTION_STRING]@host/db
JWT_SECRET=…                              JWT_SECRET=[REDACTED:JWT_SECRET]
```

The workflow is fully traceable: every stage of the agent state machine is
timed and displayed in the dashboard.

## 5. Feature Breakdown

- **Local secret detection (PYSCAN)** — cloud credentials, API keys, JWT-shaped
  tokens, database URLs with embedded credentials, private key blocks,
  `Authorization`/`Bearer` headers, password assignments, well-known provider
  token formats, and high-entropy candidates with contextual evidence.
- **Three privacy modes** — `hide`, `redact` (default), `show` (double opt-in,
  fail-closed). See §10.
- **Prompt-injection probes** — instruction-like content in scanned material is
  detected locally, fenced as untrusted data, and can never change the
  pipeline's enforcement behavior.
- **GLM security triage** — strict system prompt, JSON-schema-validated output,
  one controlled recovery attempt, safe error states.
- **PYGUARD policy gate** — deterministic validation of every model finding;
  forces `human_approval_required = true`; scrubs any raw secret the model may
  echo back (`leak_prevented` flag).
- **Deterministic risk index** — server-computed from validated findings
  (Critical 40 / High 25 / Medium 12 / Low 4, capped at 100). Never taken from
  the model's own opinion.
- **Remediation drafts** — unified diff proposals with a one-click **Copy
  Patch** action. Never auto-applied.
- **Sanitized audit history** — optional Neon PostgreSQL persistence of
  metadata and redacted evidence only.
- **Reliable demo mode** — `DEMO_MODE=true` presents a clearly-labeled
  deterministic MOCK FALLBACK derived from real local detections when the
  provider is unavailable. Live results, mock results, and provider errors are
  always visually distinct in the UI.

## 6. Architecture

```text
                 PYZEX GUARD
                      |
             Browser Dashboard  (public/index.html + app.js, Tailwind CSS)
                      |
               Express API        (lib/app.js — routes, helmet, CORS, rate limits)
                      |
               Request Guard      (zod request schema, 65,536-char cap, 160 KB body cap)
                      |
               PYSCAN Module      (tests/redactor.test.js proves the rules)
                      |
              Local Redactor      (lib/redactor.js — detection + redaction, in-memory)
                      |
             Sanitized Payload    (typed placeholders only — raw values never leave)
                      |
        Tencent ecosystem AI route (multi-provider registry —
        SumoPod default; Tencent Cloud / custom via config)
                            (lib/ai-provider.js — OpenAI-compatible adapter)
                      |
                GLM Engine        (sponsor endpoint: SumoPod-hosted, model glm-5.3-flash)
                      |
             Structured Output    (lib/security-schema.js — strict JSON contract)
                      |
              PYGUARD Module      (policy gate + leak scrub + forced human approval)
                      |
             Risk & Policy Gate   (lib/risk-engine.js — deterministic weights)
                  /       \
                 /         \
        Patch Proposal    Audit Store
     (proposal only —     (lib/audit-store.js —
      human approval)      Neon PostgreSQL, sanitized rows)
```

### 6.1 What is deterministic vs. AI-assisted

| Stage | Nature | Trust boundary |
| --- | --- | --- |
| Request validation | Deterministic | — |
| Secret detection & redaction | Deterministic | Runs entirely locally |
| Security triage reasoning | **AI-assisted** | Receives sanitized payload only |
| Output validation | Deterministic | Model output cannot skip it |
| Policy gate / human approval | Deterministic | Cannot be overridden by the model |
| Risk index | Deterministic | Computed from validated findings |
| Audit persistence | Deterministic | Stores sanitized data only |

### 6.2 Honest module naming

**PYSCAN** and **PYGUARD** are specialist *stages* of one orchestrated
workflow — implemented as application modules (`lib/redactor.js`,
`lib/pipeline.js`, `lib/risk-engine.js`), not separate AI agents. This README
describes them as what they are.

## 7. PYSCAN → PYGUARD Workflow

```text
INGEST ──▶ PYSCAN ──▶ LOCAL SANITIZATION ──▶ GLM SECURITY TRIAGE ──▶
PYGUARD POLICY VALIDATION ──▶ REMEDIATION DRAFT ──▶ HUMAN APPROVAL ──▶ AUDIT RECORD
```

Every `/api/scan` response contains the `workflow` array with per-stage
status (`ok` / `mock` / `error`) and duration in milliseconds — the dashboard
renders this timeline live.

## 8. Privacy Architecture

```text
Raw User Input
      |
      v
Request Validation ........ zod schema, size caps
      |
      v
Local Secret Detection .... lib/redactor.js (server-side, in-memory)
      |
      v
Sensitive Value Redaction . redact | hide | show(double opt-in)
      |
      v
Sanitized Payload ......... raw values absent (redact/hide)
      |
      v
External AI Provider ...... OpenAI-compatible endpoint, untrusted-data fencing
      |
      v
AI Response Validation .... strict JSON schema, 1 corrective retry
      |
      v
Policy Validation ......... PYGUARD gate: leak scrub, forced approval
      |
      v
Sanitized Audit Record .... metadata + redacted evidence only
      |
      v
Neon PostgreSQL
```

Hard guarantees (each covered by an automated test in `tests/security.test.js`):

1. Under `REDACT`/`HIDE`, raw values **never** enter the outbound AI request.
2. Raw secrets **never** appear in application logs (scrubbed structured
   logging; bodies are never logged).
3. Raw secrets **never** reach Neon — the store scrubs defensively and the
   pipeline only submits sanitized material.
4. If the model echoes a raw secret back, the policy gate replaces it with
   `[REDACTED:LEAK_PREVENTED]` and sets `leak_prevented: true`.
5. `human_approval_required` is forced to `true` server-side, even if the
   model claims otherwise (`policy_overrides: ["human_approval_forced"]`).

## 9. Local Secret Detection — capabilities & limits

**Detected patterns** (context-aware, false-positive controlled):

- Cloud credential assignments (`*_SECRET_ID`, `*_SECRET_KEY`, `ACCESS_KEY_ID`…)
- Well-known token formats: AWS `AKIA…`, Tencent `AKID…`, GitHub `ghp_/gho_/github_pat_`,
  Slack `xox…`, Google `AIza…`, Stripe `sk_test_/sk_live_`, GitLab `glpat_`
- JWT-shaped tokens (`eyJ…`), `Authorization: Bearer …` headers
- Connection strings with embedded credentials (postgres, mysql, mongodb, redis, amqp, mssql)
- PEM private key blocks (`-----BEGIN … PRIVATE KEY-----` through `END`)
- Password/secret/API-key assignments in env files, JSON, YAML, and code
- Prompt-injection phrases (threat indicator, transmitted as data only)

**Deliberately ignored** (false-positive control): `${VAR}` / `$VAR` /
`{{VAR}}` / `<placeholder>` interpolations, `process.env.*` lookups, trivial
literals (`null`, `true`…), sentences with spaces, and pure punctuation.

**Documented limitations** — regex + context heuristics cannot discover every
possible secret (obfuscated, encrypted, or custom-encoded values may pass).
Pure entropy scanning without contextual evidence is intentionally **not**
enabled because it produces unacceptable false-positive rates in practice.
The engine is a high-signal triage layer, not a guarantee. Representative
cases are covered in `tests/redactor.test.js`.

## 10. SENSITIVE_DATA configuration

| Mode | Behaviour | Opt-in |
| --- | --- | --- |
| `hide` | Values replaced by `[SENSITIVE_VALUE_REMOVED]` — no type hints leave | — |
| `redact` *(default)* | Values replaced by typed placeholders (`[REDACTED:API_KEY]`), structure preserved | — |
| `show` | Original values sent to the AI provider | **Requires BOTH** `SENSITIVE_DATA=show` **and** `ALLOW_SENSITIVE_DATA_TO_AI=true` |

`show` **fails closed**: if either condition is missing, the effective mode is
`redact` and the UI displays a warning. `show` is never enabled automatically
and never silently. Even in `show` mode, raw values are never persisted to
Neon, never written to logs, never returned in error messages, and never
included in audit records — and model output is still leak-scrubbed.

## 11. AI Provider Integration

- **Adapter**: `lib/ai-provider.js` — the only provider-aware module. Works
  with any OpenAI-compatible Chat Completions endpoint through a small
  **provider registry** (`lib/config.js`).
- **Provider profiles** (selected with `AI_PROVIDER`, default `auto` = first
  fully configured profile wins):

  | Profile | Env vars | Status |
  | --- | --- | --- |
  | `sumopod` — SumoPod sponsor endpoint | `SUMOPOD_BASE_URL` / `SUMOPOD_API_KEY` / `SUMOPOD_MODEL` | **Verified**: endpoint reachable, OpenAI-compatible auth errors; model `glm-5.3-flash` |
  | `tencent` — Tencent Cloud OpenAI-compatible inference (e.g. TI-ONE endpoint or a Hunyuan OpenAI-compatible gateway) | `TENCENT_BASE_URL` / `TENCENT_API_KEY` / `TENCENT_MODEL` | **Supported via configuration** — same adapter, same privacy pipeline; unverified pending credentials |
  | `custom` — any other OpenAI-compatible endpoint | `CUSTOM_BASE_URL` / `CUSTOM_API_KEY` / `CUSTOM_MODEL` | Supported via configuration |

- **Tencent ecosystem honesty**: the backend calls one thing — an
  OpenAI-compatible inference endpoint (`/v1/chat/completions`). No proprietary
  Tencent SDK and no proprietary WorkBuddy API is called or required. The
  `tencent` profile is a configuration surface for any Tencent-hosted
  OpenAI-compatible inference deployment; pointing it at a real endpoint is a
  credentials change, not a code change. Deeper ecosystem touchpoints
  (COS audit export, Tencent Cloud deployment targets) are documented as
  future work — none are claimed as implemented.
- **Sponsor default values** (from `.env.example`): base URL
  `https://ai.sumopod.com/v1`, model ID `glm-5.3-flash` — the exact
  provider-catalog ID, never hardcoded in application logic.
- **Reliability**: 30 s request timeout, 1 network retry, JSON-mode requests,
  robust JSON extraction (fences/prose/repair), **one** controlled corrective
  retry for schema violations, classified errors
  (`PROVIDER_NOT_CONFIGURED`, `PROVIDER_AUTH_FAILED`, `PROVIDER_RATE_LIMITED`,
  `PROVIDER_QUOTA_EXHAUSTED`, `PROVIDER_TIMEOUT`, `PROVIDER_INVALID_RESPONSE`,
  `PROVIDER_UNAVAILABLE`) that never contain credential material.

**Live-status honesty**: as of this submission, inference calls from the
deployed demo run in **DEMO/MOCK FALLBACK** mode because no provider API key
was embedded in the repository (by design). Once `SUMOPOD_API_KEY` (or a
`TENCENT_*` / `CUSTOM_*` set) is configured in the environment, the same code
path performs live GLM triage — no code changes required.

## 12. Neon Database Architecture

- Driver: `@neondatabase/serverless` HTTP driver — serverless-friendly,
  no connection pooling assumptions, works on Vercel functions.
- All queries are **parameterized** (tagged templates).
- Table: `scan_audit` (`db/schema.sql`) — scan metadata, severity, risk index,
  findings (JSONB, redacted), sanitized diff, AI status/model/latency,
  processing duration, privacy mode. **No raw content column exists.**
- Without `DATABASE_URL` (or with a non-PostgreSQL URL) the store reports
  `persistence_active: false` and the application keeps working — the UI
  states "PERSISTENCE INACTIVE" instead of pretending history exists.

## 13. Installation

```bash
git clone <your-repo-url> pyzex-guard
cd pyzex-guard
npm install
cp .env.example .env   # fill in SUMOPOD_API_KEY to enable live AI
```

Requirements: Node.js ≥ 20. No database is required to run the demo; Neon is
optional.

## 14. Local Development

```bash
npm run dev          # node --watch server.js
# or
npm start            # http://localhost:3000
```

The dashboard loads at `http://localhost:3000`. Demo presets are preloaded —
all preset credentials are synthetic and non-functional.

## 15. Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `AI_PROVIDER` | `auto` | `sumopod` \| `tencent` \| `custom` \| `auto` (first configured profile wins) |
| `SUMOPOD_BASE_URL` | `https://ai.sumopod.com/v1` | Sponsor endpoint (OpenAI-compatible) |
| `SUMOPOD_API_KEY` | *(empty)* | SumoPod API key (`sk-…`). Never commit. |
| `SUMOPOD_MODEL` | `glm-5.3-flash` | Exact model ID from the provider catalog |
| `TENCENT_BASE_URL` / `TENCENT_API_KEY` / `TENCENT_MODEL` | *(empty)* | Tencent Cloud OpenAI-compatible inference profile (e.g. TI-ONE / Hunyuan gateway) |
| `CUSTOM_BASE_URL` / `CUSTOM_API_KEY` / `CUSTOM_MODEL` | *(empty)* | Any other OpenAI-compatible endpoint |
| `SENSITIVE_DATA` | `redact` | `hide` \| `redact` \| `show` |
| `ALLOW_SENSITIVE_DATA_TO_AI` | `false` | Second condition for `show` mode |
| `DEMO_MODE` | `true` | Labeled MOCK FALLBACK when provider fails/unconfigured |
| `DATABASE_URL` | *(empty)* | Neon PostgreSQL connection string (optional) |
| `PORT` | `3000` | Local server port |

## 16. Vercel Deployment

1. Push this repository to GitHub.
2. In Vercel: **Add New → Project → Import** the repository (framework: Other).
3. Set environment variables (Project → Settings → Environment Variables):
   `SUMOPOD_API_KEY` (+ optionally `SUMOPOD_BASE_URL`, `SUMOPOD_MODEL`,
   `AI_PROVIDER`), `SENSITIVE_DATA=redact`, `ALLOW_SENSITIVE_DATA_TO_AI=false`,
   `DEMO_MODE=true`, and optionally `DATABASE_URL` (Neon).
4. Apply the schema once: run the SQL in `db/schema.sql` in the Neon console.
5. Deploy. `vercel.json` routes `/api/*` to the serverless function
   (`api/index.js`) and serves the dashboard from `public/`.

Notes: the neon HTTP driver avoids pooling issues; `express-rate-limit` uses a
per-instance memory store on serverless (documented limitation, §19).

## 17. API Documentation

### `GET /api/health`

Configuration **state** only — never secret values.

```json
{
  "status": "ok",
  "service": "pyzex-guard",
  "version": "1.0.0",
  "privacy": { "requested_mode": "redact", "effective_mode": "redact", "show_opt_in": false, "warning": null },
  "demo_mode": true,
  "ai_provider": { "configured": false, "base_url_configured": false, "api_key_configured": false, "model_configured": false, "model": null },
  "database": { "configured": false, "active": false, "reason": "DATABASE_URL_NOT_SET" },
  "limits": { "max_content_chars": 65536, "scan_rate_limit": "30 requests / 5 minutes" }
}
```

### `POST /api/preview`

Local redaction preview (no AI call, no persistence).

```bash
curl -s -X POST http://localhost:3000/api/preview \
  -H 'content-type: application/json' \
  -d '{"content":"JWT_SECRET=EXAMPLE_ONLY_NOT_A_REAL_SECRET_0000"}'
```

### `POST /api/scan`

```bash
curl -s -X POST http://localhost:3000/api/scan \
  -H 'content-type: application/json' \
  -d '{
    "source_type": "git_diff",
    "filename": "config.env",
    "content": "TENCENT_SECRET_ID=AKIDfakeEXAMPLEid000000000000000000\n"
  }'
```

Request body: `{ source_type: "snippet"|"git_diff"|"config", filename?: string(≤200), content: string(1..65,536) }`.

Response (abridged):

```json
{
  "scan_id": "pg_261107_a1b2c3d4",
  "privacy": { "effective_mode": "redact", "detected_sensitive": 1, "detections": [ { "line": 1, "type": "CLOUD_SECRET_ID", "key_name": "TENCENT_SECRET_ID", "rule": "assignment" } ] },
  "sanitized_payload": "TENCENT_SECRET_ID=[REDACTED:CLOUD_SECRET_ID]\n",
  "analysis": { "severity": "high", "summary": "…", "detected_vulnerabilities": [ … ], "compliance_status": { … } },
  "risk": { "index": 25, "band": "moderate", "note": "Application-defined triage indicator — not an industry-standard security rating." },
  "remediation": { "status": "auto_patch_proposed", "diff": "--- a/config.env …", "auto_apply": false, "human_approval_required": true },
  "ai": { "status": "live | mock_fallback", "model": "glm-5.3-flash", "latency_ms": 0, "note": "…" },
  "workflow": [ { "stage": "INGEST", "status": "ok", "duration_ms": 1 } ],
  "persistence": { "persisted": false, "reason": "DATABASE_URL_NOT_SET" }
}
```

Errors: `400 INVALID_REQUEST`, `413 PAYLOAD_TOO_LARGE`, `429 RATE_LIMITED`,
`503 PROVIDER_*`, `500 INTERNAL_ERROR` — all structured JSON.

### `GET /api/history?limit=10`

Recent **sanitized** audit records. Returns
`{ persistence_active: false, records: [] }` when Neon is not configured.

### `GET /api/presets`

Demo presets (synthetic credentials only).

## 18. Testing

```bash
npm test       # Node.js built-in test runner
```

51 tests across three suites (all passing):

- `tests/redactor.test.js` — detection rules, privacy modes, idempotency,
  scrubbing, injection probes, false-positive controls.
- `tests/api.test.js` — endpoint behavior, workflow completeness, input
  validation, oversized rejection, honest inactive-persistence state.
- `tests/security.test.js` — the security acceptance checklist: redaction
  before AI invocation (REDACT/HIDE), show-mode double opt-in, log hygiene,
  sanitized audit rows, leak-echo scrubbing, output-validation enforcement,
  prompt-injection containment, provider-failure containment, deterministic
  risk-index math.

## 19. Known Limitations

1. **Detection is heuristic.** Regex + context cannot guarantee discovery of
   every secret format (see §9). Positioning: triage aid, not a scanner of record.
2. **Live GLM inference is unverified in this submission artifact** because no
   provider API key is committed (by design). The endpoint itself was verified
   reachable and OpenAI-compatible; the full code path is exercised via the
   mock fallback with identical downstream validation.
3. **Rate limiting is per-instance** on serverless (memory store). Suitable
   for the demo; a durable store would be needed at scale.
4. **CSP allows `'unsafe-inline'` + CDN scripts** (Tailwind Play CDN, Lucide
   UMD) to keep the repo single-page and dependency-light. A production build
   should self-host compiled Tailwind and inline icons.
5. **No authentication / multi-tenancy.** The dashboard is a demo workspace;
   deploy it behind SSO for team use.
6. **No repository back-connector.** Pyzex Guard does not clone repos or read
   git history; it analyzes submitted material.
7. **Compliance notes are not certifications**, by design and by contract in
   the model schema.
8. **Risk index is an application-defined triage indicator**, not an
   industry-standard rating (CVSS/SSVC are out of scope).

## 20. Hackathon Challenge Alignment

**Challenge B — The Office Agent** asks for Agentic AI that automates
repetitive operational workflows. Pyzex Guard automates the *office routine of
security review*:

- **Autonomous workflow** — an eight-stage agent state machine (ingest → scan →
  sanitize → triage → policy-validate → draft → approval → audit) executes a
  real operational job end-to-end.
- **Human accountability** — the agent drafts; a human approves. Structurally
  enforced, never optional.
- **Enterprise reliability** — typed provider errors, labeled demo fallback,
  sanitized audit trail, deterministic risk scoring, observable per-stage timing.
- **Privacy-aware AI adoption** — shows exactly how to give an LLM enough
  context to be useful without handing it secrets. This is the pattern teams
  need before they can adopt AI agents for operational work.

## 21. Sponsor Attribution & Resources

- **Tencent Cloud International** — hackathon host.
  <https://www.tencentcloud.com/>
- **SumoPod** — hackathon supporter; provider of the OpenAI-compatible GLM
  inference endpoint used by the backend (`https://ai.sumopod.com/v1`,
  model `glm-5.3-flash`).
- **AICLUB.ID** — hackathon supporter.

Pyzex Guard is an independent hackathon project by PIXZ.DEV. It is **not**
officially endorsed by, affiliated with, or produced by Tencent Cloud,
SumoPod, or AICLUB.ID. Sponsor resources referenced: the hackathon program and
the sponsor-provided inference endpoint described above. No other sponsor
integrations are implemented or claimed.

---

## License

MIT — © 2026 Muhammad Rafif Rianto / PIXZ.DEV. See [LICENSE](LICENSE).
