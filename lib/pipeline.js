/**
 * Pyzex Guard — agent workflow orchestrator.
 *
 * INGEST → PYSCAN → LOCAL SANITIZATION → GLM SECURITY TRIAGE →
 * PYGUARD POLICY VALIDATION → REMEDIATION DRAFT → HUMAN APPROVAL → AUDIT RECORD
 *
 * Hard invariants enforced here (not suggested — enforced):
 *  - Raw content never reaches the AI provider under REDACT/HIDE modes.
 *  - Model output is schema-validated; violations trigger one controlled
 *    corrective retry, then a safe error state (or demo fallback).
 *  - Any raw secret that reappears inside model output is replaced with a
 *    leak marker and flagged (leak_prevented).
 *  - human_approval_required is ALWAYS forced to true by the policy gate.
 *  - Patches are proposals only. Nothing is ever applied automatically.
 */
import { MAX_CONTENT_CHARS, getProviderConfig, isDemoMode } from './config.js';
import { ScanRequestSchema, parseModelOutput } from './security-schema.js';
import { scanContent, resolvePrivacy, removeExactLeaks, scrubText } from './redactor.js';
import { SYSTEM_PROMPT, buildUserMessage, callChatJson, ProviderError } from './ai-provider.js';
import { buildMockAnalysis } from './mock-analysis.js';
import { computeRiskIndex, overallSeverity, riskBand } from './risk-engine.js';
import { getDefaultAuditStore } from './audit-store.js';
import crypto from 'node:crypto';

export class RequestValidationError extends Error {
  constructor(message, { status = 400, code = 'INVALID_REQUEST', issues = [] } = {}) {
    super(message);
    this.name = 'RequestValidationError';
    this.status = status;
    this.code = code;
    this.issues = issues;
  }
}

const WORKFLOW_STAGES = [
  'INGEST',
  'PYSCAN',
  'LOCAL_SANITIZATION',
  'GLM_SECURITY_TRIAGE',
  'PYGUARD_POLICY_VALIDATION',
  'REMEDIATION_DRAFT',
  'HUMAN_APPROVAL',
  'AUDIT_RECORD',
];

function newScanId() {
  const stamp = new Date().toISOString().slice(2, 10).replace(/-/g, '');
  return `pg_${stamp}_${crypto.randomBytes(4).toString('hex')}`;
}

function clampText(value, max) {
  return scrubText(String(value ?? '')).slice(0, max);
}

/** Apply the PYGUARD policy gate to a validated model response. */
function applyPolicyGate(analysis, rawSecrets) {
  const policyOverrides = [];

  // 1) Exact-echo leak removal — the model must never relay raw secrets.
  let leakPrevented = false;
  const scrub = (text) => {
    const exact = removeExactLeaks(String(text ?? ''), rawSecrets);
    if (exact.hit) leakPrevented = true;
    return scrubText(exact.text);
  };

  analysis.summary = scrub(analysis.summary);
  analysis.risk_analysis = scrub(analysis.risk_analysis);
  if (analysis.auto_remediation_diff) {
    analysis.auto_remediation_diff = scrub(analysis.auto_remediation_diff);
    if (!analysis.auto_remediation_diff.trim()) analysis.auto_remediation_diff = null;
  }
  analysis.detected_vulnerabilities = (analysis.detected_vulnerabilities ?? []).map((finding) => ({
    ...finding,
    title: clampText(finding.title, 200),
    description: clampText(finding.description, 2000),
    evidence_excerpt: clampText(finding.evidence_excerpt, 600),
    risk_impact: clampText(finding.risk_impact, 2000),
    remediation: clampText(finding.remediation, 2000),
  }));

  // 2) Findings must be grounded: drop findings without evidence or impact.
  const before = analysis.detected_vulnerabilities.length;
  analysis.detected_vulnerabilities = analysis.detected_vulnerabilities.filter(
    (f) => (f.evidence_excerpt || f.description) && f.title
  );
  if (analysis.detected_vulnerabilities.length !== before) {
    policyOverrides.push('unsupported_findings_removed');
  }

  // 3) Consistency between remediation status and diff presence.
  if (analysis.remediation_status === 'auto_patch_proposed' && !analysis.auto_remediation_diff) {
    analysis.remediation_status = 'manual_review';
    policyOverrides.push('patch_status_downgraded');
  }
  if (analysis.remediation_status === 'no_action_required' && analysis.detected_vulnerabilities.length > 0) {
    analysis.remediation_status = 'manual_review';
    policyOverrides.push('status_inconsistent_with_findings');
  }

  // 4) Human accountability is non-negotiable.
  if (analysis.human_approval_required !== true) {
    policyOverrides.push('human_approval_forced');
  }
  analysis.human_approval_required = true;

  // 5) Compliance claims are never certifications.
  if (analysis.compliance_status && Array.isArray(analysis.compliance_status.frameworks)) {
    analysis.compliance_status.frameworks = analysis.compliance_status.frameworks.slice(0, 10);
  }

  return { analysis, policyOverrides, leakPrevented };
}

/**
 * Run the full security pipeline.
 *
 * @param {object} input        { source_type, filename, content }
 * @param {object} deps         injectable: provider, store, env (for tests)
 */
export async function runSecurityPipeline(input, deps = {}) {
  const env = deps.env ?? process.env;
  const provider = deps.provider ?? null; // null → use live provider
  const store = deps.store ?? getDefaultAuditStore();

  const stages = [];
  const startedAt = Date.now();
  const track = (stage, fn) => {
    const t0 = Date.now();
    return Promise.resolve()
      .then(fn)
      .then(
        (result) => {
          stages.push({ stage, status: 'ok', duration_ms: Date.now() - t0 });
          return result;
        },
        (err) => {
          stages.push({
            stage,
            status: 'error',
            duration_ms: Date.now() - t0,
            detail: String(err?.message ?? 'error').slice(0, 200),
          });
          throw err;
        }
      );
  };

  /* 1 — INGEST: strict request validation */
  const request = await track('INGEST', () => {
    const parsed = ScanRequestSchema.safeParse(input);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message }));
      const oversized = issues.some((i) => i.path === 'content' && /exceeds/.test(i.message));
      throw new RequestValidationError('Request validation failed.', {
        status: oversized ? 413 : 400,
        code: oversized ? 'PAYLOAD_TOO_LARGE' : 'INVALID_REQUEST',
        issues,
      });
    }
    return parsed.data;
  });

  const scanId = newScanId();

  /* 2 — PYSCAN: local detection (values stay in-memory only) */
  const scan = await track('PYSCAN', () => scanContent(request.content, { mode: 'redact', collectRaw: true }));

  /* 3 — LOCAL SANITIZATION: build the outbound payload */
  const privacy = resolvePrivacy(env);
  const sanitized = await track('LOCAL_SANITIZATION', () => {
    const result = scanContent(request.content, { mode: privacy.effective_mode, collectRaw: true });
    if (!privacy.show_opt_in && privacy.effective_mode === 'show') {
      throw new Error('unreachable: show mode without opt-in');
    }
    return result.sanitized;
  });

  /* 4 — GLM SECURITY TRIAGE (live provider, one corrective retry, demo fallback) */
  const demoMode = isDemoMode(env);
  let analysis = null;
  let aiMeta = {
    status: 'live',
    model: null,
    latency_ms: 0,
    note: 'Live AI analysis via the configured OpenAI-compatible provider.',
  };

  const mockFromLocal = () =>
    buildMockAnalysis({
      sanitized,
      detections: scan.detections,
      injections: scan.injections,
      filename: request.filename,
      sourceType: request.source_type,
    });

  const providerAnalyze = async (userMessage, extraInstruction) => {
    const bound = provider ?? {
      analyze: async ({ system, user }) => {
        const { raw, model, latency_ms } = await callChatJson({ system, user }, env);
        return { raw, model, latency_ms };
      },
    };
    const started = Date.now();
    const response = await bound.analyze({
      system: extraInstruction ? `${SYSTEM_PROMPT}\n\nADDITIONAL REQUIREMENT: ${extraInstruction}` : SYSTEM_PROMPT,
      user: userMessage,
    });
    return { ...response, latency_ms: response.latency_ms ?? Date.now() - started };
  };

  const userMessage = buildUserMessage({
    sanitizedContent: sanitized,
    sourceType: request.source_type,
    filename: request.filename,
  });

  try {
    const result = await track('GLM_SECURITY_TRIAGE', async () => {
      if (!provider && !getProviderConfig(env).configured) {
        if (demoMode) {
          aiMeta = {
            status: 'mock_fallback',
            model: null,
            latency_ms: 0,
            note: 'MOCK FALLBACK — deterministic local analysis. No AI provider is configured for this deployment.',
          };
          return { fallback: true };
        }
        throw new ProviderError(
          'PROVIDER_NOT_CONFIGURED',
          'No AI provider is configured and DEMO_MODE is disabled. Set SUMOPOD_API_KEY (sponsor default) — or AI_PROVIDER=tencent with TENCENT_BASE_URL, TENCENT_API_KEY and TENCENT_MODEL.'
        );
      }

      try {
        const response = await providerAnalyze(userMessage);
        analysis = parseModelOutput(response.raw);
        aiMeta = {
          status: 'live',
          model: response.model,
          latency_ms: response.latency_ms,
          note: 'Live AI analysis via the configured OpenAI-compatible provider.',
        };
        return { live: true };
      } catch (err) {
        // Invalid model output → ONE controlled corrective retry.
        if (!(err instanceof ProviderError)) {
          try {
            const retry = await providerAnalyze(
              userMessage,
              'Your previous response could not be parsed as JSON conforming to the required schema. Return ONLY the valid JSON object and nothing else.'
            );
            analysis = parseModelOutput(retry.raw);
            aiMeta = {
              status: 'live',
              model: retry.model,
              latency_ms: retry.latency_ms,
              note: 'Live AI analysis (after one controlled JSON recovery attempt).',
            };
            return { live: true };
          } catch {
            throw new ProviderError('PROVIDER_INVALID_RESPONSE', 'The AI provider response failed validation after one recovery attempt.', {
              status: 502,
            });
          }
        }
        throw err;
      }
    });

    if (result?.fallback) {
      analysis = mockFromLocal();
    }
  } catch (err) {
    if (err instanceof ProviderError && demoMode) {
      stages.push({
        stage: 'GLM_SECURITY_TRIAGE',
        status: 'mock',
        duration_ms: 0,
        detail: `${err.code} — presenting clearly-labeled MOCK FALLBACK`,
      });
      analysis = mockFromLocal();
      aiMeta = {
        status: 'mock_fallback',
        model: null,
        latency_ms: 0,
        note: `MOCK FALLBACK — deterministic local analysis (${err.code}). The live AI call did not complete.`,
      };
    } else {
      throw err;
    }
  }

  /* 5 — PYGUARD POLICY VALIDATION */
  const gated = await track('PYGUARD_POLICY_VALIDATION', () => {
    if (!aiMeta.status || aiMeta.status === 'live') {
      // live analysis was already parsed; re-validate defensively
      analysis = parseModelOutput(JSON.stringify(analysis));
    }
    return applyPolicyGate(analysis, scan.rawSecrets);
  });
  analysis = gated.analysis;
  const policyOverrides = gated.policyOverrides;
  const leakPrevented = gated.leakPrevented;

  /* 6 — REMEDIATION DRAFT */
  const remediation = await track('REMEDIATION_DRAFT', () => ({
    status: analysis.remediation_status,
    diff: analysis.auto_remediation_diff,
    auto_apply: false,
    human_approval_required: true,
  }));

  /* 7 — HUMAN APPROVAL (always required) */
  await track('HUMAN_APPROVAL', () => {
    analysis.human_approval_required = true;
    return true;
  });

  /* 8 — AUDIT RECORD (only when persistence is configured) */
  const risk = computeRiskIndex(analysis.detected_vulnerabilities);
  const severity = overallSeverity(analysis.detected_vulnerabilities, analysis.severity);
  const processingMs = Date.now() - startedAt;

  const persistResult = await track('AUDIT_RECORD', () =>
    store.saveAuditRecord({
      scan_id: scanId,
      source_type: request.source_type,
      filename: clampText(request.filename, 200),
      privacy_mode: privacy.effective_mode,
      detected_sensitive: scan.detectionCount,
      severity,
      risk_index: risk.index,
      findings_count: analysis.detected_vulnerabilities.length,
      summary: clampText(analysis.summary, 2000),
      findings: analysis.detected_vulnerabilities,
      remediation_status: remediation.status,
      remediation_diff: remediation.diff,
      ai_status: aiMeta.status,
      ai_model: aiMeta.model,
      ai_latency_ms: aiMeta.latency_ms,
      processing_ms: processingMs,
      analysis_mode: aiMeta.status === 'live' ? 'live' : 'mock_fallback',
    })
  );

  return {
    scan_id: scanId,
    created_at: new Date().toISOString(),
    source_type: request.source_type,
    filename: request.filename || 'untitled',
    privacy: {
      requested_mode: privacy.requested_mode,
      effective_mode: privacy.effective_mode,
      show_opt_in: privacy.show_opt_in,
      detected_sensitive: scan.detectionCount,
      detections: scan.detections,
      injection_indicators: scan.injections,
      warning: privacy.warning,
    },
    sanitized_payload: sanitized.slice(0, MAX_CONTENT_CHARS),
    analysis: {
      schema_version: analysis.schema_version,
      severity,
      summary: analysis.summary,
      detected_vulnerabilities: analysis.detected_vulnerabilities,
      risk_analysis: analysis.risk_analysis,
      compliance_status: analysis.compliance_status,
    },
    risk: { ...risk, band: riskBand(risk.index) },
    remediation,
    ai: aiMeta,
    workflow: stages,
    policy_overrides: policyOverrides,
    leak_prevented: leakPrevented,
    persistence: persistResult,
    demo_mode: demoMode,
    processing_ms: processingMs,
  };
}

export { WORKFLOW_STAGES };
