/**
 * Pyzex Guard — deterministic mock analysis (DEMO MODE fallback).
 *
 * When the live provider is unavailable (or DEMO_MODE=true and the call
 * fails), Pyzex Guard presents a clearly-labeled MOCK FALLBACK. The mock is
 * NOT random filler: it is derived deterministically from the local PYSCAN
 * detections of the actual submitted material, so it always matches the
 * evidence. It passes through the exact same validation and policy gates as
 * a live response, and is never presented as live AI analysis.
 */
import { scrubText } from './redactor.js';

const TYPE_META = {
  PRIVATE_KEY: {
    severity: 'critical',
    category: 'private_key_exposure',
    title: 'Private key material embedded in source',
    impact: 'Anyone with this material can impersonate the key owner, sign malicious payloads, or access protected systems.',
    remediation: 'Remove the key from source, purge it from history, rotate the key pair, and load the new key from a secret manager.',
    rotation: true,
  },
  CLOUD_SECRET_KEY: {
    severity: 'critical',
    category: 'secret_exposure',
    title: 'Cloud secret key exposed in configuration',
    impact: 'A valid secret key grants programmatic control over the associated cloud account and its resources.',
    remediation: 'Move the value into a managed secret store, reference it via environment variables, and rotate the exposed key.',
    rotation: true,
  },
  CLOUD_SECRET_ID: {
    severity: 'high',
    category: 'secret_exposure',
    title: 'Cloud credential identifier exposed',
    impact: 'Combined with its secret counterpart, an exposed identifier enables unauthorized cloud API usage.',
    remediation: 'Keep identifiers in environment variables and rotate the credential pair if it was ever committed.',
    rotation: true,
  },
  DATABASE_CONNECTION_STRING: {
    severity: 'high',
    category: 'insecure_configuration',
    title: 'Database connection string contains embedded credentials',
    impact: 'Embedded usernames and passwords in connection strings leak database access to anyone who can read the file.',
    remediation: 'Read the connection string from an environment variable or secret manager; rotate the database password.',
    rotation: true,
  },
  JWT_SECRET: {
    severity: 'high',
    category: 'secret_exposure',
    title: 'JWT signing secret hardcoded in configuration',
    impact: 'Anyone holding the signing secret can mint fully valid tokens and impersonate any user or service.',
    remediation: 'Move the signing secret to a managed secret store, rotate it, and invalidate outstanding sessions.',
    rotation: true,
  },
  JWT_TOKEN: {
    severity: 'high',
    category: 'token_exposure',
    title: 'JWT token committed to source',
    impact: 'A live JWT can be replayed to impersonate a user or service until it expires.',
    remediation: 'Revoke the token, shorten token lifetimes, and load tokens at runtime instead of committing them.',
    rotation: true,
  },
  API_KEY: {
    severity: 'high',
    category: 'secret_exposure',
    title: 'API key hardcoded in source',
    impact: 'Hardcoded API keys allow unauthorized quota usage and data access if the repository is shared or leaked.',
    remediation: 'Move the key to an environment variable, restrict its scopes, and rotate the exposed key.',
    rotation: true,
  },
  API_SECRET: {
    severity: 'high',
    category: 'secret_exposure',
    title: 'Application secret hardcoded in source',
    impact: 'Signing or client secrets in source let attackers forge trusted artifacts such as session tokens.',
    remediation: 'Load the secret from environment configuration and rotate the exposed value.',
    rotation: true,
  },
  ACCESS_TOKEN: {
    severity: 'high',
    category: 'token_exposure',
    title: 'Access token exposed in source',
    impact: 'Exposed tokens can be replayed against the issuing service until revoked.',
    remediation: 'Revoke the token and fetch it at runtime from a secret manager.',
    rotation: true,
  },
  AUTHORIZATION_HEADER: {
    severity: 'high',
    category: 'token_exposure',
    title: 'Authorization header value captured in source',
    impact: 'Captured bearer credentials allow session hijacking or API impersonation.',
    remediation: 'Remove captured header values and revoke the underlying credential.',
    rotation: true,
  },
  PASSWORD: {
    severity: 'medium',
    category: 'insecure_configuration',
    title: 'Password assigned directly in configuration',
    impact: 'Plainly assigned passwords are easy to leak via repositories, logs, and process listings.',
    remediation: 'Reference the password through environment variables and rotate it if previously shared.',
    rotation: true,
  },
  HIGH_ENTROPY_CANDIDATE: {
    severity: 'medium',
    category: 'secret_exposure',
    title: 'High-entropy string assigned near credential-related context',
    impact: 'High-entropy values near key-like names are frequently real credentials.',
    remediation: 'Verify the value, move it to a secret manager if sensitive, and rotate if exposed.',
    rotation: false,
  },
  PROMPT_INJECTION: {
    severity: 'medium',
    category: 'prompt_injection',
    title: 'Prompt-injection attempt detected inside scanned material',
    impact: 'Instruction-like content in scanned data tries to hijack automated agents; it is treated strictly as untrusted data.',
    remediation: 'Review the source of this content and keep agent guardrails (untrusted-data fencing, output validation, forced human approval) enabled.',
    rotation: false,
  },
};

const SEVERITY_RANK = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

function toEnvRef(keyName, sourceType) {
  const upper = String(keyName || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toUpperCase();
  if (sourceType === 'snippet' || sourceType === 'git_diff') {
    return `process.env.${upper.replace(/[^A-Z0-9_]/g, '_') || 'SECRET_VALUE'}`;
  }
  return `\${${upper || 'SECRET_VALUE'}}`;
}

function buildMockDiff(sanitized, detections, filename, sourceType) {
  if (!detections.length) return null;
  const lines = sanitized.split('\n');
  const detectedLines = new Set(detections.map((d) => d.line));

  const output = [];
  output.push(`--- a${filename ? '/' + filename : '/scanned-source'}`);
  output.push(`+++ b${filename ? '/' + filename : '/scanned-source'}`);

  // Group contiguous detected lines into hunks with one line of context.
  let hunkStart = -1;
  let hunkLines = [];
  const flushHunk = () => {
    if (hunkStart === -1) return;
    const ctxBefore = Math.max(1, hunkStart - 1);
    const ctxAfter = Math.min(lines.length, hunkStart + hunkLines.length);
    const oldCount = ctxAfter - ctxBefore + 1;
    output.push(`@@ -${ctxBefore},${oldCount} +${ctxBefore},${oldCount} @@`);
    for (let i = ctxBefore; i <= ctxAfter; i++) {
      const lineText = lines[i - 1] ?? '';
      if (detectedLines.has(i)) {
        const detection = detections.find((d) => d.line === i);
        output.push(`-${lineText}`);
        output.push(
          `+${lineText.replace(/\[REDACTED:[A-Z_]+\]|\[SENSITIVE_VALUE_REMOVED\]/, toEnvRef(detection?.key_name, sourceType))}`
        );
      } else {
        output.push(` ${lineText}`);
      }
    }
    hunkStart = -1;
    hunkLines = [];
  };

  for (let i = 1; i <= lines.length; i++) {
    if (detectedLines.has(i)) {
      if (hunkStart === -1) hunkStart = i;
      hunkLines.push(i);
    } else {
      flushHunk();
    }
  }
  flushHunk();
  return output.join('\n').slice(0, 4000);
}

/** Defence in depth: scrub every string value in a structured result. */
function deepScrub(value, depth = 0) {
  if (depth > 6) return value;
  if (typeof value === 'string') return scrubText(value);
  if (Array.isArray(value)) return value.map((item) => deepScrub(item, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) out[key] = deepScrub(item, depth + 1);
    return out;
  }
  return value;
}

/**
 * Build a fully schema-compatible mock analysis from local detections.
 * Everything is passed through scrubText as defence in depth.
 */
export function buildMockAnalysis({ sanitized, detections, injections, filename, sourceType }) {
  const findings = [];
  let seq = 0;

  for (const detection of detections) {
    const meta = TYPE_META[detection.type] ?? TYPE_META.HIGH_ENTROPY_CANDIDATE;
    seq += 1;
    const evidenceLine = (sanitized.split('\n')[detection.line - 1] ?? '').trim().slice(0, 200);
    findings.push({
      id: `PG-${String(seq).padStart(3, '0')}`,
      category: meta.category,
      severity: meta.severity,
      title: `${meta.title} (${detection.key_name})`,
      description: `${meta.title} — detected by local PYSCAN rule "${detection.rule}" on line ${detection.line}.`,
      line: detection.line,
      evidence_excerpt: evidenceLine,
      risk_impact: meta.impact,
      confidence: 0.9,
      remediation: meta.remediation,
      rotation_required: meta.rotation,
    });
  }

  for (const injection of injections.slice(0, 3)) {
    seq += 1;
    findings.push({
      id: `PG-${String(seq).padStart(3, '0')}`,
      category: TYPE_META.PROMPT_INJECTION.category,
      severity: TYPE_META.PROMPT_INJECTION.severity,
      title: TYPE_META.PROMPT_INJECTION.title,
      description: `Untrusted instruction-like content was found on line ${injection.line}. It was transmitted to the AI stage fenced as data only.`,
      line: injection.line,
      evidence_excerpt: injection.phrase,
      risk_impact: TYPE_META.PROMPT_INJECTION.impact,
      confidence: 0.75,
      remediation: TYPE_META.PROMPT_INJECTION.remediation,
      rotation_required: false,
    });
  }

  const severity =
    findings.length === 0
      ? 'none'
      : findings.reduce(
          (acc, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[acc] ? f.severity : acc),
          'none'
        );

  const hasSecrets = detections.length > 0;
  const summary =
    findings.length === 0
      ? 'Local PYSCAN scanning found no obvious sensitive values or injection attempts in the submitted material. A clean sample does not prove the application is secure.'
      : `Local PYSCAN scanning identified ${detections.length} sensitive value${detections.length === 1 ? '' : 's'}${
          injections.length ? ` and ${injections.length} prompt-injection indicator${injections.length === 1 ? '' : 's'}` : ''
        } in the submitted material.`;

  const diff = hasSecrets ? buildMockDiff(sanitized, detections, filename, sourceType) : null;

  const analysis = {
    schema_version: '1.0',
    severity,
    summary,
    detected_vulnerabilities: findings,
    risk_analysis:
      findings.length === 0
        ? 'No actionable exposure was found by deterministic local analysis. This is not a guarantee of security.'
        : 'Deterministic local analysis matched known credential and configuration patterns. Each finding below cites its redacted evidence; severities follow the Pyzex Guard triage weights.',
    auto_remediation_diff: diff,
    remediation_status: findings.length === 0 ? 'no_action_required' : diff ? 'auto_patch_proposed' : 'manual_review',
    compliance_status: {
      status: findings.length === 0 ? 'not_assessed' : 'review_required',
      frameworks: [],
      notes: 'Preliminary automated assessment — not a compliance certification.',
    },
    human_approval_required: findings.length > 0,
  };
  return deepScrub(analysis);
}
