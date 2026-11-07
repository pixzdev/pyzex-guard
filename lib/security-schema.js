/**
 * Pyzex Guard — strict request & AI-response validation schemas (zod).
 *
 * Two contracts live here:
 *   1. ScanRequestSchema  — what the dashboard is allowed to send.
 *   2. AIResponseSchema   — the ONLY shape the model may return. Anything
 *      that fails this schema is rejected (with one controlled recovery
 *      attempt at pipeline level) and never reaches the client raw.
 */
import { z } from 'zod';
import { MAX_CONTENT_CHARS } from './config.js';

export const SOURCE_TYPES = ['snippet', 'git_diff', 'config'];

export const ScanRequestSchema = z.object({
  source_type: z.enum(SOURCE_TYPES),
  filename: z
    .string()
    .trim()
    .max(200)
    .optional()
    .default(''),
  content: z
    .string()
    .min(1, 'content must not be empty')
    .max(MAX_CONTENT_CHARS, `content exceeds ${MAX_CONTENT_CHARS} characters`),
});

/* ------------------------------------------------------------------ */
/* AI response contract                                               */
/* ------------------------------------------------------------------ */

const SeverityEnum = z.enum(['critical', 'high', 'medium', 'low', 'none']);
const FindingSeverityEnum = z.enum(['critical', 'high', 'medium', 'low']);
const RemediationStatusEnum = z.enum(['auto_patch_proposed', 'manual_review', 'no_action_required']);
const ComplianceStatusEnum = z.enum(['review_required', 'not_assessed']);

const clampConfidence = (value) => {
  const num = typeof value === 'number' ? value : Number.parseFloat(value);
  if (!Number.isFinite(num)) return 0;
  return Math.min(1, Math.max(0, num));
};

const FindingSchema = z.object({
  id: z.string().min(1).max(40),
  category: z.string().min(1).max(60),
  severity: FindingSeverityEnum,
  title: z.string().min(1).max(200),
  description: z.string().max(2000).default(''),
  line: z.number().int().min(1).max(100000).nullable().optional().default(null),
  evidence_excerpt: z.string().max(600).default(''),
  risk_impact: z.string().max(2000).default(''),
  confidence: z
    .union([z.number(), z.string()])
    .transform(clampConfidence),
  remediation: z.string().max(2000).default(''),
  rotation_required: z.boolean().optional().default(false),
});

export const AIResponseSchema = z.object({
  schema_version: z.string().max(16).optional().default('1.0'),
  severity: SeverityEnum,
  summary: z.string().min(1).max(2000),
  detected_vulnerabilities: z.array(FindingSchema).max(20).optional().default([]),
  risk_analysis: z.string().max(4000).optional().default(''),
  auto_remediation_diff: z.string().max(16000).nullable().optional().default(null),
  remediation_status: RemediationStatusEnum.optional().default('manual_review'),
  compliance_status: z
    .object({
      status: ComplianceStatusEnum.optional().default('review_required'),
      frameworks: z.array(z.string().max(40)).max(10).optional().default([]),
      notes: z.string().max(1000).optional().default(''),
    })
    .optional()
    .default({ status: 'review_required', frameworks: [], notes: '' }),
  human_approval_required: z.boolean().optional().default(true),
});

export const DEFAULT_COMPLIANCE = Object.freeze({
  status: 'review_required',
  frameworks: [],
  notes: 'Preliminary automated assessment — not a compliance certification.',
});

/**
 * Pre-parse normalization: models frequently uppercase enums or send
 * stringified numbers. Normalize the known fields, then validate strictly.
 */
export function normalizeModelOutput(candidate) {
  if (candidate === null || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return candidate;
  }
  const out = { ...candidate };
  if (typeof out.severity === 'string') out.severity = out.severity.trim().toLowerCase();
  if (Array.isArray(out.detected_vulnerabilities)) {
    out.detected_vulnerabilities = out.detected_vulnerabilities.map((f) => {
      if (f && typeof f === 'object') {
        const copy = { ...f };
        if (typeof copy.severity === 'string') copy.severity = copy.severity.trim().toLowerCase();
        if (typeof copy.line === 'string') {
          const parsed = Number.parseInt(copy.line, 10);
          copy.line = Number.isFinite(parsed) ? parsed : null;
        }
        return copy;
      }
      return f;
    });
  }
  return out;
}

/** Extract a JSON object from raw model text (fences, prose, stray tokens). */
export function extractJson(rawText) {
  if (typeof rawText !== 'string' || !rawText.trim()) {
    throw new Error('empty response');
  }
  let text = rawText.trim();

  // 1) direct parse
  try {
    return JSON.parse(text);
  } catch {
    /* continue */
  }

  // 2) strip markdown code fences
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    try {
      return JSON.parse(fence[1].trim());
    } catch {
      /* continue */
    }
    text = fence[1].trim();
  }

  // 3) outermost braces
  const first = text.indexOf('{');
  const last = text.lastIndexOf('}');
  if (first !== -1 && last > first) {
    const candidate = text.slice(first, last + 1);
    try {
      return JSON.parse(candidate);
    } catch {
      // 4) controlled repair: trailing commas + control chars
      const repaired = candidate
        .replace(/,\s*([}\]])/g, '$1')
        // eslint-disable-next-line no-control-regex
        .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '');
      return JSON.parse(repaired);
    }
  }

  throw new Error('no JSON object found in model response');
}

/** Validate + normalize a raw model string. Throws on contract violation. */
export function parseModelOutput(rawText) {
  const candidate = normalizeModelOutput(extractJson(rawText));
  return AIResponseSchema.parse(candidate);
}
