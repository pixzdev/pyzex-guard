/**
 * Pyzex Guard — deterministic server-side risk engine (PYGUARD core).
 *
 * The risk index is computed by the APPLICATION from validated findings —
 * never taken from the model's own opinion of severity beyond the per-finding
 * classification that has already passed schema + policy validation.
 *
 * This is an application-defined triage indicator, NOT an industry-standard
 * security rating.
 */

export const SEVERITY_WEIGHTS = Object.freeze({
  critical: 40,
  high: 25,
  medium: 12,
  low: 4,
  none: 0,
});

const SEVERITY_RANK = Object.freeze(['none', 'low', 'medium', 'high', 'critical']);

export function computeRiskIndex(findings) {
  const breakdown = {};
  let sum = 0;
  for (const finding of findings ?? []) {
    const weight = SEVERITY_WEIGHTS[finding?.severity] ?? 0;
    if (weight > 0) {
      breakdown[finding.severity] = (breakdown[finding.severity] ?? 0) + weight;
      sum += weight;
    }
  }
  return {
    index: Math.min(100, sum),
    breakdown,
    note: 'Application-defined triage indicator — not an industry-standard security rating.',
  };
}

export function overallSeverity(findings, fallback = 'none') {
  let rank = SEVERITY_RANK.indexOf(fallback);
  for (const finding of findings ?? []) {
    const idx = SEVERITY_RANK.indexOf(finding?.severity);
    if (idx > rank) rank = idx;
  }
  return SEVERITY_RANK[rank] ?? fallback;
}

export function riskBand(index) {
  if (index >= 75) return 'critical';
  if (index >= 50) return 'elevated';
  if (index >= 25) return 'moderate';
  return 'low';
}
