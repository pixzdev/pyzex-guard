/**
 * Pyzex Guard — sanitized audit store (Neon PostgreSQL, serverless-ready).
 *
 * Design rules:
 *  - Parameterized queries only (neon() tagged templates).
 *  - Raw scanned content is NEVER accepted as a column value; callers pass
 *    the already-sanitized record. A final defensive scrub runs here anyway.
 *  - A missing or non-PostgreSQL DATABASE_URL means persistence is inactive
 *    — the application keeps working and reports the state honestly.
 */
import { neon } from '@neondatabase/serverless';
import { getDatabaseUrl } from './config.js';
import { scrubText } from './redactor.js';

export function createAuditStore({ sql = null, reason = null } = {}) {
  const state = { sql, lastError: null };

  const scrubRecord = (record) => ({
    ...record,
    filename: scrubText(String(record.filename ?? '')),
    summary: scrubText(String(record.summary ?? '')),
    remediation_diff: record.remediation_diff ? scrubText(String(record.remediation_diff)) : null,
    findings: typeof record.findings === 'string' ? scrubText(record.findings) : JSON.stringify(record.findings ?? []),
  });

  async function saveAuditRecord(record) {
    if (!state.sql) {
      return { persisted: false, reason: state.lastError ? 'DB_INIT_FAILED' : 'DATABASE_URL_NOT_SET' };
    }
    const clean = scrubRecord(record);
    try {
      await state.sql`
        INSERT INTO scan_audit (
          scan_id, source_type, filename, privacy_mode, detected_sensitive,
          severity, risk_index, findings_count, summary, findings,
          remediation_status, remediation_diff, ai_status, ai_model,
          ai_latency_ms, processing_ms, analysis_mode
        ) VALUES (
          ${clean.scan_id}, ${clean.source_type}, ${clean.filename}, ${clean.privacy_mode},
          ${clean.detected_sensitive}, ${clean.severity}, ${clean.risk_index},
          ${clean.findings_count}, ${clean.summary}, ${clean.findings}::jsonb,
          ${clean.remediation_status}, ${clean.remediation_diff}, ${clean.ai_status},
          ${clean.ai_model}, ${clean.ai_latency_ms}, ${clean.processing_ms}, ${clean.analysis_mode}
        )
        ON CONFLICT (scan_id) DO NOTHING
      `;
      return { persisted: true };
    } catch (err) {
      state.lastError = String(err?.message ?? 'db error').slice(0, 200);
      return { persisted: false, reason: 'DB_WRITE_FAILED' };
    }
  }

  async function getHistory(limit = 10) {
    if (!state.sql) {
      return { persistence_active: false, reason: 'DATABASE_URL_NOT_SET', records: [] };
    }
    const safeLimit = Math.min(Math.max(Number.parseInt(limit, 10) || 10, 1), 25);
    try {
      const rows = await state.sql`
        SELECT
          scan_id, created_at, source_type, filename, privacy_mode,
          detected_sensitive, severity, risk_index, findings_count, summary,
          remediation_status, ai_status, ai_model, ai_latency_ms, processing_ms,
          analysis_mode
        FROM scan_audit
        ORDER BY created_at DESC
        LIMIT ${safeLimit}
      `;
      return { persistence_active: true, records: rows };
    } catch (err) {
      state.lastError = String(err?.message ?? 'db error').slice(0, 200);
      return { persistence_active: false, reason: 'DB_READ_FAILED', records: [] };
    }
  }

  async function ping() {
    if (!state.sql) return { active: false, reason: 'DATABASE_URL_NOT_SET' };
    try {
      await state.sql`SELECT 1`;
      return { active: true, reason: null };
    } catch (err) {
      state.lastError = String(err?.message ?? 'db error').slice(0, 200);
      return { active: false, reason: 'DB_UNREACHABLE' };
    }
  }

  function status() {
    return {
      configured: Boolean(state.sql),
      last_error: state.lastError,
    };
  }

  return { saveAuditRecord, getHistory, ping, status };
}

/** Default store bound to DATABASE_URL (cached; safe to call repeatedly). */
let defaultStore = null;
export function getDefaultAuditStore() {
  if (defaultStore) return defaultStore;
  const url = getDatabaseUrl();
  if (!url) {
    defaultStore = createAuditStore({ sql: null });
  } else {
    try {
      defaultStore = createAuditStore({ sql: neon(url) });
    } catch {
      defaultStore = createAuditStore({ sql: null, reason: 'DB_INIT_FAILED' });
    }
  }
  return defaultStore;
}

/** Test seam: reset the cached default store. */
export function resetDefaultAuditStore() {
  defaultStore = null;
}
