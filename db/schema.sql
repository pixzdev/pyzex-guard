-- ============================================================
-- Pyzex Guard — sanitized audit schema (Neon PostgreSQL)
--
-- IMPORTANT: this table stores SANITIZED metadata only.
-- Raw scanned content and raw credential values are never written.
-- All evidence excerpts are already redacted by the local redactor
-- before any row is inserted.
-- ============================================================

CREATE TABLE IF NOT EXISTS scan_audit (
  id                 BIGSERIAL PRIMARY KEY,
  scan_id            TEXT        NOT NULL UNIQUE,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  source_type        TEXT        NOT NULL,
  filename           TEXT        NOT NULL DEFAULT '',
  privacy_mode       TEXT        NOT NULL DEFAULT 'redact',
  detected_sensitive INTEGER     NOT NULL DEFAULT 0,
  severity           TEXT        NOT NULL,
  risk_index         INTEGER     NOT NULL DEFAULT 0,
  findings_count     INTEGER     NOT NULL DEFAULT 0,
  summary            TEXT        NOT NULL DEFAULT '',
  findings           JSONB       NOT NULL DEFAULT '[]'::jsonb,
  remediation_status TEXT        NOT NULL DEFAULT 'manual_review',
  remediation_diff   TEXT,
  ai_status          TEXT        NOT NULL,
  ai_model           TEXT,
  ai_latency_ms      INTEGER,
  processing_ms      INTEGER,
  analysis_mode      TEXT        NOT NULL DEFAULT 'live'
);

CREATE INDEX IF NOT EXISTS scan_audit_created_at_idx ON scan_audit (created_at DESC);
CREATE INDEX IF NOT EXISTS scan_audit_severity_idx   ON scan_audit (severity);
