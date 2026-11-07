/**
 * Pyzex Guard — Express application factory.
 *
 * The same app instance serves local development (server.js) and the Vercel
 * serverless function (api/index.js). Route handlers never log request
 * bodies, and error output is scrubbed before logging.
 */
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

import { APP, MAX_CONTENT_CHARS, isDemoMode, getProviderConfig, getDatabaseUrl } from './config.js';
import { resolvePrivacy, scrubText } from './redactor.js';
import { providerHealth } from './ai-provider.js';
import { runSecurityPipeline, RequestValidationError } from './pipeline.js';
import { ProviderError } from './ai-provider.js';
import { PRESETS } from './presets.js';
import { getDefaultAuditStore } from './audit-store.js';
import { scanContent } from './redactor.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(__dirname, '..', 'public');

const VERSION = APP.version;

/* ------------------------------------------------------------------ */
/* Structured logging — never includes bodies or secret material       */
/* ------------------------------------------------------------------ */
function logEvent(level, msg, meta = {}) {
  const safeMeta = {};
  for (const [key, value] of Object.entries(meta)) {
    safeMeta[key] = typeof value === 'string' ? scrubText(value).slice(0, 300) : value;
  }
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...safeMeta }));
}

/* ------------------------------------------------------------------ */
/* Rate limiters                                                       */
/* ------------------------------------------------------------------ */
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: { code: 'RATE_LIMITED', message: 'Too many requests. Please retry later.' } },
});

const scanLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: { code: 'RATE_LIMITED', message: 'Scan rate limit reached (30 per 5 minutes). Please retry later.' },
  },
});

const previewLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: { code: 'RATE_LIMITED', message: 'Preview rate limit reached. Please retry later.' },
  },
});

/* ------------------------------------------------------------------ */
/* App factory                                                         */
/* ------------------------------------------------------------------ */
export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com', 'https://unpkg.com'],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com', 'https://fonts.googleapis.com'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com'],
          imgSrc: ["'self'", 'data:'],
          connectSrc: ["'self'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          frameAncestors: ["'self'"],
        },
      },
      crossOriginEmbedderPolicy: false,
    })
  );
  app.use(cors());
  app.use(express.json({ limit: '160kb' }));

  // Request log: method, path, status, duration — bodies are never logged.
  app.use((req, res, next) => {
    const started = Date.now();
    res.on('finish', () => {
      logEvent('info', 'http', {
        method: req.method,
        path: req.path,
        status: res.statusCode,
        ms: Date.now() - started,
      });
    });
    next();
  });

  const api = express.Router();
  api.use(globalLimiter);

  /* ------------------------------ health ------------------------------ */
  api.get('/health', async (req, res) => {
    const store = getDefaultAuditStore();
    let dbActive = { active: false, reason: 'DATABASE_URL_NOT_SET' };
    if (getDatabaseUrl()) {
      dbActive = await store.ping();
    }
    res.json({
      status: 'ok',
      service: APP.name,
      version: VERSION,
      time: new Date().toISOString(),
      privacy: resolvePrivacy(),
      demo_mode: isDemoMode(),
      ai_provider: providerHealth(),
      database: {
        configured: Boolean(getDatabaseUrl()),
        active: dbActive.active,
        reason: dbActive.reason,
      },
      limits: {
        max_content_chars: MAX_CONTENT_CHARS,
        scan_rate_limit: '30 requests / 5 minutes',
      },
    });
  });

  /* ------------------------------ presets ----------------------------- */
  api.get('/presets', (req, res) => {
    res.json({
      presets: PRESETS.map((p) => ({
        id: p.id,
        label_en: p.label_en,
        label_id: p.label_id,
        description_en: p.description_en,
        description_id: p.description_id,
        source_type: p.source_type,
        filename: p.filename,
        content: p.content,
      })),
      note: 'All preset credential values are synthetic and non-functional.',
    });
  });

  /* ------------------------------ preview ----------------------------- */
  // Local-only privacy preview: exactly what the AI stage would receive.
  // No AI call, no persistence, no body logging.
  api.post('/preview', previewLimiter, (req, res, next) => {
    try {
      const body = req.body ?? {};
      const content = typeof body.content === 'string' ? body : null;
      if (!content) {
        return res.status(400).json({ error: { code: 'INVALID_REQUEST', message: 'content (string) is required.' } });
      }
      if (content.content.length > MAX_CONTENT_CHARS) {
        return res.status(413).json({
          error: { code: 'PAYLOAD_TOO_LARGE', message: `content exceeds ${MAX_CONTENT_CHARS} characters.` },
        });
      }
      const privacy = resolvePrivacy();
      const scanned = scanContent(content.content, { mode: privacy.effective_mode });
      res.json({
        privacy: {
          requested_mode: privacy.requested_mode,
          effective_mode: privacy.effective_mode,
          show_opt_in: privacy.show_opt_in,
          warning: privacy.warning,
          detected_sensitive: scanned.detectionCount,
          detections: scanned.detections,
          injection_indicators: scanned.injections,
        },
        sanitized_payload: scanned.sanitized,
      });
    } catch (err) {
      next(err);
    }
  });

  /* ------------------------------- scan ------------------------------- */
  api.post('/scan', scanLimiter, async (req, res, next) => {
    try {
      const result = await runSecurityPipeline(req.body);
      res.json(result);
    } catch (err) {
      if (err instanceof RequestValidationError) {
        return res.status(err.status).json({
          error: { code: err.code, message: err.message, issues: err.issues },
        });
      }
      if (err instanceof ProviderError) {
        logEvent('warn', 'provider_error', { code: err.code, detail: err.detail ?? '' });
        return res.status(err.status ?? 503).json({
          error: { code: err.code, message: err.message },
        });
      }
      next(err);
    }
  });

  /* ------------------------------ history ----------------------------- */
  api.get('/history', async (req, res, next) => {
    try {
      const store = getDefaultAuditStore();
      const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 10, 1), 25);
      const result = await store.getHistory(limit);
      res.json({
        persistence_active: result.persistence_active,
        reason: result.reason ?? null,
        records: result.records,
      });
    } catch (err) {
      next(err);
    }
  });

  app.use('/api', api);
  app.use('/api', (req, res) => {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: `Unknown API route: ${req.method} ${req.path}` } });
  });

  /* --------------------------- static assets -------------------------- */
  if (fs.existsSync(PUBLIC_DIR)) {
    app.use(express.static(PUBLIC_DIR, { index: 'index.html' }));
    app.get(/^\/(?!api(\/|$)).*/, (req, res) => {
      res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
    });
  }

  /* --------------------------- error handler -------------------------- */
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err?.type === 'entity.too.large' || err?.statusCode === 413) {
      return res.status(413).json({
        error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body exceeds the accepted size.' },
      });
    }
    if (err instanceof SyntaxError && 'body' in err) {
      return res.status(400).json({
        error: { code: 'INVALID_JSON', message: 'Request body is not valid JSON.' },
      });
    }
    const errorId = crypto.randomUUID();
    logEvent('error', 'unhandled_error', { error_id: errorId, message: scrubText(String(err?.message ?? '')) });
    res.status(500).json({
      error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred.', error_id: errorId },
    });
  });

  return app;
}
