/**
 * Pyzex Guard — central configuration.
 *
 * All configuration is read from the environment at call time (never frozen at
 * import time) so that tests can exercise different privacy/provider states.
 *
 * Secrets are never exported as printable values by the health endpoint or
 * logs; accessors here are internal to the server process.
 */
import 'dotenv/config';

export const APP = Object.freeze({
  name: 'pyzex-guard',
  version: '1.0.0',
  vendor: 'PIXZ.DEV',
  author: 'Muhammad Rafif Rianto',
});

/** Maximum characters of scanned content accepted per request. */
export const MAX_CONTENT_CHARS = 65_536;

/** Maximum characters the AI payload preview shows per line / total. */
export const MAX_PREVIEW_CHARS = 8_000;

export function getPrivacyConfig(env = process.env) {
  return {
    sensitiveData: env.SENSITIVE_DATA,
    allowSensitiveDataToAi: env.ALLOW_SENSITIVE_DATA_TO_AI,
    demoMode: env.DEMO_MODE,
  };
}

export function isDemoMode(env = process.env) {
  return String(env.DEMO_MODE ?? 'true').trim().toLowerCase() === 'true';
}

export function getProviderConfig(env = process.env) {
  const baseUrl = String(env.WORKBUDDY_BASE_URL ?? '').trim().replace(/\/+$/, '');
  const apiKey = String(env.WORKBUDDY_API_KEY ?? '').trim();
  const model = String(env.WORKBUDDY_MODEL ?? '').trim();
  return {
    baseUrl,
    apiKey,
    model,
    configured: Boolean(baseUrl && apiKey && model),
  };
}

export function getDatabaseUrl(env = process.env) {
  const url = String(env.DATABASE_URL ?? '').trim();
  // Neon PostgreSQL only — anything else (e.g. internal file: URIs) is treated
  // as "not configured" so persistence fails safe instead of erroring loudly.
  if (!/^postgres(ql)?:\/\//i.test(url)) return '';
  return url;
}
