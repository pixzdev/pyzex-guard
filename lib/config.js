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

/**
 * Provider registry — the hackathon sponsor default is SumoPod's
 * OpenAI-compatible GLM endpoint. Any other OpenAI-compatible inference
 * endpoint (including Tencent Cloud deployments such as TI-ONE or a Hunyuan
 * gateway) plugs in through its own profile without code changes.
 *
 * Selection: AI_PROVIDER pins a profile (sumopod | tencent | custom).
 * With AI_PROVIDER=auto (default) the first fully configured profile wins.
 * Only variable NAMES are fixed here; every value comes from the environment.
 */
export const PROVIDER_PROFILES = Object.freeze({
  sumopod: Object.freeze({
    id: 'sumopod',
    label: 'SumoPod (hackathon sponsor)',
    baseUrlEnv: 'SUMOPOD_BASE_URL',
    apiKeyEnv: 'SUMOPOD_API_KEY',
    modelEnv: 'SUMOPOD_MODEL',
    defaultBaseUrl: 'https://ai.sumopod.com/v1',
    defaultModel: 'glm-5.3-flash',
  }),
  tencent: Object.freeze({
    id: 'tencent',
    label: 'Tencent Cloud (OpenAI-compatible inference, e.g. TI-ONE / Hunyuan gateway)',
    baseUrlEnv: 'TENCENT_BASE_URL',
    apiKeyEnv: 'TENCENT_API_KEY',
    modelEnv: 'TENCENT_MODEL',
    defaultBaseUrl: '',
    defaultModel: '',
  }),
  custom: Object.freeze({
    id: 'custom',
    label: 'Custom OpenAI-compatible endpoint',
    baseUrlEnv: 'CUSTOM_BASE_URL',
    apiKeyEnv: 'CUSTOM_API_KEY',
    modelEnv: 'CUSTOM_MODEL',
    defaultBaseUrl: '',
    defaultModel: '',
  }),
});

function readProfile(env, profile) {
  const baseUrl = String(env[profile.baseUrlEnv] ?? profile.defaultBaseUrl ?? '')
    .trim()
    .replace(/\/+$/, '');
  const apiKey = String(env[profile.apiKeyEnv] ?? '').trim();
  const model = String(env[profile.modelEnv] ?? profile.defaultModel ?? '').trim();
  return {
    profile: profile.id,
    label: profile.label,
    baseUrl,
    apiKey,
    model,
    configured: Boolean(baseUrl && apiKey && model),
  };
}

export function getProviderConfig(env = process.env) {
  const requested = String(env.AI_PROVIDER ?? 'auto').trim().toLowerCase();
  const all = Object.values(PROVIDER_PROFILES).map((p) => readProfile(env, p));
  let candidates = all;
  if (requested !== 'auto' && PROVIDER_PROFILES[requested]) {
    candidates = all.filter((c) => c.profile === requested);
  }
  const active = candidates.find((c) => c.configured) ?? candidates[0] ?? all[0];
  return {
    ...active,
    requested,
    candidates: all.map(({ profile, label, baseUrl, model, configured }) => ({
      profile,
      label,
      base_url_configured: Boolean(baseUrl),
      model: model || null,
      configured,
    })),
  };
}

export function getDatabaseUrl(env = process.env) {
  const url = String(env.DATABASE_URL ?? '').trim();
  // Neon PostgreSQL only — anything else (e.g. internal file: URIs) is treated
  // as "not configured" so persistence fails safe instead of erroring loudly.
  if (!/^postgres(ql)?:\/\//i.test(url)) return '';
  return url;
}
