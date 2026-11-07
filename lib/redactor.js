/**
 * Pyzex Guard — local secret detection & redaction engine (PYSCAN core).
 *
 * This module runs entirely server-side BEFORE any external AI call.
 * It never persists, logs, or transmits original sensitive values: detection
 * results only ever contain the KEY NAME, the credential TYPE and the LINE
 * NUMBER — never the value itself.
 *
 * Privacy modes (see resolvePrivacy):
 *   redact → replace values with typed placeholders   [REDACTED:API_KEY]
 *   hide   → replace values with a generic marker     [SENSITIVE_VALUE_REMOVED]
 *   show   → pass original values (requires double opt-in at env level)
 */

export const MODES = Object.freeze({
  HIDE: 'hide',
  REDACT: 'redact',
  SHOW: 'show',
});

export const HIDE_MARKER = '[SENSITIVE_VALUE_REMOVED]';
export const LEAK_MARKER = '[REDACTED:LEAK_PREVENTED]';

const redactToken = (type) => `[REDACTED:${type}]`;

/* ------------------------------------------------------------------ */
/* Key-name classification                                             */
/* ------------------------------------------------------------------ */

const KEY_CLASSIFIERS = [
  { re: /(database|db|mongo|redis|postgres|mysql)[._-]?url/i, type: 'DATABASE_CONNECTION_STRING' },
  { re: /jwt[._-]?secret/i, type: 'JWT_SECRET' },
  { re: /(secret_?id|access_?key_?id)/i, type: 'CLOUD_SECRET_ID' },
  { re: /(secret_?access_?key|secret_?key)/i, type: 'CLOUD_SECRET_KEY' },
  { re: /private[._-]?key/i, type: 'PRIVATE_KEY' },
  { re: /(api[._-]?key|apikey)/i, type: 'API_KEY' },
  { re: /(auth[._-]?)?token/i, type: 'ACCESS_TOKEN' },
  { re: /(password|passwd|pwd)/i, type: 'PASSWORD' },
  { re: /(secret|credential)/i, type: 'API_SECRET' },
  { re: /(authorization|auth)/i, type: 'AUTHORIZATION_HEADER' },
];

const SENSITIVE_KEY_RE =
  /(secret|token|password|passwd|pwd|api[._-]?key|apikey|credential|private[._-]?key|access[._-]?key|authorization)/i;

function classifyKeyName(name) {
  for (const c of KEY_CLASSIFIERS) {
    if (c.re.test(name)) return c.type;
  }
  return 'SENSITIVE_VALUE';
}

/* ------------------------------------------------------------------ */
/* Format-specific detectors (checked for every character position)     */
/* ------------------------------------------------------------------ */

// scheme://user:password@host  — credentials inside a connection string.
const URL_CREDS_RE =
  /\b((?:postgres(?:ql)?|mysql|maria|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql):\/\/)([^\s:@/'"<>]{1,128}):([^\s@/'"<>]{1,256})@/gi;

const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g;

const BEARER_RE = /\b((?:authorization)["']?\s*[:=]\s*(?:bearer\s+)?["']?)([A-Za-z0-9._~+/=-]{16,})/gi;

const PRIVATE_KEY_RE =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----/g;

const TOKEN_FORMATS = [
  { re: /\bAKIA[0-9A-Z]{16}\b/g, type: 'CLOUD_SECRET_ID', keyName: 'AWS_ACCESS_KEY_ID' },
  { re: /\bAKID[A-Za-z0-9]{13,63}\b/g, type: 'CLOUD_SECRET_ID', keyName: 'TENCENT_SECRET_ID' },
  { re: /\bgh[pousr]_[A-Za-z0-9]{30,255}\b/g, type: 'ACCESS_TOKEN', keyName: 'GITHUB_TOKEN' },
  { re: /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g, type: 'ACCESS_TOKEN', keyName: 'GITHUB_PAT' },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,250}\b/g, type: 'ACCESS_TOKEN', keyName: 'SLACK_TOKEN' },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/g, type: 'API_KEY', keyName: 'GOOGLE_API_KEY' },
  { re: /\bsk-(?:test|live)-[A-Za-z0-9]{16,247}\b/g, type: 'API_KEY', keyName: 'STRIPE_SECRET_KEY' },
  { re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,250}\b/g, type: 'API_KEY', keyName: 'API_KEY' },
  { re: /\bglpat-[A-Za-z0-9_-]{20,250}\b/g, type: 'ACCESS_TOKEN', keyName: 'GITLAB_PAT' },
];

/* ------------------------------------------------------------------ */
/* Assignment detection (env files, code, YAML, JSON)                  */
/* ------------------------------------------------------------------ */

const ASSIGN_LINE_RE =
  /^\s*(?:export\s+)?(?:const|let|var|readonly|pub(?:lic)?\s+static\s+final\s+)?["'`]?([A-Za-z_][A-Za-z0-9_.-]{0,64})["'`]?\s*(:=|=|:)\s*(.+?)\s*,?\s*$/;

/**
 * Values that must NOT be treated as secrets: interpolation placeholders,
 * environment lookups and trivial literals. This keeps false positives low
 * while still detecting obviously-fake demo credentials (which mimic the
 * shape of real ones).
 */
function isRedactableValue(rawValue) {
  if (rawValue.length < 6 || rawValue.length > 4096) return false;
  if (/\s/.test(rawValue)) return false;
  if (/^\$\{[^}]*\}$/.test(rawValue)) return false;          // ${VAR}
  if (/^\$[A-Za-z_][A-Za-z0-9_]*$/.test(rawValue)) return false; // $VAR
  if (/^\{\{[^}]*\}\}$/.test(rawValue)) return false;        // {{VAR}}
  if (/^<[^<>]*>$/.test(rawValue)) return false;             // <your-key-here>
  if (/^\[(?:REDACTED|SENSITIVE_VALUE)[^\]]*\]$/.test(rawValue)) return false; // already-redacted markers
  if (/^-----BEGIN [A-Z0-9 ]*-----$/.test(rawValue)) return false;
  if (/^(process\.env|os\.environ|getenv\s*\(|System\.getenv|env\[|config\s*\()/i.test(rawValue)) return false;
  if (/^(null|none|true|false|undefined|yes|no|on|off)$/i.test(rawValue)) return false;
  if (/^[.,;:/\\|_*#-]+$/.test(rawValue)) return false;
  return true;
}

function stripQuotes(value) {
  const q = value[0];
  if ((q === '"' || q === "'" || q === '`') && value.length > 1 && value.endsWith(q)) {
    return value.slice(1, -1);
  }
  return value;
}

/* ------------------------------------------------------------------ */
/* Prompt-injection probes (threat indicators, NOT redacted)           */
/* ------------------------------------------------------------------ */

const INJECTION_RES = [
  /\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+instructions\b/i,
  /\bdisregard\s+(?:all\s+|any\s+)?(?:previous|prior|above)?\s*instructions\b/i,
  /\breveal\s+(?:your|the|its)\s+(?:system\s+)?(?:prompt|instructions)\b/i,
  /\byou\s+are\s+now\s+(?:a|an|the)\b/i,
  /\bact\s+as\s+(?:an?\s+)?(?:admin|root|system|developer|engineer)\b/i,
  /\bauto[-]?(?:approve|deploy|apply)\b/i,
  /\bdisable\s+human\s+(?:approval|review)\b/i,
  /\b(?:system|developer)\s+mode\s*(?::|enabled)\b/i,
];

export function detectInjections(content, limit = 3) {
  const out = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length && out.length < limit; i++) {
    for (const re of INJECTION_RES) {
      const m = lines[i].match(re);
      if (m) {
        out.push({ line: i + 1, phrase: m[0].slice(0, 80) });
        break; // one indicator per line is enough
      }
    }
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Core detection                                                      */
/* ------------------------------------------------------------------ */

function lineOf(content, index) {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

/**
 * Detect sensitive material and return a non-overlapping, ordered match list.
 * Matches never contain the raw value outside this function's scope.
 */
export function detect(content) {
  const matches = [];
  const push = (start, end, type, keyName, rule) => {
    if (start < 0 || end <= start || end > content.length) return;
    matches.push({ start, end, type, keyName, rule, line: lineOf(content, start) });
  };

  // 0) Private key blocks (multiline, highest priority)
  let m;
  const pkRe = new RegExp(PRIVATE_KEY_RE.source, 'g');
  while ((m = pkRe.exec(content)) !== null) {
    push(m.index, m.index + m[0].length, 'PRIVATE_KEY', 'PRIVATE_KEY_BLOCK', 'private_key');
  }

  // 1) Assignments with sensitive key names (line-based, earliest per line)
  const lines = content.split('\n');
  let offset = 0;
  for (const lineText of lines) {
    const am = lineText.match(ASSIGN_LINE_RE);
    if (am && SENSITIVE_KEY_RE.test(am[1])) {
      const rawValue = stripQuotes(am[3].trim());
      if (isRedactableValue(rawValue)) {
        const valueIdxInLine = lineText.indexOf(am[3]);
        if (valueIdxInLine !== -1) {
          push(
            offset + valueIdxInLine,
            offset + valueIdxInLine + am[3].length,
            classifyKeyName(am[1]),
            am[1],
            'assignment'
          );
        }
      }
    }
    offset += lineText.length + 1;
  }

  // 2) Connection-string credentials
  const urlRe = new RegExp(URL_CREDS_RE.source, 'gi');
  while ((m = urlRe.exec(content)) !== null) {
    const creds = m[0].slice(m[1].length, -1); // "user:password" without the '@'
    if (creds.includes('[REDACTED') || creds.includes('SENSITIVE_VALUE_REMOVED')) {
      continue; // already-redacted URL — never re-detect our own markers
    }
    // cover "user:password@" — from end of scheme to the trailing '@'
    const credsStart = m.index + m[1].length;
    const credsEnd = m.index + m[0].length - 1; // exclude '@'
    push(credsStart, credsEnd, 'DATABASE_CONNECTION_STRING', 'CONNECTION_URL', 'url');
  }

  // 3) JWT-shaped tokens
  const jwtRe = new RegExp(JWT_RE.source, 'g');
  while ((m = jwtRe.exec(content)) !== null) {
    push(m.index, m.index + m[0].length, 'JWT_TOKEN', 'JWT', 'jwt');
  }

  // 4) Authorization / Bearer headers
  const bearerRe = new RegExp(BEARER_RE.source, 'gi');
  while ((m = bearerRe.exec(content)) !== null) {
    const tokenStart = m.index + m[1].length;
    push(tokenStart, tokenStart + m[2].length, 'AUTHORIZATION_HEADER', 'AUTHORIZATION', 'auth_header');
  }

  // 5) Well-known token formats
  for (const tf of TOKEN_FORMATS) {
    const re = new RegExp(tf.re.source, 'g');
    while ((m = re.exec(content)) !== null) {
      push(m.index, m.index + m[0].length, tf.type, tf.keyName, 'token_format');
    }
  }

  // Resolve overlaps: earliest match wins; longer/earlier rules take priority.
  matches.sort((a, b) => a.start - b.start || b.end - a.end);
  const kept = [];
  let lastEnd = -1;
  for (const cand of matches) {
    if (cand.start >= lastEnd) {
      kept.push(cand);
      lastEnd = cand.end;
    }
  }
  return kept;
}

/* ------------------------------------------------------------------ */
/* Public scanning API                                                 */
/* ------------------------------------------------------------------ */

/**
 * Scan content and produce a sanitized copy.
 *
 * @returns {{
 *   sanitized: string,
 *   detections: Array<{line:number, type:string, key_name:string, rule:string}>,
 *   detectionCount: number,
 *   injections: Array<{line:number, phrase:string}>,
 *   rawSecrets: string[]  // ONLY when collectRaw=true; used in-memory for
 *                         // post-AI leak checks, never persisted or logged
 * }}
 */
export function scanContent(content, { mode = MODES.REDACT, collectRaw = false } = {}) {
  const matches = detect(content);

  let sanitized = content;
  for (let i = matches.length - 1; i >= 0; i--) {
    const match = matches[i];
    if (mode === MODES.SHOW) continue; // opt-in passthrough (gated upstream)
    const replacement = mode === MODES.HIDE ? HIDE_MARKER : redactToken(match.type);
    sanitized = sanitized.slice(0, match.start) + replacement + sanitized.slice(match.end);
  }

  const rawSecrets = collectRaw
    ? matches
        .map((mt) => content.slice(mt.start, mt.end))
        .filter((v) => v.length >= 8)
    : [];

  return {
    sanitized,
    detections: matches.map((mt) => ({
      line: mt.line,
      type: mt.type,
      key_name: mt.keyName,
      rule: mt.rule,
    })),
    detectionCount: matches.length,
    injections: detectInjections(content),
    rawSecrets,
  };
}

/**
 * Aggressively remove secret-shaped material from arbitrary text.
 * Used for application logs and for scrubbing AI output (defence in depth —
 * exact-echo removal via rawSecrets is the primary guarantee).
 */
export function scrubText(text) {
  if (typeof text !== 'string') return text;
  return scanContent(text, { mode: MODES.HIDE }).sanitized;
}

/**
 * Replace any exact occurrence of known raw secrets with a leak marker.
 * `rawSecrets` lives only within the scope of a single scan request.
 */
export function removeExactLeaks(text, rawSecrets) {
  let out = text;
  let hit = false;
  for (const secret of rawSecrets) {
    if (secret && out.includes(secret)) {
      out = out.split(secret).join(LEAK_MARKER);
      hit = true;
    }
  }
  return { text: out, hit };
}

/* ------------------------------------------------------------------ */
/* Privacy mode resolution (fail-closed)                               */
/* ------------------------------------------------------------------ */

export function resolvePrivacy(env = process.env) {
  const raw = String(env.SENSITIVE_DATA ?? 'redact').trim().toLowerCase();
  const requested = [MODES.HIDE, MODES.REDACT, MODES.SHOW].includes(raw) ? raw : 'redact';
  const allowRaw = String(env.ALLOW_SENSITIVE_DATA_TO_AI ?? 'false').trim().toLowerCase() === 'true';
  const showOptIn = requested === MODES.SHOW && allowRaw;
  const effective = requested === MODES.SHOW ? (showOptIn ? MODES.SHOW : MODES.REDACT) : requested;

  let warning = null;
  if (requested === MODES.SHOW && !showOptIn) {
    warning =
      'SENSITIVE_DATA=show requires ALLOW_SENSITIVE_DATA_TO_AI=true. Fail-closed: redaction remains active.';
  } else if (effective === MODES.SHOW) {
    warning =
      'SHOW mode is active: original sensitive values are sent to the configured AI provider. Values are never persisted or logged.';
  }

  return {
    requested_mode: requested,
    effective_mode: effective,
    show_opt_in: showOptIn,
    warning,
  };
}

/** Build the sanitized outbound payload according to the effective mode. */
export function buildAiPayload(content, privacy, { collectRaw = false } = {}) {
  return scanContent(content, { mode: privacy.effective_mode, collectRaw });
}
