/**
 * Pyzex Guard — dashboard client.
 * Renders the agent workflow, privacy preview, findings, remediation diff
 * and audit history. All status displays reflect REAL server responses —
 * the UI never simulates provider activity that has not occurred.
 */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const MAX_CHARS = 65536;

  const state = {
    sourceType: 'snippet',
    presets: [],
    activePreset: null,
    previewTimer: null,
    lastResult: null,
    scanning: false,
  };

  const WORKFLOW_STAGES = [
    ['INGEST', 'Ingest'],
    ['PYSCAN', 'PYSCAN'],
    ['LOCAL_SANITIZATION', 'Sanitize'],
    ['GLM_SECURITY_TRIAGE', 'GLM triage'],
    ['PYGUARD_POLICY_VALIDATION', 'PYGUARD'],
    ['REMEDIATION_DRAFT', 'Remediation'],
    ['HUMAN_APPROVAL', 'Approval'],
    ['AUDIT_RECORD', 'Audit'],
  ];

  const SEVERITY_STYLE = {
    critical: { text: 'text-red-300', border: 'border-crimson/50', bg: 'bg-crimson/10', dot: 'bg-red-400', raw: '#EF4444' },
    high: { text: 'text-orange-300', border: 'border-orange-500/50', bg: 'bg-orange-500/10', dot: 'bg-orange-400', raw: '#F97316' },
    medium: { text: 'text-amber-300', border: 'border-amber/50', bg: 'bg-amber/10', dot: 'bg-amber-400', raw: '#F59E0B' },
    low: { text: 'text-blue-300', border: 'border-blue-500/50', bg: 'bg-blue-500/10', dot: 'bg-blue-400', raw: '#3B82F6' },
    none: { text: 'text-emerald', border: 'border-emerald/50', bg: 'bg-emerald/10', dot: 'bg-emerald', raw: '#10B981' },
  };

  /* ------------------------------ utils ------------------------------ */

  const escapeHtml = (value) =>
    String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');

  const highlightTokens = (text) =>
    escapeHtml(text).replace(
      /\[(REDACTED:[A-Z_]+|SENSITIVE_VALUE_REMOVED|REDACTED:LEAK_PREVENTED)\]/g,
      (match) =>
        match === '[SENSITIVE_VALUE_REMOVED]'
          ? `<span class="tok tok-hide">${match}</span>`
          : `<span class="tok">${match}</span>`
    );

  const refreshIcons = () => window.lucide && window.lucide.createIcons();

  async function api(path, options = {}) {
    const response = await fetch(path, {
      headers: { 'content-type': 'application/json' },
      ...options,
    });
    let body = {};
    try {
      body = await response.json();
    } catch {
      /* non-JSON response */
    }
    if (!response.ok) {
      const error = new Error(body?.error?.message || `Request failed (${response.status})`);
      error.code = body?.error?.code || 'HTTP_ERROR';
      error.status = response.status;
      throw error;
    }
    return body;
  }

  /* ------------------------------ header ----------------------------- */

  function renderHealth(health) {
    const ai = health.ai_provider;
    const chipAi = $('chip-ai');
    const dot = chipAi.querySelector('.stage-dot');
    const label = chipAi.querySelector('[data-chip-label]');
    if (ai.configured) {
      dot.className = 'stage-dot size-1.5 rounded-full bg-emerald inline-block';
      label.textContent = `AI · ${ai.provider}: ${ai.model || 'configured'}`;
      chipAi.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-emerald/30 bg-emerald/10 text-emerald text-[11px]';
    } else {
      dot.className = 'stage-dot size-1.5 rounded-full bg-amber inline-block';
      label.textContent = `AI · ${ai.provider} · demo/mock`;
      chipAi.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-amber/40 bg-amber/10 text-amber text-[11px]';
    }

    const privacy = health.privacy;
    const chipPrivacy = $('chip-privacy');
    const privacyLabel = chipPrivacy.querySelector('[data-chip-label]');
    privacyLabel.textContent = `Privacy · ${privacy.effective_mode}`;
    if (privacy.effective_mode === 'show') {
      chipPrivacy.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-crimson/50 bg-crimson/10 text-red-300 text-[11px]';
    } else {
      chipPrivacy.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-emerald/30 bg-emerald/10 text-emerald text-[11px]';
    }

    const showBanner = $('show-banner');
    if (privacy.effective_mode === 'show') {
      $('show-banner-text').textContent = privacy.warning || 'SHOW mode is active — original sensitive values will be sent to the AI provider.';
      showBanner.classList.remove('hidden');
    } else if (privacy.warning) {
      $('show-banner-text').textContent = privacy.warning;
      showBanner.classList.remove('hidden');
      showBanner.className = 'border-b border-amber/30 bg-amber/10';
    } else {
      showBanner.classList.add('hidden');
    }

    $('chip-demo').classList.toggle('hidden', !health.demo_mode);

    const chipDb = $('chip-db');
    const dbLabel = chipDb.querySelector('[data-chip-label]');
    if (health.database.active) {
      dbLabel.textContent = 'Audit · Neon';
      chipDb.className = 'hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-emerald/30 bg-emerald/10 text-emerald text-[11px]';
    } else if (health.database.configured) {
      dbLabel.textContent = 'Audit · database error';
      chipDb.className = 'hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-crimson/40 bg-crimson/10 text-red-300 text-[11px]';
    } else {
      dbLabel.textContent = 'Audit · local';
      chipDb.className = 'hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-line bg-surface text-secondary text-[11px]';
    }
  }

  /* ----------------------------- pipeline ---------------------------- */

  function renderPipeline(stages, overall) {
    const container = $('pipeline');
    const statusMap = new Map((stages ?? []).map((stage) => [stage.stage, stage]));
    $('pipeline-status').textContent = overall;

    container.innerHTML = WORKFLOW_STAGES.map(([stageKey, label], index) => {
      const stage = statusMap.get(stageKey);
      let stateClass = 'text-meta';
      let dotClass = 'bg-neutral-700';
      let badge = '';

      if (state.scanning && overall === 'Running') {
        stateClass = 'stage-active text-emerald';
        dotClass = 'bg-emerald';
      }
      if (stage) {
        if (stage.status === 'ok') {
          stateClass = 'text-secondary';
          dotClass = 'bg-emerald';
          badge = `${stage.duration_ms}ms`;
        } else if (stage.status === 'mock') {
          stateClass = 'text-amber-300';
          dotClass = 'bg-amber';
          badge = 'mock';
        } else if (stage.status === 'error') {
          stateClass = 'text-red-300';
          dotClass = 'bg-red-400';
          badge = 'skipped';
        }
      }
      const isLast = index === WORKFLOW_STAGES.length - 1;
      return `
        <div class="flex items-center ${isLast ? '' : 'flex-1 min-w-[110px]'}" data-stage="${stageKey}">
          <div class="flex flex-col items-center gap-1.5 ${isLast ? '' : 'w-min'}">
            <div class="stage-dot size-2 rounded-full ${dotClass}"></div>
            <div class="text-[11px] whitespace-nowrap ${stateClass}">${label}</div>
            <div class="text-[11px] whitespace-nowrap text-meta num h-4">${badge}</div>
          </div>
          ${isLast ? '' : '<div class="h-px flex-1 bg-line mx-2 mb-5"></div>'}
        </div>`;
    }).join('');
  }

  /* --------------------------- privacy panel ------------------------- */

  function severityOf(type) {
    if (type === 'PRIVATE_KEY' || type === 'CLOUD_SECRET_KEY') return 'critical';
    if (type === 'PROMPT_INJECTION' || type === 'PASSWORD') return 'medium';
    return 'high';
  }

  function renderPreview(payload) {
    const privacy = payload.privacy;
    const chip = $('privacy-mode-chip');
    chip.textContent = `Mode · ${privacy.effective_mode}`;
    if (privacy.effective_mode === 'show') {
      chip.className = 'text-[11px] px-2 py-1 rounded border border-crimson/50 bg-crimson/10 text-red-300';
    } else {
      chip.className = 'text-[11px] px-2 py-1 rounded border border-emerald/30 bg-emerald/10 text-emerald';
    }

    $('privacy-count').textContent = privacy.detected_sensitive;

    const detections = $('privacy-detections');
    detections.innerHTML = privacy.detections.length === 0
      ? '<span class="text-[11px] text-meta">No sensitive values detected — tidak ada nilai sensitif terdeteksi</span>'
      : privacy.detections
          .map(
            (d) => {
              const style = SEVERITY_STYLE[severityOf(d.type)];
              return `<span class="font-mono text-[11px] px-2 py-1 rounded border ${style.border} ${style.bg} ${style.text}">L${d.line} · ${escapeHtml(d.key_name)} <span class="opacity-70">${escapeHtml(d.type)}</span></span>`;
            }
          )
          .join('') +
        (privacy.injection_indicators ?? [])
          .map(
            (inj) =>
              `<span class="font-mono text-[11px] px-2 py-1 rounded border border-amber/50 bg-amber/10 text-amber-300">L${inj.line} · PROMPT_INJECTION</span>`
          )
          .join('');

    const warning = $('privacy-warning');
    if (privacy.warning) {
      $('privacy-warning-text').textContent = privacy.warning;
      warning.classList.remove('hidden');
    } else {
      warning.classList.add('hidden');
    }

    $('sanitized-preview').innerHTML = highlightTokens(payload.sanitized_payload || '');
  }

  /* ----------------------------- presets ----------------------------- */

  function renderPresets(presets) {
    $('preset-row').innerHTML = presets
      .map(
        (preset) => `
        <button data-preset="${preset.id}" class="text-left rounded border border-line bg-raised hover:border-emerald/40 px-3 py-2.5 transition-colors group">
          <div class="text-[13px] font-medium text-secondary group-hover:text-emerald leading-snug text-pretty">${escapeHtml(preset.label_en)}</div>
          <div class="font-mono text-[11px] text-meta mt-1 leading-snug">${escapeHtml(preset.filename)}</div>
        </button>`
      )
      .join('');
    $('preset-row').querySelectorAll('[data-preset]').forEach((button) => {
      button.addEventListener('click', () => loadPreset(presets.find((p) => p.id === button.dataset.preset)));
    });
  }

  function loadPreset(preset) {
    if (!preset) return;
    state.activePreset = preset.id;
    $('filename').value = preset.filename;
    $('content').value = preset.content;
    setSourceType(preset.source_type);
    updateCharCount();
    schedulePreview(true);
    $('preset-row')
      .querySelectorAll('[data-preset]')
      .forEach((button) => {
        const active = button.dataset.preset === preset.id;
        button.classList.toggle('border-emerald/60', active);
        button.classList.toggle('bg-emerald/10', active);
      });
  }

  function setSourceType(type) {
    state.sourceType = type;
    $('source-type')
      .querySelectorAll('[data-st]')
      .forEach((button) => {
        const active = button.dataset.st === type;
        button.className = active
          ? 'px-2.5 py-1.5 bg-raised text-ink'
          : `px-2.5 py-1.5 text-secondary hover:text-ink ${button.dataset.st === 'git_diff' ? 'border-x border-line' : ''}`;
      });
  }

  /* ------------------------------ scanning --------------------------- */

  function setScanning(scanning) {
    state.scanning = scanning;
    const button = $('scan-btn');
    button.disabled = scanning;
    $('scan-spinner').classList.toggle('hidden', !scanning);
    $('scan-play').classList.toggle('hidden', scanning);
    $('scan-btn-label').textContent = scanning ? 'Agent running…' : 'Trigger agent triage';
  }

  function showScanError(code, message) {
    $('scan-error').classList.remove('hidden');
    $('scan-error-title').textContent = code || 'ERROR';
    $('scan-error-msg').textContent = message || '';
  }

  function hideScanError() {
    $('scan-error').classList.add('hidden');
  }

  async function runScan() {
    if (state.scanning) return;
    const content = $('content').value;
    if (!content.trim()) {
      showScanError('EMPTY_INPUT', 'Paste source material or load a demo preset first. / Tempel kode atau muat preset demo terlebih dahulu.');
      return;
    }
    hideScanError();
    setScanning(true);
    $('results').classList.add('hidden');
    $('results-empty').classList.add('hidden');
    $('results-loading').classList.remove('hidden');
    renderPipeline([], 'Running');
    try {
      const result = await api('/api/scan', {
        method: 'POST',
        body: JSON.stringify({
          source_type: state.sourceType,
          filename: $('filename').value.trim(),
          content,
        }),
      });
      state.lastResult = result;
      renderResult(result);
      hideScanError();
      loadHistory();
      loadHealth();
    } catch (error) {
      $('results-loading').classList.add('hidden');
      $('results-empty').classList.remove('hidden');
      renderPipeline([], 'Error');
      showScanError(error.code, error.message);
      if (error.code === 'PROVIDER_NOT_CONFIGURED' || error.code === 'PROVIDER_UNAVAILABLE') {
        showScanError(error.code, `${error.message} — enable DEMO_MODE or configure the provider to continue.`);
      }
    } finally {
      setScanning(false);
    }
  }

  /* ------------------------------ results ---------------------------- */

  function renderResult(result) {
    $('results-loading').classList.add('hidden');
    $('results-empty').classList.add('hidden');
    $('results').classList.remove('hidden');
    renderPipeline(result.workflow, result.ai.status === 'live' ? 'Completed · live' : `Completed · ${result.ai.status === 'mock_fallback' ? 'mock fallback' : result.ai.status}`);
    renderFindingsHeader(result);
    renderFindings(result);
    renderRemediation(result);
    refreshIcons();
  }

  function renderFindingsHeader(result) {
    const index = result.risk.index;
    const circumference = 2 * Math.PI * 34;
    const gauge = $('risk-gauge');
    gauge.style.strokeDashoffset = String(circumference * (1 - index / 100));
    const color = SEVERITY_STYLE[result.risk.band === 'critical' ? 'critical' : result.risk.band === 'elevated' ? 'high' : result.risk.band === 'moderate' ? 'medium' : 'none'].raw;
    gauge.style.stroke = color;
    $('risk-index-num').textContent = String(index);

    const bandChip = $('risk-band-chip');
    const bandLabel = result.risk.band.charAt(0).toUpperCase() + result.risk.band.slice(1);
    bandChip.textContent = `Risk · ${bandLabel}`;
    bandChip.style.color = color;
    bandChip.style.borderColor = color + '66';

    const severity = SEVERITY_STYLE[result.analysis.severity] ?? SEVERITY_STYLE.none;
    const severityChip = $('severity-chip');
    severityChip.textContent = `Severity · ${result.analysis.severity}`;
    severityChip.className = `text-[11px] px-2 py-0.5 rounded border ${severity.border} ${severity.bg} ${severity.text}`;

    $('finding-count').textContent = `${result.analysis.detected_vulnerabilities.length} finding(s) · ${result.privacy.detected_sensitive} redacted value(s)`;

    const aiChip = $('ai-status-chip');
    const aiDot = aiChip.querySelector('.stage-dot');
    const aiLabel = $('ai-status-label');
    const live = result.ai.status === 'live';
    aiLabel.textContent = live ? 'Live AI analysis' : result.ai.status === 'mock_fallback' ? 'Mock fallback' : result.ai.status;
    aiDot.className = `stage-dot size-1.5 rounded-full ${live ? 'bg-emerald' : 'bg-amber'}`;
    aiChip.className = `inline-flex items-center gap-1.5 px-2.5 py-1 rounded border ${
      live ? 'border-emerald/30 bg-emerald/10 text-emerald' : 'border-amber/40 bg-amber/10 text-amber'
    } text-[11px]`;
    $('ai-meta').textContent = `${result.ai.model ?? 'local deterministic engine'} · ${result.ai.latency_ms}ms AI · ${result.processing_ms}ms total${live ? '' : ' · not a live AI result'}`;

    $('analysis-summary').textContent = result.analysis.summary;
    $('risk-analysis').textContent = result.analysis.risk_analysis;

    const compliance = result.analysis.compliance_status;
    $('compliance-note').innerHTML = `Compliance · <span class="font-medium">${escapeHtml(compliance.status)}</span>${
      compliance.frameworks?.length ? ` · frameworks: ${escapeHtml(compliance.frameworks.join(', '))}` : ' · no frameworks asserted'
    } — ${escapeHtml(compliance.notes || 'Preliminary automated assessment — not a compliance certification.')}${
      result.leak_prevented ? ' · <span class="text-emerald">output leak prevented by policy gate</span>' : ''
    }`;
  }

  function renderFindings(result) {
    const findings = result.analysis.detected_vulnerabilities;
    const section = $('findings-section');
    if (findings.length === 0) {
      section.innerHTML = `
        <div class="rounded-lg border border-emerald/30 bg-emerald/5 px-5 py-4 flex items-start gap-3">
          <i data-lucide="check-circle-2" class="size-5 text-emerald shrink-0 mt-0.5"></i>
          <div class="text-[13px] text-secondary leading-relaxed">
            <span class="font-semibold text-emerald">No vulnerabilities found.</span>
            Local scanning found no obvious sensitive values. A clean sample does not prove the application is secure.
          </div>
        </div>`;
      return;
    }
    section.innerHTML = findings
      .map((finding) => {
        const style = SEVERITY_STYLE[finding.severity] ?? SEVERITY_STYLE.medium;
        const confidencePct = Math.round((finding.confidence ?? 0) * 100);
        return `
        <article class="rounded-lg border ${style.border} bg-surface overflow-hidden fade-in">
          <div class="px-5 py-3 border-b border-line flex items-center gap-2.5 flex-wrap">
            <span class="size-1.5 rounded-full ${style.dot}"></span>
            <span class="font-mono text-[11px] ${style.text} num">${escapeHtml(finding.id)} · ${finding.severity}</span>
            <span class="font-mono text-[11px] px-1.5 py-0.5 rounded bg-raised text-secondary border border-line">${escapeHtml(finding.category)}</span>
            ${finding.rotation_required ? '<span class="text-[11px] px-1.5 py-0.5 rounded bg-crimson/10 text-red-300 border border-crimson/40">Rotate credential</span>' : ''}
            ${finding.line ? `<span class="font-mono text-[11px] text-meta ml-auto num">line ${finding.line}</span>` : ''}
          </div>
          <div class="px-5 py-4 space-y-3">
            <h3 class="text-[14px] font-semibold leading-snug text-pretty">${escapeHtml(finding.title)}</h3>
            ${finding.description ? `<p class="text-[13px] text-secondary leading-relaxed text-pretty">${escapeHtml(finding.description)}</p>` : ''}
            ${finding.evidence_excerpt ? `
            <div>
              <div class="text-[12px] text-meta mb-1">Redacted evidence</div>
              <pre class="bg-obsidian border border-line rounded px-3 py-2 font-mono text-[11.5px] leading-relaxed whitespace-pre-wrap break-all text-secondary">${highlightTokens(finding.evidence_excerpt)}</pre>
            </div>` : ''}
            ${finding.risk_impact ? `
            <div class="text-[13px] text-secondary leading-relaxed"><span class="text-[12px] text-meta block mb-0.5">Risk impact</span>${escapeHtml(finding.risk_impact)}</div>` : ''}
            <div class="flex items-center gap-3">
              <div class="text-[12px] text-meta">Confidence</div>
              <div class="flex-1 max-w-[160px] h-1 rounded bg-raised overflow-hidden">
                <div class="h-full ${style.dot}" style="width:${confidencePct}%"></div>
              </div>
              <div class="text-[11px] text-secondary num">${confidencePct}%</div>
            </div>
            ${finding.remediation ? `
            <div class="rounded border border-line bg-raised px-3.5 py-2.5 text-[13px] text-ink leading-relaxed text-pretty">
              <span class="text-[12px] text-meta block mb-1">Recommended remediation</span>${escapeHtml(finding.remediation)}
            </div>` : ''}
          </div>
        </article>`;
      })
      .join('');
  }

  function renderRemediation(result) {
    const diff = result.remediation.diff;
    const copyButton = $('copy-patch');
    $('remediation-status').innerHTML = `Status · <span class="font-mono">${escapeHtml(result.remediation.status)}</span>${
      result.remediation.auto_apply ? '' : ' · auto-apply disabled — proposal only'
    }`;
    if (diff) {
      copyButton.classList.remove('hidden');
      copyButton.classList.add('inline-flex');
      copyButton.dataset.diff = diff;
      $('diff-view').classList.remove('hidden');
      $('diff-view').innerHTML = diff
        .split('\n')
        .map((line) => {
          const escaped = escapeHtml(line) || '&nbsp;';
          if (line.startsWith('+') && !line.startsWith('+++')) return `<div class="diff-add px-1">${escaped}</div>`;
          if (line.startsWith('-') && !line.startsWith('---')) return `<div class="diff-del px-1">${escaped}</div>`;
          if (line.startsWith('@@')) return `<div class="diff-hunk px-1">${escaped}</div>`;
          return `<div class="px-1 text-secondary">${escaped}</div>`;
        })
        .join('');
      $('remediation-empty').textContent = '';
    } else {
      copyButton.classList.add('hidden');
      copyButton.classList.remove('inline-flex');
      $('diff-view').classList.add('hidden');
      $('remediation-empty').textContent =
        result.remediation.status === 'no_action_required'
          ? 'No patch required for this scan.'
          : 'No deterministic patch was proposed. Follow the per-finding remediation guidance and apply changes manually after review.';
    }
  }

  async function copyPatch() {
    const button = $('copy-patch');
    const text = button.dataset.diff || '';
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const helper = document.createElement('textarea');
        helper.value = text;
        document.body.appendChild(helper);
        helper.select();
        document.execCommand('copy');
        helper.remove();
      }
      button.querySelector('[data-label]').textContent = 'Copied';
      setTimeout(() => {
        button.querySelector('[data-label]').textContent = 'Copy patch';
      }, 1500);
    } catch {
      button.querySelector('[data-label]').textContent = 'Copy failed';
    }
  }

  /* ------------------------------ history ---------------------------- */

  async function loadHistory() {
    try {
      const history = await api('/api/history?limit=10');
      const status = $('history-status');
      if (!history.persistence_active) {
        status.textContent = 'Persistence inactive — set DATABASE_URL (Neon) to enable';
        $('history-list').innerHTML =
          '<div class="text-[13px] text-meta">Sanitized audit persistence is not active. Scans still work; records are simply not stored. Configure a Neon PostgreSQL DATABASE_URL to enable history.</div>';
        return;
      }
      status.textContent = `Neon PostgreSQL · ${history.records.length} record(s)`;
      $('history-list').innerHTML = history.records.length === 0
        ? '<div class="text-[13px] text-meta">No sanitized audit records yet.</div>'
        : history.records
            .map((record) => {
              const style = SEVERITY_STYLE[record.severity] ?? SEVERITY_STYLE.none;
              return `
              <div class="flex flex-wrap items-center gap-x-3 gap-y-1 rounded border border-line bg-raised px-3.5 py-2.5 text-[12px]">
                <span class="font-mono text-secondary">${escapeHtml(String(record.scan_id))}</span>
                <span class="text-meta num">${escapeHtml(new Date(record.created_at).toLocaleString())}</span>
                <span class="font-mono text-secondary">${escapeHtml(record.filename || 'untitled')}</span>
                <span class="px-1.5 py-0.5 rounded border ${style.border} ${style.bg} ${style.text}">${record.severity}</span>
                <span class="text-meta num">risk ${record.risk_index}</span>
                <span class="text-meta num">${record.findings_count} finding(s)</span>
                <span class="ml-auto ${record.analysis_mode === 'live' ? 'text-emerald' : 'text-amber'}">${record.analysis_mode === 'live' ? 'Live' : 'Mock fallback'}</span>
              </div>`;
            })
            .join('');
    } catch {
      $('history-status').textContent = 'History unavailable';
    }
  }

  /* -------------------------------- misc ----------------------------- */

  function updateCharCount() {
    const length = $('content').value.length;
    const counter = $('char-count');
    counter.textContent = length.toLocaleString('en-US');
    counter.parentElement.className =
      length > MAX_CHARS
        ? 'mt-1.5 flex items-center justify-between text-[11px] text-red-400'
        : 'mt-1.5 flex items-center justify-between text-[11px] text-meta';
  }

  async function schedulePreview(immediate = false) {
    clearTimeout(state.previewTimer);
    const content = $('content').value;
    if (!content.trim()) {
      $('sanitized-preview').innerHTML = '<span class="text-meta">Load a preset or start typing — the sanitized payload updates live.</span>';
      $('privacy-count').textContent = '0';
      $('privacy-detections').innerHTML = '';
      return;
    }
    const delay = immediate ? 0 : 400;
    state.previewTimer = setTimeout(async () => {
      try {
        const payload = await api('/api/preview', {
          method: 'POST',
          body: JSON.stringify({ content }),
        });
        renderPreview(payload);
      } catch {
        /* preview is best-effort; scan will surface real errors */
      }
    }, delay);
  }

  async function loadHealth() {
    try {
      renderHealth(await api('/api/health'));
    } catch {
      /* header chips keep last known state */
    }
  }

  /* -------------------------------- init ----------------------------- */

  async function init() {
    $('source-type').querySelectorAll('[data-st]').forEach((button) => {
      button.addEventListener('click', () => setSourceType(button.dataset.st));
    });
    $('scan-btn').addEventListener('click', runScan);
    $('copy-patch').addEventListener('click', copyPatch);
    $('empty-run-demo').addEventListener('click', () => {
      if (state.presets.length > 0) loadPreset(state.presets[0]);
      runScan();
    });
    $('content').addEventListener('input', () => {
      updateCharCount();
      schedulePreview(false);
      state.activePreset = null;
      $('preset-row').querySelectorAll('[data-preset]').forEach((button) => {
        button.classList.remove('border-emerald/60', 'bg-emerald/10');
      });
    });

    loadHealth();
    try {
      const data = await api('/api/presets');
      state.presets = data.presets;
      renderPresets(data.presets);
      if (data.presets.length > 0) loadPreset(data.presets[0]);
    } catch {
      /* presets panel stays empty; manual paste still works */
    }
    loadHistory();
    renderPipeline([], 'Idle');
    refreshIcons();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
