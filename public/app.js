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
    ['INGEST', 'Ingest', 'inbox'],
    ['PYSCAN', 'PYSCAN', 'scan-search'],
    ['LOCAL_SANITIZATION', 'Sanitize', 'eye-off'],
    ['GLM_SECURITY_TRIAGE', 'GLM triage', 'bot'],
    ['PYGUARD_POLICY_VALIDATION', 'PYGUARD', 'shield-check'],
    ['REMEDIATION_DRAFT', 'Remediation', 'wrench'],
    ['HUMAN_APPROVAL', 'Approval', 'user-check'],
    ['AUDIT_RECORD', 'Audit', 'database'],
  ];

  const SOURCE_TYPE_META = {
    snippet: { icon: 'code-2', label: 'Snippet' },
    git_diff: { icon: 'git-pull-request', label: 'Git diff' },
    config: { icon: 'settings-2', label: 'Config' },
  };

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
      chipAi.className = 'inline-flex items-center gap-1.5 pl-2.5 pr-3 py-1.5 rounded-full border border-emerald/30 bg-emerald/10 text-emerald text-[11.5px] font-medium whitespace-nowrap';
    } else {
      dot.className = 'stage-dot size-1.5 rounded-full bg-amber inline-block';
      label.textContent = `AI · ${ai.provider} · demo/mock`;
      chipAi.className = 'inline-flex items-center gap-1.5 pl-2.5 pr-3 py-1.5 rounded-full border border-amber/40 bg-amber/10 text-amber text-[11.5px] font-medium whitespace-nowrap';
    }

    const privacy = health.privacy;
    const chipPrivacy = $('chip-privacy');
    const privacyLabel = chipPrivacy.querySelector('[data-chip-label]');
    privacyLabel.textContent = `Privacy · ${privacy.effective_mode}`;
    if (privacy.effective_mode === 'show') {
      chipPrivacy.className = 'inline-flex items-center gap-1.5 pl-2.5 pr-3 py-1.5 rounded-full border border-crimson/50 bg-crimson/10 text-red-300 text-[11.5px] font-medium whitespace-nowrap';
    } else {
      chipPrivacy.className = 'inline-flex items-center gap-1.5 pl-2.5 pr-3 py-1.5 rounded-full border border-emerald/30 bg-emerald/10 text-emerald text-[11.5px] font-medium whitespace-nowrap';
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
      chipDb.className = 'hidden sm:inline-flex items-center gap-1.5 pl-2.5 pr-3 py-1.5 rounded-full border border-emerald/30 bg-emerald/10 text-emerald text-[11.5px] font-medium whitespace-nowrap';
    } else if (health.database.configured) {
      dbLabel.textContent = 'Audit · database error';
      chipDb.className = 'hidden sm:inline-flex items-center gap-1.5 pl-2.5 pr-3 py-1.5 rounded-full border border-crimson/40 bg-crimson/10 text-red-300 text-[11.5px] font-medium whitespace-nowrap';
    } else {
      dbLabel.textContent = 'Audit · local';
      chipDb.className = 'hidden sm:inline-flex items-center gap-1.5 pl-2.5 pr-3 py-1.5 rounded-full border border-line bg-surface/80 text-secondary text-[11.5px] font-medium whitespace-nowrap';
    }
  }

  /* ----------------------------- pipeline ---------------------------- */

  function renderPipeline(stages, overall) {
    const container = $('pipeline');
    const statusMap = new Map((stages ?? []).map((stage) => [stage.stage, stage]));
    const statusEl = $('pipeline-status');
    statusEl.textContent = overall.toUpperCase();
    const overallTone = overall === 'Running' ? 'text-emerald border-emerald/40 bg-emerald/10'
      : overall === 'Error' ? 'text-red-300 border-crimson/40 bg-crimson/10'
      : /mock|fallback/i.test(overall) ? 'text-amber border-amber/40 bg-amber/10'
      : /live/i.test(overall) ? 'text-emerald border-emerald/40 bg-emerald/10'
      : 'text-meta';
    statusEl.className = `text-[11.5px] font-mono num px-2.5 py-1 rounded-full border bg-obsidian/60 ${overallTone}`;

    container.innerHTML = WORKFLOW_STAGES.map(([stageKey, label, icon], index) => {
      const stage = statusMap.get(stageKey);
      let nodeClass = '';
      let stateClass = 'text-meta';
      let badge = '';

      if (state.scanning && overall === 'Running') {
        nodeClass = 'stage-active';
        stateClass = 'stage-active text-emerald font-medium';
      }
      if (stage) {
        if (stage.status === 'ok') {
          nodeClass = 'stage-done';
          stateClass = 'text-secondary';
          badge = stage.duration_ms > 0 ? `${stage.duration_ms}ms` : 'done';
        } else if (stage.status === 'mock') {
          nodeClass = 'stage-mock';
          stateClass = 'text-amber-300';
          badge = 'mock';
        } else if (stage.status === 'error') {
          nodeClass = 'stage-error';
          stateClass = 'text-red-300';
          badge = 'skipped';
        }
      }
      const nextStage = statusMap.get(WORKFLOW_STAGES[index + 1]?.[0]);
      const linkDone = Boolean(stage && stage.status === 'ok' && nextStage);
      const isLast = index === WORKFLOW_STAGES.length - 1;
      return `
        <div class="flex items-start ${isLast ? '' : 'flex-1 min-w-[118px]'} ${nodeClass}" data-stage="${stageKey}">
          <div class="flex flex-col items-center gap-1.5 shrink-0">
            <div class="stage-node"><i data-lucide="${icon}" class="size-4"></i></div>
            <div class="text-[11.5px] whitespace-nowrap ${stateClass}">${label}</div>
            <div class="text-[10.5px] font-mono whitespace-nowrap text-meta num h-4">${badge}</div>
          </div>
          ${isLast ? '' : `<div class="stage-link flex-1 mt-[17px] mx-2 min-w-[24px] ${linkDone ? 'stage-link-done' : ''}"></div>`}
        </div>`;
    }).join('');
    refreshIcons();
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
      chip.className = 'text-[11px] font-mono px-2.5 py-1 rounded-full border border-crimson/50 bg-crimson/10 text-red-300';
    } else {
      chip.className = 'text-[11px] font-mono px-2.5 py-1 rounded-full border border-emerald/30 bg-emerald/10 text-emerald';
    }

    $('privacy-count').textContent = privacy.detected_sensitive;

    const detections = $('privacy-detections');
    detections.innerHTML = privacy.detections.length === 0
      ? '<span class="text-[12px] text-meta">No sensitive values detected — tidak ada nilai sensitif terdeteksi</span>'
      : privacy.detections
          .map(
            (d) => {
              const style = SEVERITY_STYLE[severityOf(d.type)];
              return `<span class="font-mono text-[11.5px] px-2.5 py-1 rounded-md border ${style.border} ${style.bg} ${style.text}">L${d.line} · ${escapeHtml(d.key_name)} <span class="opacity-70">${escapeHtml(d.type)}</span></span>`;
            }
          )
          .join('') +
        (privacy.injection_indicators ?? [])
          .map(
            (inj) =>
              `<span class="font-mono text-[11.5px] px-2.5 py-1 rounded-md border border-amber/50 bg-amber/10 text-amber-300">L${inj.line} · PROMPT_INJECTION</span>`
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
      .map((preset) => {
        const meta = SOURCE_TYPE_META[preset.source_type] ?? SOURCE_TYPE_META.snippet;
        const risky = !/safe/i.test(preset.id);
        return `
        <button data-preset="${preset.id}" class="lift group text-left rounded-xl border border-line bg-raised/70 hover:border-emerald/40 hover:bg-raised px-3.5 py-3">
          <div class="flex items-center justify-between gap-2">
            <span class="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-meta">
              <i data-lucide="${meta.icon}" class="size-3"></i>${meta.label}
            </span>
            <i data-lucide="${risky ? 'bug' : 'check-circle-2'}" class="size-3.5 ${risky ? 'text-crimson/70' : 'text-emerald/70'}"></i>
          </div>
          <div class="text-[13px] font-medium text-secondary group-hover:text-ink leading-snug text-pretty mt-1.5">${escapeHtml(preset.label_en)}</div>
          <div class="font-mono text-[10.5px] text-meta mt-1 leading-snug truncate">${escapeHtml(preset.filename)}</div>
        </button>`;
      })
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
        button.classList.toggle('shadow-glow-emerald', active);
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
    if (window.innerWidth < 1024) {
      $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  function renderFindingsHeader(result) {
    const index = result.risk.index;
    const circumference = 2 * Math.PI * 39;
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
    severityChip.className = `text-[11.5px] font-medium px-2.5 py-1 rounded-full border ${severity.border} ${severity.bg} ${severity.text}`;

    $('finding-count').textContent = `${result.analysis.detected_vulnerabilities.length} finding(s) · ${result.privacy.detected_sensitive} redacted value(s)`;

    const aiChip = $('ai-status-chip');
    const aiDot = aiChip.querySelector('.stage-dot');
    const aiLabel = $('ai-status-label');
    const live = result.ai.status === 'live';
    aiLabel.textContent = live ? 'Live AI analysis' : result.ai.status === 'mock_fallback' ? 'Mock fallback' : result.ai.status;
    aiDot.className = `stage-dot size-1.5 rounded-full ${live ? 'bg-emerald' : 'bg-amber'}`;
    aiChip.className = `inline-flex items-center gap-1.5 pl-2.5 pr-3 py-1.5 rounded-full border whitespace-nowrap ${
      live ? 'border-emerald/30 bg-emerald/10 text-emerald' : 'border-amber/40 bg-amber/10 text-amber'
    } text-[11.5px] font-medium`;
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
        <div class="rounded-2xl border border-emerald/30 bg-emerald/5 px-6 py-5 flex items-start gap-3.5">
          <div class="size-9 rounded-lg bg-emerald/10 border border-emerald/25 flex items-center justify-center shrink-0">
            <i data-lucide="check-circle-2" class="size-4.5 text-emerald"></i>
          </div>
          <div class="text-[13.5px] text-secondary leading-relaxed">
            <span class="font-semibold text-emerald">No vulnerabilities found.</span><br />
            Local scanning found no obvious sensitive values. A clean sample does not prove the application is secure.
          </div>
        </div>`;
      return;
    }
    section.innerHTML = findings
      .map((finding, i) => {
        const style = SEVERITY_STYLE[finding.severity] ?? SEVERITY_STYLE.medium;
        const confidencePct = Math.round((finding.confidence ?? 0) * 100);
        return `
        <article class="finding-card rounded-2xl border border-line bg-surface shadow-card fade-in" style="--rail:${style.raw}; animation-delay:${i * 60}ms">
          <div class="px-6 py-3 border-b border-line flex items-center gap-2 flex-wrap bg-white/[0.015]">
            <span class="inline-flex items-center gap-1.5 font-mono text-[11px] font-medium ${style.text}"><span class="size-1.5 rounded-full ${style.dot}"></span>${escapeHtml(finding.id)}</span>
            <span class="text-[11px] font-medium px-2 py-0.5 rounded-full border ${style.border} ${style.bg} ${style.text}">${finding.severity}</span>
            <span class="font-mono text-[10.5px] px-2 py-0.5 rounded-md bg-raised text-secondary border border-line">${escapeHtml(finding.category)}</span>
            ${finding.rotation_required ? '<span class="text-[11px] font-medium px-2 py-0.5 rounded-full bg-crimson/10 text-red-300 border border-crimson/40 inline-flex items-center gap-1"><i data-lucide="key-round" class="size-3"></i>Rotate credential</span>' : ''}
            ${finding.line ? `<span class="font-mono text-[11px] text-meta ml-auto num">line ${finding.line}</span>` : ''}
          </div>
          <div class="px-6 py-5 space-y-4">
            <h3 class="text-[15.5px] font-semibold leading-snug text-pretty">${escapeHtml(finding.title)}</h3>
            ${finding.description ? `<p class="text-[13.5px] text-secondary leading-relaxed text-pretty">${escapeHtml(finding.description)}</p>` : ''}
            ${finding.evidence_excerpt ? `
            <div class="terminal">
              <div class="terminal-bar">
                <i style="background:#EF4444"></i><i style="background:#F59E0B"></i><i style="background:#10B981"></i>
                <span class="terminal-title">evidence · redacted</span>
              </div>
              <pre class="px-3.5 py-3 font-mono text-[11.5px] leading-relaxed whitespace-pre-wrap break-all text-secondary">${highlightTokens(finding.evidence_excerpt)}</pre>
            </div>` : ''}
            ${finding.risk_impact ? `
            <div class="flex items-start gap-2.5 text-[13.5px] text-secondary leading-relaxed">
              <i data-lucide="zap" class="size-3.5 mt-1 shrink-0 ${style.text}"></i>
              <span><span class="text-[11.5px] font-mono uppercase tracking-wider text-meta block mb-0.5">Risk impact</span>${escapeHtml(finding.risk_impact)}</span>
            </div>` : ''}
            <div class="flex items-center gap-3 max-w-sm">
              <div class="text-[11px] font-mono uppercase tracking-wider text-meta shrink-0">Confidence</div>
              <div class="meter flex-1"><div style="width:${confidencePct}%; background:${style.raw}"></div></div>
              <div class="text-[11.5px] font-mono text-secondary num shrink-0">${confidencePct}%</div>
            </div>
            ${finding.remediation ? `
            <div class="rounded-xl border border-emerald/25 bg-emerald/[0.06] px-4 py-3 text-[13.5px] text-ink leading-relaxed text-pretty flex items-start gap-2.5">
              <i data-lucide="wrench" class="size-4 mt-0.5 shrink-0 text-emerald"></i>
              <span><span class="text-[11.5px] font-mono uppercase tracking-wider text-emerald/80 block mb-0.5">Recommended remediation</span>${escapeHtml(finding.remediation)}</span>
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
      $('diff-view').innerHTML = `
        <div class="terminal-bar sticky top-0 z-10">
          <i style="background:#EF4444"></i><i style="background:#F59E0B"></i><i style="background:#10B981"></i>
          <span class="terminal-title">remediation.patch · proposal only</span>
        </div>` +
        diff
          .split('\n')
          .map((line) => {
            const escaped = escapeHtml(line) || '&nbsp;';
            if (line.startsWith('+') && !line.startsWith('+++')) return `<div class="diff-row diff-add"><span class="diff-sign">+</span><span class="diff-code">${escaped}</span></div>`;
            if (line.startsWith('-') && !line.startsWith('---')) return `<div class="diff-row diff-del"><span class="diff-sign">−</span><span class="diff-code">${escaped}</span></div>`;
            if (line.startsWith('@@')) return `<div class="diff-row diff-hunk"><span class="diff-sign">@</span><span class="diff-code">${escaped}</span></div>`;
            return `<div class="diff-row"><span class="diff-sign">&nbsp;</span><span class="diff-code text-secondary">${escaped}</span></div>`;
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
              <div class="grid grid-cols-2 sm:grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1.5 rounded-xl border border-line bg-raised/60 hover:bg-raised px-4 py-3 text-[12.5px] transition-colors">
                <div class="flex items-center gap-3 min-w-0">
                  <span class="font-mono text-secondary truncate">${escapeHtml(String(record.scan_id))}</span>
                  <span class="font-mono text-meta hidden md:inline truncate">${escapeHtml(record.filename || 'untitled')}</span>
                </div>
                <div class="flex items-center gap-2.5 justify-end flex-wrap">
                  <span class="px-2 py-0.5 rounded-full border text-[11px] font-medium ${style.border} ${style.bg} ${style.text}">${record.severity}</span>
                  <span class="text-meta num">risk ${record.risk_index}</span>
                  <span class="text-meta num hidden sm:inline">${record.findings_count} finding(s)</span>
                  <span class="inline-flex items-center gap-1 ${record.analysis_mode === 'live' ? 'text-emerald' : 'text-amber'}">
                    <span class="size-1.5 rounded-full ${record.analysis_mode === 'live' ? 'bg-emerald' : 'bg-amber'}"></span>${record.analysis_mode === 'live' ? 'Live' : 'Mock fallback'}
                  </span>
                  <span class="text-meta num hidden lg:inline">${escapeHtml(new Date(record.created_at).toLocaleString())}</span>
                </div>
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
    document.addEventListener('keydown', (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        runScan();
      }
    });
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
