const API_URL        = 'http://localhost:8000/predict';
const REPORT_URL     = 'http://localhost:8000/report';

// Remember the current tab URL globally so report button always has it
let _currentTabUrl = '';

// ── On popup open: get current tab URL immediately ────────────────────────────
// This ensures _currentTabUrl is always set even before a manual scan
chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  if (tab?.url) _currentTabUrl = tab.url;
});

// ── Scan button ───────────────────────────────────────────────────────────────
document.getElementById('scan').onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  _currentTabUrl = tab.url;  // always keep it fresh

  const btn = document.getElementById('scan');
  btn.textContent = 'Scanning…';
  btn.disabled = true;
  document.getElementById('result').innerHTML = '';

  try {
    // ── Capture screenshot + /predict simultaneously ──────────────────────────
    const screenshotPromise = (async () => {
      try {
        const dataUrl = await chrome.tabs.captureVisibleTab(null, { format: 'png' });
        const res = await fetch('http://localhost:8000/screenshot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: tab.url, screenshot: dataUrl })
        });
        return res.ok ? await res.json() : null;
      } catch (_) { return null; }
    })();

    const predictPromise = fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url })
    });

    const [res, screenshotResult] = await Promise.all([predictPromise, screenshotPromise]);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Prediction failed');

    // ── Visual clone override ─────────────────────────────────────────────────
    const userReportedSafe = data.status === 'user_reported' && data.prediction === 'Legitimate';
    if (screenshotResult?.is_clone && !userReportedSafe && data.prediction !== 'Phishing') {
      data.prediction = 'Phishing';
      data.confidence = Math.max(data.confidence ?? 0, 0.95);
      data.message    = 'Page design matches a known phishing template';
      data.reasons    = [
        { label: 'Page visually clones a known phishing site',
          severity: 'high', feature: 'visual_clone', value: 1 },
        ...(data.reasons || [])
      ];
      // Write overridden result back to server cache for consistency
      fetch('http://localhost:8000/cache/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tab.url, result: { ...data, status: 'predicted' } })
      }).catch(() => {});
    }

    showResult(data);

  } catch (e) {
    document.getElementById('result').innerHTML =
      `<div class="phish"><h3>⚠️ Error</h3><p class="message-text">${e.message}</p></div>`;
  } finally {
    btn.textContent = 'Scan Current Page';
    btn.disabled = false;
  }
};

// ── Result renderer ───────────────────────────────────────────────────────────
function showResult(data) {
  const div         = document.getElementById('result');
  const verdict     = data.prediction;
  const isTrusted   = data.status === 'trusted';
  const isPhish     = verdict === 'Phishing';
  const isUncertain = verdict === 'Uncertain';
  const confidence  = data.confidence ?? 0;
  const confPct     = (confidence * 100).toFixed(1);
  const reasons     = data.reasons || [];

  const colorClass  = isPhish ? 'phish' : isUncertain ? 'uncertain' : 'safe';
  const icon        = isPhish ? '🚨' : isUncertain ? '⚠️' : '✅';
  const label       = isPhish ? 'Phishing' : isUncertain ? 'Uncertain' : 'Legitimate';

  const gsbChecked  = data.gsb_checked;
  const gsbHit      = reasons.some(r => r.feature === 'gsb');
  const cloneHit    = reasons.some(r => r.feature === 'visual_clone');
  const vt          = data.vt || {};
  const vtChecked   = vt.checked;
  const vtTrust     = vt.trust_score ?? -1;
  const vtVerdict   = vt.verdict || 'unknown';
  const vtMal       = vt.malicious ?? 0;
  const vtTotal     = vt.total ?? 0;

  const severityIcon = { high: '🔴', medium: '🟡', low: '🔵' };

  // ── Badges ────────────────────────────────────────────────────────
  const badges = [];
  if (isTrusted) {
    badges.push('<span class="badge badge-trusted">✓ Verified Safe List</span>');
  } else {
    badges.push('<span class="badge badge-ml">🤖 ML Model</span>');

    if (gsbChecked && gsbChecked !== 'gsb_skipped') {
      badges.push(gsbHit
        ? '<span class="badge badge-gsb-hit">🛡 GSB: FLAGGED</span>'
        : '<span class="badge badge-gsb-ok">🛡 GSB: Clean</span>');
    } else if (gsbChecked === 'gsb_skipped') {
      badges.push('<span class="badge badge-gsb-skip">🛡 GSB: No key</span>');
    }

    if (vtChecked) {
      const vtClass = vtVerdict === 'malicious' ? 'badge-vt-bad'
                    : vtVerdict === 'suspicious' ? 'badge-vt-warn'
                    : 'badge-vt-ok';
      const vtText  = vtVerdict === 'malicious'
        ? `🔬 VT: ${vtMal}/${vtTotal} malicious`
        : vtVerdict === 'suspicious'
        ? `🔬 VT: suspicious · Trust ${vtTrust}/100`
        : `🔬 VT: ${vtTotal} vendors · Trust ${vtTrust}/100`;
      badges.push(`<span class="badge ${vtClass}">${vtText}</span>`);
    } else if (vt.source === 'vt_skipped') {
      badges.push('<span class="badge badge-vt-skip">🔬 VT: No key</span>');
    }

    if (cloneHit) {
      badges.push('<span class="badge badge-clone">📸 Visual Clone</span>');
    }
  }

  // ── Reasons ────────────────────────────────────────────────────────
  const showReasons  = (isPhish || isUncertain) && reasons.length > 0;
  const reasonsTitle = isUncertain ? 'Signals detected' : 'Why we flagged this';
  const reasonsHtml  = showReasons
    ? `<div class="reasons">
        <div class="reasons-title">${reasonsTitle}</div>
        <ul class="reasons-list">
          ${reasons.map(r => `
            <li class="reason-item reason-${r.severity}">
              <span class="reason-icon">${severityIcon[r.severity] || '⚪'}</span>
              <span>${r.label}</span>
            </li>`).join('')}
        </ul>
      </div>`
    : '';

  // ── Report buttons ─────────────────────────────────────────────────────────
  // Phishing  → "Mark as Safe" only
  // Uncertain → BOTH buttons (user decides which way to correct it)
  // Legitimate→ "Report as Phishing" only
  // Trusted   → no buttons
  let reportHtml = '';
  if (isPhish) {
    reportHtml = `<div id="report-area"><button class="report-btn" id="btn-safe">Mark as Safe (False Positive)</button></div>`;
  } else if (isUncertain) {
    reportHtml = `
      <div id="report-area" style="display:flex; gap:8px; margin-top:2px;">
        <button class="report-btn report-btn--half" id="btn-safe">Mark as Safe</button>
        <button class="report-btn report-btn--half report-btn--danger" id="btn-phish">Report as Phishing</button>
      </div>`;
  } else if (!isTrusted) {
    reportHtml = `<div id="report-area"><button class="report-btn report-btn--danger" id="btn-phish">Report as Phishing</button></div>`;
  }

  div.innerHTML = `
    <div class="${colorClass}">
      <h3>${icon} ${label}</h3>
      <div class="badges-row">${badges.join('')}</div>
      <div class="confidence-row">
        <span class="confidence-label">Confidence</span>
        <span class="confidence-value">${confPct}%</span>
      </div>
      <div class="confidence-bar">
        <div class="confidence-fill ${isPhish ? 'fill-phish' : isUncertain ? 'fill-uncertain' : 'fill-safe'}"
             style="width:${confPct}%"></div>
      </div>
      <p class="message-text">${data.message || ''}</p>
      ${reasonsHtml}
      ${reportHtml}
    </div>
  `;

  // Wire buttons via addEventListener (onclick in innerHTML is blocked by CSP)
  const btnSafe  = document.getElementById('btn-safe');
  const btnPhish = document.getElementById('btn-phish');

  // Shared lock — once either button is clicked, both become unclickable
  // preventing conflicting reports from being sent in the same scan session.
  function wireUncertainButtons() {
    if (!btnSafe || !btnPhish) return;
    function onAction(clickedBtn, otherBtn, reportType) {
      clickedBtn.disabled = true;
      otherBtn.disabled   = true;
      sendReport(clickedBtn, reportType);
    }
    btnSafe.addEventListener('click',  () => onAction(btnSafe,  btnPhish, 'false_positive'));
    btnPhish.addEventListener('click', () => onAction(btnPhish, btnSafe,  'false_negative'));
  }

  if (btnSafe && btnPhish) {
    wireUncertainButtons();
  } else {
    if (btnSafe)  btnSafe.addEventListener('click',  () => sendReport(btnSafe,  'false_positive'));
    if (btnPhish) btnPhish.addEventListener('click', () => sendReport(btnPhish, 'false_negative'));
  }
}

// ── Report + Hash ──────────────────────────────────────────────────────────────
// Does two things simultaneously:
//   1. POST /report  — updates verdict cache for this URL (24h)
//   2. Hash endpoint — /hash/add (false_negative) or /hash/remove-by-url (false_positive)
//
// On success: replaces the entire #report-area with a confirmation text,
// matching the web app behaviour (buttons disappear, text appears).
async function sendReport(btn, reportType) {
  const url = _currentTabUrl;

  if (!url || url.startsWith('edge://') || url.startsWith('chrome://')) {
    btn.textContent = '⚠ Cannot report this page type';
    return;
  }

  // Immediately disable button to prevent double-click
  btn.textContent = 'Sending…';
  btn.disabled = true;

  try {
    // Capture screenshot for hash/add (false_negative only — best effort)
    let dataUrl = null;
    if (reportType === 'false_negative') {
      try { dataUrl = await chrome.tabs.captureVisibleTab(null, { format: 'png' }); }
      catch (_) {}
    }

    // Fire /report and hash endpoint simultaneously
    const reportPromise = fetch(REPORT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, report_type: reportType, reported_by: 'popup' })
    });

    const hashPromise = reportType === 'false_negative' && dataUrl
      ? fetch('http://localhost:8000/hash/add', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, screenshot: dataUrl })
        }).then(r => r.json())
          .then(d => console.log('[PhishGuard] Hash added:', d.added, 'db_size:', d.db_size))
          .catch(e => console.warn('[PhishGuard] Hash add failed:', e))
      : reportType === 'false_positive'
      ? fetch('http://localhost:8000/hash/remove-by-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        }).then(r => r.json())
          .then(d => console.log('[PhishGuard] Hash removed:', d.removed))
          .catch(e => console.warn('[PhishGuard] Hash remove failed:', e))
      : Promise.resolve();

    const [res] = await Promise.all([reportPromise, hashPromise]);

    if (res.ok) {
      // Replace the entire #report-area with confirmation text (mirrors web app)
      const area = document.getElementById('report-area');
      if (area) {
        const confirmText = reportType === 'false_positive'
          ? '✓ Marked as safe — thank you'
          : '✓ Reported as phishing — thank you';
        area.outerHTML = `<p class="report-confirm">${confirmText}</p>`;
      }
    } else {
      throw new Error(`Server returned ${res.status}`);
    }
  } catch (err) {
    console.error('PhishGuard report failed:', err);
    btn.textContent = 'Failed — try again';
    btn.disabled = false;
  }
}