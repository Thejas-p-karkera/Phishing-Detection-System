const API_URL        = 'http://localhost:8000/predict';
const REPORT_URL     = 'http://localhost:8000/report';

// ── Screenshot-safe capture ─────────────────────────────────────────────────
// Always hide the content.js overlay banner before capturing a screenshot,
// then restore it. Prevents the banner from being baked into stored/compared
// perceptual hashes (see content.js for full explanation of the bug this fixes).
async function captureCleanScreenshot(tabId, windowId = null) {
  let hideResult = null;
  try {
    hideResult = await chrome.tabs.sendMessage(tabId, { action: 'hideOverlay' });
  } catch (err) {
    // Common cause: content.js hasn't been injected into this tab yet — e.g.
    // the tab was open before the extension was installed/reloaded, or this
    // is the first scan on this tab this session. This is EXPECTED and
    // harmless: if content.js never ran, there is no overlay banner to hide
    // in the first place, so the screenshot is already clean.
    // Logged at console.debug (not console.warn) so it doesn't get flagged
    // as an "Error" on the extension's chrome://extensions Errors page —
    // Chrome surfaces console.warn there, which made this benign, already-
    // handled fallback look like a real bug.
    console.debug('[PhishGuard] hideOverlay skipped (content script not present on this tab) — '
      + 'proceeding with capture as-is.', err?.message || err);
  }

  // BUGFIX (mirrors background.js fix): requestAnimationFrame fires on the
  // POPUP window's repaint cycle, NOT the tab's.  The orange overlay may
  // therefore still be pixel-visible in the tab when captureVisibleTab runs,
  // baking the banner into stored pHashes and causing mismatches on every
  // subsequent rescan.  setTimeout(50) gives the tab a full repaint cycle
  // (≥1 × 16 ms frame) before we grab the screenshot — same fix applied to
  // background.js at the time MV3 service-worker support was added.
  await new Promise(resolve => setTimeout(resolve, 50));

  let dataUrl = null;
  try {
    // BUGFIX: pass the explicit windowId instead of null so we always capture
    // the correct browser window even when called from the popup context,
    // where captureVisibleTab(null) can resolve to the popup's own window.
    dataUrl = await chrome.tabs.captureVisibleTab(windowId, { format: 'png' });
  } finally {
    if (hideResult?.hidden) {
      try { await chrome.tabs.sendMessage(tabId, { action: 'restoreOverlay' }); }
      catch (_) {}
    }
  }
  return dataUrl;
}

// Remember the current tab URL/ID globally so report button always has it
let _currentTabUrl      = '';
let _currentTabId       = null;
let _currentTabWindowId = null;   // BUGFIX: needed for captureCleanScreenshot(tabId, windowId)

// ── On popup open: get current tab URL immediately ────────────────────────────
// This ensures _currentTabUrl is always set even before a manual scan
chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  if (tab?.url) _currentTabUrl = tab.url;
  if (tab?.id != null) _currentTabId = tab.id;
  if (tab?.windowId != null) _currentTabWindowId = tab.windowId;
});

// ── Scan button ───────────────────────────────────────────────────────────────
document.getElementById('scan').onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  _currentTabUrl      = tab.url;  // always keep it fresh
  _currentTabId       = tab.id;
  _currentTabWindowId = tab.windowId;  // BUGFIX: needed for correct capture window

  const btn = document.getElementById('scan');
  btn.textContent = 'Scanning…';
  btn.disabled = true;
  document.getElementById('result').innerHTML = '';

  try {
    // ── Capture screenshot + /predict simultaneously ──────────────────────────
    // scanScreenshotUrl is exposed outside the IIFE so the hash/add call below
    // can save the screenshot to the pHash DB when the result is Phishing.
    let scanScreenshotUrl = null;
    const screenshotPromise = (async () => {
      try {
        const dataUrl = await captureCleanScreenshot(tab.id, tab.windowId);
        if (!dataUrl) return null;
        scanScreenshotUrl = dataUrl;   // expose for hash/add below
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
      // manual: true tells the backend this is a user-initiated scan, so
      // "trusted" verdicts still get logged to Scan History / Total Scans.
      body: JSON.stringify({ url: tab.url, manual: true })
    });

    const [res, screenshotResult] = await Promise.all([predictPromise, screenshotPromise]);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Prediction failed');

    // ── Visual clone override ─────────────────────────────────────────────────
    const isUserReported = data.status === 'user_reported';
    // BUGFIX: skip the override entirely when data.status === 'cached'.
    // /screenshot's URL fast-path matches _URL_TO_HASH regardless of whether
    // /predict itself served this scan from cache or ran fresh. Without this
    // guard, a plain repeat scan within the same server session (cache hit,
    // correctly logged as "cached" in scan history) would still get relabeled
    // "Visual Clone" on screen — even though nothing new was detected, and
    // the backend intentionally does NOT re-derive visual-clone status on
    // cache hits (see app.py's /predict cache-hit branch for the same rule).
    // Visual-clone detection should only ever apply to a genuinely FRESH scan
    // (e.g. right after a server restart, when the hash DB persisted but the
    // in-memory result cache did not).
    if (screenshotResult?.is_clone && !isUserReported && data.status !== 'cached') {
      // BUGFIX: removed `&& data.prediction !== 'Phishing'` from the condition.
      // Previously, when /predict already returned 'Phishing' (e.g. via PhishTank
      // or ML), this entire block was skipped — so the visual-clone message,
      // reasons, and cache/update call were all silently dropped.  After a server
      // restart the rescan showed 'Phishing' with ML/feed reasons only, with no
      // indication that the page matched a stored pHash.
      data.prediction = 'Phishing';
      data.confidence = Math.max(data.confidence ?? 0, 0.99);
      data.message    = 'Page design matches a known phishing template';
      if (!(data.reasons || []).some(r => r.feature === 'visual_clone')) {
        data.reasons = [
          { label: 'Page visually clones a known phishing site',
            severity: 'high', feature: 'visual_clone', value: 1 },
          ...(data.reasons || [])
        ];
      }
      // Write overridden result back to server cache for consistency
      fetch('http://localhost:8000/cache/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tab.url, result: { ...data, status: 'visual_clone' } })
      }).catch(() => {});
    }

    // ── Auto-save screenshot to pHash DB when system detects phishing ──────
    // Mirrors background.js behaviour (line: "if (prediction === 'Phishing'…)").
    // Rules:
    //   • Only on FRESH scans — if data.status is 'cached' or 'visual_clone'
    //     the hash already exists; no need (and wasteful) to re-add it.
    //   • Not for 'user_reported' — the sendReport() path handles those.
    //   • Only when we actually have a screenshot to hash.
    const isFreshScan = !['cached', 'visual_clone'].includes(data.status);
    if (data.prediction === 'Phishing' && scanScreenshotUrl
        && data.status !== 'user_reported' && isFreshScan) {
      fetch('http://localhost:8000/hash/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tab.url, screenshot: scanScreenshotUrl })
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
      try { dataUrl = await captureCleanScreenshot(_currentTabId, _currentTabWindowId); }
      catch (_) {}
    }

    // Fire /report and hash endpoint simultaneously
    const reportPromise = fetch(REPORT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // Include screenshot on false_negative so /report can add hash in one call
      body: JSON.stringify({
        url,
        report_type:  reportType,
        reported_by:  'popup',
        screenshot:   (reportType === 'false_negative' && dataUrl) ? dataUrl : '',
      })
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