// ─── URL guard ────────────────────────────────────────────────────────────────
// Mirror the same check used in background.js so content script never
// attempts to scan browser-internal or blank pages.
function isScannable(url) {
  if (!url) return false;
  const SKIP_PREFIXES = [
    'chrome://', 'chrome-extension://',
    'edge://', 'edge-extension://',
    'about:', 'data:', 'javascript:',
    'file://', 'blob:',
    'moz-extension://', 'safari-extension://',
  ];
  if (SKIP_PREFIXES.some(p => url.startsWith(p))) return false;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return false;
  return true;
}

// ─── Scan guard ───────────────────────────────────────────────────────────────
// Prevents the scan from firing more than once per page load.
let hasScanned = false;

function scanCurrentPage() {
  if (hasScanned) return;
  if (!isScannable(window.location.href)) return;
  hasScanned = true;

  // Send the URL scan request. Background.js also takes a screenshot in
  // parallel using chrome.tabs.captureVisibleTab (only available in background)
  // and sends it to /screenshot. Results are merged before replying here.
  chrome.runtime.sendMessage(
    { action: 'scan', url: window.location.href },
    (response) => {
      if (chrome.runtime.lastError) {
        console.warn('PhishGuard: message failed —', chrome.runtime.lastError.message);
        return;
      }
      if (!response) return;

      const prediction = response.prediction;
      // Show overlay for Phishing and Uncertain — not for Legitimate
      if (prediction === 'Phishing' || prediction === 'Uncertain') {
        showPopup(prediction, response.confidence || 0, response.message || '', response.reasons || []);
      }
    }
  );
}

// ─── Overlay Popup ───────────────────────────────────────────────────────────────
// Purposely minimal — no report buttons, no detailed reasons drill-down.
// The full feature set (VT badge, reasons, report buttons, feature vector)
// lives exclusively in the "Scan Current Page" popup panel.
//
// Role of this overlay:
//   • Give the user an INSTANT visual warning the moment the page loads
//   • Show the verdict, confidence, and the top reasons at a glance
//   • Let the user dismiss it — nothing more
//
// Role of "Scan Current Page" panel:
//   • Full details: GSB, VT trust score, all badges
//   • Report as Phishing / Mark as Safe buttons
//   • Feature vector inspection
//
// Keeping them separate means users visit the popup panel for actions,
// which is intentional — the overlay is an alert, not a control panel.

function showPopup(prediction, confidence, message, reasons) {
  const existing = document.getElementById('phishguard-popup');
  if (existing) existing.remove();

  const isPhish     = prediction === 'Phishing';
  const isUncertain = prediction === 'Uncertain';

  const bg        = isPhish
    ? 'linear-gradient(135deg, #c62828, #e53935)'
    : 'linear-gradient(135deg, #bf360c, #e64a19)';
  const titleIcon = isPhish ? '🚨' : '⚠️';
  const titleText = isPhish ? 'Phishing Detected' : 'Suspicious Site';
  const autoDismiss = isPhish ? 15000 : 20000;

  // Show top 3 reasons only (keep overlay compact)
  const severityIcon = { high: '🔴', medium: '🟡', low: '🔵' };
  const topReasons   = (reasons || []).slice(0, 3);
  const reasonsHtml  = topReasons.length > 0
    ? `<div style="margin-top:12px; border-top:1px solid rgba(255,255,255,0.2); padding-top:10px;">
        <ul style="margin:0; padding:0; list-style:none; display:flex; flex-direction:column; gap:5px;">
          ${topReasons.map(r => `
            <li style="display:flex; align-items:flex-start; gap:7px; font-size:0.83rem;
                        background:rgba(0,0,0,0.15); border-radius:7px; padding:6px 10px;">
              <span style="flex-shrink:0;">${severityIcon[r.severity] || '⚪'}</span>
              <span>${r.label}</span>
            </li>`).join('')}
        </ul>
        ${reasons.length > 3
          ? `<p style="margin:6px 0 0; font-size:0.75rem; opacity:0.6; text-align:right;">
               +${reasons.length - 3} more — click the extension icon for details
             </p>`
          : ''}
      </div>`
    : '';

  const popup = document.createElement('div');
  popup.id = 'phishguard-popup';
  popup.style.cssText = `
    position: fixed; top: 20px; right: 20px; z-index: 2147483647;
    min-width: 320px; max-width: 400px;
    background: ${bg};
    border-radius: 16px; padding: 18px;
    box-shadow: 0 20px 48px rgba(0,0,0,0.55);
    font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    color: white;
    border: 1px solid rgba(255,255,255,0.2);
  `;

  popup.innerHTML = `
    <div style="display:flex; align-items:flex-start; gap:12px; margin-bottom:4px;">
      <div style="font-size:2rem; flex-shrink:0;">${titleIcon}</div>
      <div style="flex:1;">
        <div style="font-size:1.2rem; font-weight:700; margin-bottom:2px;">${titleText}</div>
        <div style="font-size:0.83rem; opacity:0.85; line-height:1.4;">${message}</div>
      </div>
      <button id="pg-dismiss"
        style="align-self:flex-start; padding:4px 9px; background:rgba(255,255,255,0.2);
               border:none; border-radius:6px; color:white; cursor:pointer;
               font-size:0.8rem; flex-shrink:0; line-height:1.4;">
        ✕
      </button>
    </div>

    <div style="margin-top:10px; background:rgba(0,0,0,0.2); border-radius:10px; padding:8px 12px;">
      <div style="display:flex; align-items:center; gap:10px;">
        <div style="flex:1; height:7px; background:rgba(255,255,255,0.2);
                    border-radius:999px; overflow:hidden;">
          <div style="height:100%; width:${Math.round(confidence * 100)}%;
                      background:white; border-radius:999px;"></div>
        </div>
        <div style="font-size:0.95rem; font-weight:700; flex-shrink:0;">
          ${Math.round(confidence * 100)}%
        </div>
      </div>
    </div>

    ${reasonsHtml}

    <p style="margin-top:10px; margin-bottom:0; font-size:0.72rem; opacity:0.55;
               text-align:center; letter-spacing:0.02em;">
      Click the PhishGuard icon for full details &amp; actions
    </p>
  `;

  document.documentElement.appendChild(popup);

  // Only one interaction: dismiss
  popup.querySelector('#pg-dismiss').addEventListener('click', () => popup.remove());
  setTimeout(() => { if (popup.parentNode) popup.remove(); }, autoDismiss);
}

// ─── Init ─────────────────────────────────────────────────────────────────────
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', scanCurrentPage);
} else {
  scanCurrentPage();
}