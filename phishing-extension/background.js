const API_URL = 'http://localhost:8000/predict';

// ── Screenshot-safe capture ─────────────────────────────────────────────────
// Always hide the content.js overlay banner before capturing a screenshot,
// then restore it. Prevents the banner from being baked into stored/compared
// perceptual hashes (see content.js for full explanation of the bug this fixes).
async function captureCleanScreenshot(tabId, windowId) {
  let hideResult = null;
  if (tabId != null) {
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
  }

  // BUGFIX: requestAnimationFrame does NOT exist in MV3 service workers.
  // The original `await new Promise(resolve => requestAnimationFrame(...))` threw
  // ReferenceError every time, which was silently swallowed by the outer catch —
  // making capturedDataUrl always null so /screenshot was never called and visual
  // clone detection never ran for background auto-scans.
  //
  // setTimeout IS available in service workers (and also in popup/content contexts),
  // so it works everywhere.  50 ms gives the browser one repaint cycle to actually
  // remove the overlay pixels before we grab the screenshot.
  await new Promise(resolve => setTimeout(resolve, 50));

  let dataUrl = null;
  try {
    dataUrl = await chrome.tabs.captureVisibleTab(windowId, { format: 'png' });
  } finally {
    if (hideResult?.hidden && tabId != null) {
      try { await chrome.tabs.sendMessage(tabId, { action: 'restoreOverlay' }); }
      catch (_) {}
    }
  }
  return dataUrl;
}

// ─── Trusted domains whitelist (synced from backend) ─────────────────────────
let TRUSTED_DOMAINS = new Set(['localhost', '127.0.0.1']);

async function fetchTrustedWhitelist() {
  try {
    const response = await fetch('http://localhost:8000/static-whitelist');
    if (response.ok) {
      const data = await response.json();
      TRUSTED_DOMAINS = new Set(data.domains);
      console.log(`[PhishGuard] Loaded ${TRUSTED_DOMAINS.size} trusted domains from backend`);
    } else {
      console.warn('[PhishGuard] Could not fetch whitelist, using fallback');
    }
  } catch (err) {
    console.warn('[PhishGuard] Failed to fetch whitelist:', err);
  }
}
fetchTrustedWhitelist();

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

function isTrustedDomain(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    const bare = hostname.replace(/^www\./, '');
    if (TRUSTED_DOMAINS.has(bare)) return true;
    for (const trusted of TRUSTED_DOMAINS) {
      if (bare.endsWith('.' + trusted)) return true;
    }
  } catch (_) {}
  return false;
}

async function scanUrl(url, tabId = null) {
  if (!isScannable(url)) {
    chrome.action.setBadgeText({ text: '' }).catch(() => {});
    return null;
  }

  if (isTrustedDomain(url)) {
    chrome.action.setBadgeBackgroundColor({ color: '#4caf50' }).catch(() => {});
    chrome.action.setBadgeText({ text: 'SAFE' }).catch(() => {});
    // BUGFIX: scanUrl() is only ever reached via the content-script's
    // automatic "scan" message on page load/navigation — the manual scan
    // button in popup.js calls /predict directly and never touches this
    // function. So this branch is ALWAYS auto-scan, never manual. Per the
    // same rule as the backend's Tier 1/2 checks, a trusted-domain auto-scan
    // must never be logged to Scan History / Total Scans — so the
    // /log-trusted call is removed entirely rather than gated.
    return { prediction: 'Legitimate', confidence: 1.0, message: 'Trusted domain — skipped scan' };
  }

  if (tabId) {
    chrome.action.setBadgeText({ text: '...', tabId }).catch(() => {});
    chrome.action.setBadgeBackgroundColor({ color: '#9e9e9e', tabId }).catch(() => {});
  } else {
    chrome.action.setBadgeText({ text: '...' }).catch(() => {});
    chrome.action.setBadgeBackgroundColor({ color: '#9e9e9e' }).catch(() => {});
  }

  const controller = new AbortController();
  // BUGFIX: 10s was too short for /predict, which chains WHOIS + ML + GSB +
  // VirusTotal + feed lookups. Domains already flagged suspicious (extra VT
  // scrutiny) can legitimately take longer, causing the fetch to abort with
  // a DOMException (AbortError) even though the server was still working.
  // That aborted request fell through to the catch block, showed a
  // misleading "Scan failed — server unreachable" badge, and logged an
  // unreadable "[object DOMException]" on the extension's Errors page.
  // 20s gives slow multi-check scans room to finish normally.
  const timeoutHandle = setTimeout(() => controller.abort(), 20000);

  try {
    // ── PERF FIX: Resolve windowId BEFORE launching the parallel race ──────
    // chrome.tabs.get() is a fast local Chrome API call (~1ms) that does NOT
    // need to wait for the server. Doing it upfront lets us start the screenshot
    // capture at the same time as /predict instead of after it completes.
    let windowId = null;
    if (tabId) {
      try {
        const tabInfo = await chrome.tabs.get(tabId);
        windowId = tabInfo.windowId;
      } catch (_) {}
    }

    // ── PERF FIX: Launch /predict AND screenshot capture simultaneously ─────
    // Previously: predict (~3-8s) → screenshot (~1s) → /screenshot API (~0.5s)
    //             = predict_time + capture_time + api_time  total
    // Now:        predict AND screenshot start at the same time.
    //             Since predict takes longer, screenshot is almost always done
    //             by the time predict responds. User-visible wait drops by ~1-2s.
    //
    // popup.js already uses Promise.all for this — background.js now matches it.
    const predictPromise = fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // manual: false (explicit) — this is the automatic background scan.
      // "trusted" verdicts from here are intentionally NOT logged; see
      // /predict Tier 1 in app.py.
      body: JSON.stringify({ url, manual: false }),
      signal: controller.signal,
    });

    // Wait for /predict first — it drives the verdict
    const predictRes = await predictPromise;
    clearTimeout(timeoutHandle);
    if (!predictRes.ok) throw new Error(`HTTP ${predictRes.status}`);
    const data = await predictRes.json();

    // BUGFIX: take the screenshot AFTER /predict returns, not concurrently.
    //
    // Previously the screenshot started at the same time as /predict and
    // finished at ~50 ms.  /predict takes 3-8 s (WHOIS + ML + content fetch)
    // so by the time it finishes the screenshot was taken up to 8 s earlier —
    // when a JS-heavy page (React/Next.js SPA) may only have painted its
    // loading skeleton.  That skeleton looks completely different from the
    // fully-rendered page, so pHash distance easily exceeded the similarity
    // threshold even for the identical URL, breaking visual clone detection.
    //
    // Taking the screenshot after /predict means it is captured once the page
    // has had 3-8 s to render — matching popup.js's behaviour (screenshot is
    // always of the fully-rendered page the user is actively viewing).
    let capturedDataUrl = null;
    try {
      capturedDataUrl = await captureCleanScreenshot(tabId, windowId);
    } catch (_) {}

    let screenshotResult = null;
    if (capturedDataUrl) {
      try {
        const screenshotRes = await fetch('http://localhost:8000/screenshot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, screenshot: capturedDataUrl })
        });
        screenshotResult = screenshotRes.ok ? await screenshotRes.json() : null;
      } catch (_) {}
    }

    let confidence = data.confidence ?? 0.5;
    let message = data.message ?? 'Scanned';
    let prediction = data.prediction ?? 'Legitimate';
    let reasons = data.reasons ?? [];

    // Any user-reported verdict (safe OR phishing) is definitive and final — it
    // must never be re-labeled by the visual-clone heuristic on a rescan.
    // Previously this only guarded the false_positive case (prediction ===
    // 'Legitimate'), so a false_negative report (user marked it Phishing) had
    // no protection: rescans re-triggered "Visual Clone" and overwrote the
    // cached "Marked as phishing by user report" reason.
    const isUserReported = data.status === 'user_reported';
    // BUGFIX: skip the override entirely when data.status === 'cached'.
    // Same reasoning as popup.js — see its comment for full explanation.
    if (screenshotResult?.is_clone && !isUserReported && data.status !== 'cached') {
      // BUGFIX: always apply visual-clone verdict and evidence, even when
      // /predict already returned 'Phishing' via PhishTank / ML.
      // Previously the inner `if (prediction !== 'Phishing')` guard meant
      // that message and reasons were never updated in that case — so the UI
      // showed 'Phishing (PhishTank)' with no mention of the pHash match,
      // and after a server restart (cache cleared) the rescan looked identical
      // to a plain ML hit rather than a visual-clone detection.
      prediction = 'Phishing';
      confidence = Math.max(confidence, 0.99);
      message    = 'Page design matches a known phishing template';
      if (!reasons.some(r => r.feature === 'visual_clone')) {
        reasons = [
          { label: 'Page visually clones a known phishing site', severity: 'high', feature: 'visual_clone', value: 1 },
          ...reasons
        ];
      }
      fetch('http://localhost:8000/cache/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, result: {
          status: 'visual_clone', prediction, confidence, message, reasons,
          gsb_checked: data.gsb_checked, vt: data.vt || {}, features: data.features || {}
        }})
      }).catch(() => {});
    }

    const isFreshScan = !['cached', 'visual_clone'].includes(data.status);
    if (prediction === 'Phishing' && capturedDataUrl && data.status !== 'user_reported' && isFreshScan) {
      fetch('http://localhost:8000/hash/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, screenshot: capturedDataUrl })
      }).catch(() => {});
    }

    const isPhish = prediction === 'Phishing';
    const isUncertain = prediction === 'Uncertain';
    const badgeText = isPhish ? 'PHSH' : isUncertain ? 'WARN' : 'SAFE';
    const badgeColor = isPhish ? '#d32f2f' : isUncertain ? '#e65100' : '#2e7d32';
    if (tabId) {
      chrome.action.setBadgeText({ text: badgeText, tabId }).catch(() => {});
      chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId }).catch(() => {});
      _tabResults.set(tabId, { prediction, badgeText, badgeColor });
    } else {
      chrome.action.setBadgeText({ text: badgeText }).catch(() => {});
      chrome.action.setBadgeBackgroundColor({ color: badgeColor }).catch(() => {});
    }

    if (isPhish || isUncertain) {
      let hostname = url;
      try { hostname = new URL(url).hostname.replace(/^www\./, ''); } catch (_) {}
      const notifId = `phishguard-${tabId || 0}-${Date.now()}`;
      chrome.notifications.create(notifId, {
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: isPhish ? `Phishing Detected — ${hostname}` : `Suspicious Site — ${hostname}`,
        message: `${Math.round(confidence * 100)}% · ${message}`
      });
    }
    return { prediction, confidence, message, reasons };
  } catch (e) {
    // BUGFIX: log a readable message instead of the raw error object.
    // console.error('...', e) on a DOMException (e.g. AbortError) rendered
    // as the unhelpful "[object DOMException]" on the extension's Errors page.
    const isTimeout = e?.name === 'AbortError';
    console.error('PhishGuard scan error:', e?.message || e?.name || String(e));
    if (tabId) {
      chrome.action.setBadgeText({ text: 'ERR', tabId }).catch(() => {});
      chrome.action.setBadgeBackgroundColor({ color: '#ff9800', tabId }).catch(() => {});
    } else {
      chrome.action.setBadgeText({ text: 'ERR' }).catch(() => {});
      chrome.action.setBadgeBackgroundColor({ color: '#ff9800' }).catch(() => {});
    }
    // BUGFIX: distinguish "the scan took too long" from "the server is down" —
    // these are different problems with different fixes on the user's end.
    return {
      prediction: 'Legitimate',
      confidence: 0,
      message: isTimeout ? 'Scan timed out — the site may be slow to respond' : 'Scan failed — server unreachable'
    };
  }
}

const _tabResults = new Map();

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scan') {
    const tabId = sender.tab?.id ?? null;
    scanUrl(request.url, tabId)
      .then(result => sendResponse(result ?? { prediction: 'Legitimate', confidence: 0, message: 'Skipped' }))
      .catch(err => {
        console.error('PhishGuard scan error:', err?.message || err?.name || String(err));
        sendResponse({ prediction: 'Legitimate', confidence: 0, message: 'Error' });
      });
    return true;
  }
  if (request.action === 'addHash') {
    (async () => {
      try {
        // BUGFIX: when this message is sent from popup.js, sender.tab is null
        // because the sender is the extension popup, not a content script in a tab.
        // With tabId=null, captureCleanScreenshot skips hideOverlay and
        // captureVisibleTab(null) may capture the wrong window.
        // Fix: actively query the focused active tab when sender.tab is absent.
        let tabId    = sender.tab?.id    ?? null;
        let windowId = null;

        if (tabId == null) {
          try {
            const [activeTab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
            if (activeTab) { tabId = activeTab.id; windowId = activeTab.windowId; }
          } catch (_) {}
        } else {
          try {
            const info = await chrome.tabs.get(tabId);
            windowId = info.windowId;
          } catch (_) {}
        }

        const dataUrl = await captureCleanScreenshot(tabId, windowId);
        const res = await fetch('http://localhost:8000/hash/add', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: request.url, screenshot: dataUrl })
        });
        const data = await res.json();
        sendResponse({ ok: true, hash: data.added, db_size: data.db_size });
      } catch (err) {
        sendResponse({ ok: false, error: String(err) });
      }
    })();
    return true;
  }
  if (request.action === 'removeHash') {
    (async () => {
      try {
        const res = await fetch('http://localhost:8000/hash/remove-by-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: request.url })
        });
        const data = await res.json();
        sendResponse({ ok: true, removed: data.removed, db_size: data.db_size });
      } catch (err) {
        sendResponse({ ok: false, error: String(err) });
      }
    })();
    return true;
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const stored = _tabResults.get(tabId);
  if (stored) {
    chrome.action.setBadgeText({ text: stored.badgeText, tabId }).catch(() => {});
    chrome.action.setBadgeBackgroundColor({ color: stored.badgeColor, tabId }).catch(() => {});
  } else {
    chrome.action.setBadgeText({ text: '', tabId }).catch(() => {});
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  _tabResults.delete(tabId);
});