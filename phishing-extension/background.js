const API_URL = 'http://localhost:8000/predict';

// ─── Confidence threshold (now handled server-side) ──────────────────────────
// The server applies the 80% threshold and returns "Phishing"/"Uncertain"/"Legitimate".
// background.js trusts that verdict directly — no re-evaluation here.

// ─── Trusted domains whitelist ────────────────────────────────────────────────
// Two-tier system:
//   TRUSTED_DOMAINS  — never scan, return safe instantly (Tier 1: well-known giants)
//   All subdomain matching is handled in isTrustedDomain() below, so adding
//   'openai.com' also covers 'chat.openai.com', 'api.openai.com', etc.
//
// Why this matters for AI/search sites:
//   Bing, ChatGPT, Perplexity etc. use long token-heavy URLs, many subdomains,
//   and blocks scrapers — all of which score high on phishing heuristics.
//   The model was not trained on these URL patterns so it misfires.
const TRUSTED_DOMAINS = new Set([
  // ── Search engines ────────────────────────────────────────────────────
  'google.com',       'google.co.in',     'google.co.uk',    'google.com.au',
  'bing.com',         'yahoo.com',        'duckduckgo.com',  'baidu.com',
  'yandex.com',       'yandex.ru',        'ecosia.org',      'brave.com',
  'startpage.com',    'search.yahoo.com',

  // ── AI assistants & LLMs ──────────────────────────────────────────────
  'openai.com',       'chatgpt.com',      // ChatGPT
  'claude.ai',        'anthropic.com',    // Claude
  'gemini.google.com','bard.google.com',  // Gemini / Bard
  'perplexity.ai',    'you.com',          // Perplexity / You.com
  'copilot.microsoft.com',                // Microsoft Copilot
  'meta.ai',                              // Meta AI
  'grok.x.ai',        'x.ai',            // Grok
  'mistral.ai',       'huggingface.co',   // Mistral / HuggingFace
  'cohere.com',       'ai.google',        // Cohere / Google AI
  'deepmind.google',  'deepmind.com',     // DeepMind
  'stability.ai',     'midjourney.com',   // Image AI
  'character.ai',     'poe.com',          // Character.ai / Poe
  'phind.com',        'kagi.com',         // Phind / Kagi

  // ── AI writing & productivity tools ──────────────────────────────────
  'quillbot.com',     'grammarly.com',    // QuillBot / Grammarly
  'writesonic.com',   'jasper.ai',        // Writesonic / Jasper
  'copy.ai',          'rytr.me',          // Copy.ai / Rytr
  'wordtune.com',     'hemingwayapp.com', // Wordtune / Hemingway
  'humanizer.com',    'undetectable.ai',  // Humanizer / Undetectable
  'stealthwriter.ai', 'scribbr.com',      // StealthWriter / Scribbr
  'paperrater.com',   'prowritingaid.com',// PaperRater / ProWritingAid
  'smodin.io',        'jenni.ai',         // Smodin / Jenni AI
  'notion.so',        'coda.io',          // Notion / Coda
  'obsidian.md',      'roamresearch.com', // Obsidian / Roam

  // ── Microsoft ecosystem ───────────────────────────────────────────────
  'microsoft.com',    'live.com',         'office.com',       'outlook.com',
  'hotmail.com',      'msn.com',          'azure.com',        'azurewebsites.net',
  'windows.com',      'xbox.com',         'linkedin.com',     'skype.com',
  'onenote.com',      'sharepoint.com',   'teams.microsoft.com',

  // ── Google ecosystem ──────────────────────────────────────────────────
  'google.com',       'youtube.com',      'gmail.com',        'googleapis.com',
  'googleusercontent.com', 'gstatic.com', 'googlevideo.com',  'googletagmanager.com',
  'google.co.in',     'google.co.uk',     'maps.google.com',  'drive.google.com',
  'docs.google.com',  'sheets.google.com','slides.google.com','meet.google.com',
  'classroom.google.com',

  // ── Apple ecosystem ───────────────────────────────────────────────────
  'apple.com',        'icloud.com',       'itunes.apple.com', 'apps.apple.com',

  // ── Amazon / AWS ──────────────────────────────────────────────────────
  'amazon.com',       'amazon.in',        'amazon.co.uk',     'amazon.de',
  'aws.amazon.com',   'amazonaws.com',    'cloudfront.net',

  // ── Social media ──────────────────────────────────────────────────────
  'facebook.com',     'instagram.com',    'twitter.com',      'x.com',
  'threads.net',      'whatsapp.com',     'messenger.com',    'fb.com',
  'tiktok.com',       'snapchat.com',     'pinterest.com',    'tumblr.com',
  'discord.com',      'telegram.org',     'signal.org',

  // ── Developer tools ───────────────────────────────────────────────────
  'github.com',       'gitlab.com',       'bitbucket.org',    'stackoverflow.com',
  'npmjs.com',        'pypi.org',         'docker.com',       'hub.docker.com',
  'heroku.com',       'vercel.app',       'netlify.app',      'netlify.com',
  'firebase.google.com', 'firebaseapp.com', 'web.app',
  'replit.com',       'codepen.io',       'codesandbox.io',   'jsfiddle.net',
  'dev.to',           'hashnode.dev',     'medium.com',

  // ── Cloud & hosting ───────────────────────────────────────────────────
  'digitalocean.com', 'linode.com',       'vultr.com',        'cloudflare.com',
  'workers.dev',      'pages.dev',        'render.com',

  // ── Finance & banking (commonly scanned) ──────────────────────────────
  'paypal.com',       'stripe.com',       'wise.com',         'revolut.com',
  'coinbase.com',     'binance.com',

  // ── E-commerce ────────────────────────────────────────────────────────
  'ebay.com',         'etsy.com',         'shopify.com',      'flipkart.com',
  'myntra.com',       'meesho.com',

  // ── News & media ──────────────────────────────────────────────────────
  'bbc.com',          'bbc.co.uk',        'cnn.com',          'reuters.com',
  'nytimes.com',      'theguardian.com',  'ndtv.com',         'timesofindia.com',
  'hindustantimes.com','thehindu.com',     'livemint.com',

  // ── Knowledge & reference ─────────────────────────────────────────────
  'wikipedia.org',    'wikimedia.org',    'wikidata.org',     'britannica.com',
  'quora.com',        'reddit.com',

  // ── Local ─────────────────────────────────────────────────────────────
  'localhost',        '127.0.0.1',
]);

// ─── URL sanity check ────────────────────────────────────────────────────────
// Returns true only for URLs the extension should actually scan.
function isScannable(url) {
  if (!url) return false;

  // Block all browser-internal and non-http schemes
  const SKIP_PREFIXES = [
    'chrome://', 'chrome-extension://',
    'edge://', 'edge-extension://',
    'about:', 'data:', 'javascript:',
    'file://', 'blob:',
    'moz-extension://', 'safari-extension://',
    'opera://', 'vivaldi://',
  ];
  if (SKIP_PREFIXES.some(p => url.startsWith(p))) return false;

  // Block blank / empty pages
  if (url === 'about:blank' || url === 'about:newtab' || url.trim() === '') return false;

  // Must start with http:// or https://
  if (!url.startsWith('http://') && !url.startsWith('https://')) return false;

  return true;
}

// Returns true if the hostname matches a trusted domain or any subdomain of one.
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

// ─── Core scan function ───────────────────────────────────────────────────────
async function scanUrl(url, tabId = null) {
  if (!isScannable(url)) {
    try { chrome.action.setBadgeText({ text: '' }); } catch (_) {}
    return null;
  }

  // Short-circuit for trusted domains — no network call needed
  if (isTrustedDomain(url)) {
    try {
      chrome.action.setBadgeBackgroundColor({ color: '#4caf50' });
      chrome.action.setBadgeText({ text: 'SAFE' });
    } catch (_) {}
    return { prediction: 'Legitimate', confidence: 1.0, message: 'Trusted domain — skipped scan' };
  }

  try {
    if (tabId) {
      chrome.action.setBadgeText({ text: '...', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#9e9e9e', tabId });
    } else {
      chrome.action.setBadgeText({ text: '...' });
      chrome.action.setBadgeBackgroundColor({ color: '#9e9e9e' });
    }
  } catch (_) {}

  try {
    // ── Capture screenshot + call /predict simultaneously ─────────────────────
    // Screenshot is used for visual clone detection (pHash comparison against
    // known phishing pages) and for auto-adding hashes when Phishing is confirmed.
    // Stored in _capturedDataUrl so it can be reused for /hash/add without
    // a second capture call.
    let _capturedDataUrl = null;

    const screenshotPromise = (async () => {
      try {
        _capturedDataUrl = await chrome.tabs.captureVisibleTab(null, { format: 'png' });
        const res = await fetch('http://localhost:8000/screenshot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, screenshot: _capturedDataUrl })
        });
        return res.ok ? await res.json() : null;
      } catch (_) { return null; }  // best-effort, never blocks main result
    })();

    const predictPromise = fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    const [predictRes, screenshotResult] = await Promise.all([predictPromise, screenshotPromise]);

    if (!predictRes.ok) throw new Error(`HTTP ${predictRes.status}`);
    const data = await predictRes.json();

    let   confidence = data.confidence ?? 0.5;
    let   message    = data.message ?? 'Scanned';
    let   prediction = data.prediction ?? 'Legitimate'; // "Phishing"|"Uncertain"|"Legitimate"
    let   reasons    = data.reasons ?? [];

    // ── Visual clone override ─────────────────────────────────────────────────
    // If the page screenshot matches a known phishing page hash (Hamming ≤10),
    // override the verdict to Phishing regardless of what ML predicted.
    // Exception: skip override if the user already marked this page as safe
    // (status === 'user_reported' && prediction === 'Legitimate').
    const userReportedSafe = data.status === 'user_reported' && prediction === 'Legitimate';
    if (screenshotResult?.is_clone && !userReportedSafe) {
      if (prediction !== 'Phishing') {
        prediction = 'Phishing';
        message    = 'Page design matches a known phishing template';
        reasons    = [
          { label: 'Page visually clones a known phishing site',
            severity: 'high', feature: 'visual_clone', value: 1 },
          ...reasons
        ];
      }
      // Write the overridden result back to server cache so popup.js and
      // the next auto-scan all see the same consistent Phishing verdict.
      fetch('http://localhost:8000/cache/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, result: {
          status: data.status, prediction, confidence, message, reasons,
          gsb_checked: data.gsb_checked, vt: data.vt || {}, features: data.features || {}
        }})
      }).catch(() => {});
    }

    // ── Auto-add screenshot hash when Phishing is confirmed ───────────────────
    // Only when NOT a user_reported result to prevent re-hashing corrected pages.
    if (prediction === 'Phishing' && _capturedDataUrl && data.status !== 'user_reported') {
      fetch('http://localhost:8000/hash/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, screenshot: _capturedDataUrl })
      }).then(r => r.json())
        .then(d => console.log(`[PhishGuard] Hash auto-added: ${d.added} db_size=${d.db_size}`))
        .catch(() => {});
    }

    // ── Badge & notification ─────────────────────────────────────────────────
    // Server is the single decision-maker — no threshold re-evaluation here.
    //
    // "Phishing"  → red  PHSH badge + notification (confirmed threat)
    // "Uncertain" → amber WARN badge + notification (conflict: ML flagged, VT clears)
    // "Legitimate"→ green SAFE badge, no notification

    const isPhish     = prediction === 'Phishing';
    const isUncertain = prediction === 'Uncertain';

    // Per-tab badge — each tab shows its own verdict independently
    const badgeText  = isPhish ? 'PHSH' : isUncertain ? 'WARN' : 'SAFE';
    const badgeColor = isPhish ? '#d32f2f' : isUncertain ? '#e65100' : '#2e7d32';
    try {
      if (tabId) {
        chrome.action.setBadgeText({ text: badgeText, tabId });
        chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
      } else {
        chrome.action.setBadgeText({ text: badgeText });
        chrome.action.setBadgeBackgroundColor({ color: badgeColor });
      }
      // Store result for badge restoration when switching tabs
      if (tabId) _tabResults.set(tabId, { prediction, badgeText, badgeColor });
    } catch (_) {}

    if (isPhish || isUncertain) {
      let hostname = url;
      try { hostname = new URL(url).hostname.replace(/^www\./, ''); } catch (_) {}

      // Use a unique notification ID: tab + timestamp.
      // Previously we used a deterministic ID per hostname, which caused the OS
      // to silently update an existing notification on refresh instead of showing
      // a new toast. A unique ID guarantees a new notification every page load.
      const notifId = `phishguard-${tabId || 0}-${Date.now()}`;

      chrome.notifications.create(notifId, {
        type:    'basic',
        iconUrl: 'icons/icon48.png',
        title:   isPhish
          ? `Phishing Detected — ${hostname}`
          : `Suspicious Site — ${hostname}`,
        message: `${Math.round(confidence * 100)}% · ${message}`
      });
    }



    return { prediction, confidence, message, reasons };

  } catch (e) {
    console.error('PhishGuard scan error:', e);
    try {
      if (tabId) {
        chrome.action.setBadgeText({ text: 'ERR', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#ff9800', tabId });
      } else {
        chrome.action.setBadgeText({ text: 'ERR' });
        chrome.action.setBadgeBackgroundColor({ color: '#ff9800' });
      }
    } catch (_) {}
    return { prediction: 'Legitimate', confidence: 0, message: 'Scan failed — server unreachable' };
  }
}

// ─── Per-tab result store ─────────────────────────────────────────────────────
// Stores the last scan result (badge text + colour) per tab so the correct
// badge can be restored when the user switches between tabs.
//
// content.js is the ONLY scan trigger (re-injects fresh on every navigation
// and every refresh). This eliminates the dual-trigger problem that caused
// notifications to be silently suppressed on refresh.
const _tabResults = new Map();  // tabId → { prediction, badgeText, badgeColor }

// ─── Message listener ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

  // ── Scan request (sole trigger — from content.js on every page load) ────────
  // sender.tab.id lets us set per-tab badge and unique per-tab notifications.
  if (request.action === 'scan') {
    const tabId = sender.tab?.id ?? null;
    scanUrl(request.url, tabId)
      .then(result => sendResponse(result ?? { prediction: 'Legitimate', confidence: 0, message: 'Skipped' }))
      .catch(err => {
        console.error('PhishGuard scan error:', err);
        sendResponse({ prediction: 'Legitimate', confidence: 0, message: 'Error' });
      });
    return true;  // keep message channel open for async response
  }

  // ── Hash add (called by popup.js false_negative report) ─────────────────────
  if (request.action === 'addHash') {
    (async () => {
      try {
        const dataUrl = await chrome.tabs.captureVisibleTab(null, { format: 'png' });
        const res  = await fetch('http://localhost:8000/hash/add', {
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

  // ── Hash remove by URL (called by popup.js false_positive report) ───────────
  if (request.action === 'removeHash') {
    (async () => {
      try {
        const res  = await fetch('http://localhost:8000/hash/remove-by-url', {
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

// ─── Badge restoration on tab switch ─────────────────────────────────────────
// When the user switches to a tab that was already scanned, restore its badge.
// We do NOT re-scan here — content.js handles scanning on every page load.
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const stored = _tabResults.get(tabId);
  if (stored) {
    // Restore the badge for this tab
    try {
      chrome.action.setBadgeText({ text: stored.badgeText, tabId });
      chrome.action.setBadgeBackgroundColor({ color: stored.badgeColor, tabId });
    } catch (_) {}
  } else {
    // Tab not yet scanned (e.g. just opened) — clear badge
    try {
      chrome.action.setBadgeText({ text: '', tabId });
    } catch (_) {}
  }
});

// Clean up stored result when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  _tabResults.delete(tabId);
});