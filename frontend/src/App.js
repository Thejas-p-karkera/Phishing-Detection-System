import React, { useState } from 'react';
import './App.css';

const API_URL    = 'http://localhost:8000/predict';
const REPORT_URL = 'http://localhost:8000/report';

const SEVERITY_ICON = { high: '🔴', medium: '🟡', low: '🔵' };

function verdictClass(p) {
  if (p === 'Phishing')  return 'phish';
  if (p === 'Uncertain') return 'uncertain';
  return 'safe';
}
function verdictIcon(p) {
  if (p === 'Phishing')  return '🚨';
  if (p === 'Uncertain') return '⚠️';
  return '✅';
}

// ── Confidence bar ────────────────────────────────────────────────────────────
function ConfidenceBar({ value, prediction }) {
  const pct = (value * 100).toFixed(1);
  const fillClass =
    prediction === 'Phishing'  ? 'conf-fill--phish' :
    prediction === 'Uncertain' ? 'conf-fill--uncertain' :
                                 'conf-fill--safe';
  return (
    <div className="conf-wrapper">
      <div className="conf-labels">
        <span className="conf-label-text">Confidence</span>
        <span className="conf-value">{pct}%</span>
      </div>
      <div className="conf-track">
        <div className={`conf-fill ${fillClass}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

// ── Source badges ─────────────────────────────────────────────────────────────
// Mirrors popup.js badge logic exactly, with web-app-specific status handling.
function SourceBadges({ data }) {
  const status     = data.status;
  const gsbChecked = data.gsb_checked;
  const reasons    = data.reasons || [];
  const gsbHit     = reasons.some(r => r.feature === 'gsb');
  const cloneHit   = reasons.some(r => r.feature === 'visual_clone');
  const vt         = data.vt || {};
  const vtChecked  = vt.checked;
  const vtVerdict  = vt.verdict || 'unknown';
  const vtMal      = vt.malicious ?? 0;
  const vtTotal    = vt.total ?? 0;
  const vtTrust    = vt.trust_score ?? -1;

  // ── Status-specific single badge ──────────────────────────────────────────
  // These statuses bypass the full pipeline — show a descriptive badge instead
  // of "ML Model" which would be factually incorrect.
  if (status === 'trusted') {
    return <div className="badges"><span className="badge badge--trusted">✓ Verified Safe List</span></div>;
  }
  if (status === 'known') {
    return <div className="badges"><span className="badge badge--known">📋 Known URL (training data)</span></div>;
  }
  if (status === 'user_reported') {
    return <div className="badges"><span className="badge badge--user-reported">👤 User Reported</span></div>;
  }
  if (status === 'skipped') {
    return <div className="badges"><span className="badge badge--gsb-skip">⏭ Not scannable</span></div>;
  }

  // ── Full pipeline badges (status: 'predicted' or 'feed_match') ────────────
  let vtBadge = null;
  if (vtChecked) {
    const vtClass = vtVerdict === 'malicious' ? 'badge--vt-bad'
                  : vtVerdict === 'suspicious' ? 'badge--vt-warn'
                  : 'badge--vt-ok';
    const vtText  = vtVerdict === 'malicious'
      ? `🔬 VT: ${vtMal}/${vtTotal} malicious`
      : vtVerdict === 'suspicious'
      ? `🔬 VT: suspicious · Trust ${vtTrust}/100`
      : `🔬 VT: ${vtTotal} vendors · Trust ${vtTrust}/100`;
    vtBadge = <span className={`badge ${vtClass}`}>{vtText}</span>;
  } else if (vt.source === 'vt_skipped') {
    vtBadge = <span className="badge badge--vt-skip">🔬 VT: No API key</span>;
  }

  return (
    <div className="badges">
      <span className="badge badge--ml">🤖 ML Model</span>

      {/* GSB badge */}
      {gsbChecked === 'gsb_skipped' && (
        <span className="badge badge--gsb-skip">🛡 GSB: No API key</span>
      )}
      {gsbChecked && gsbChecked !== 'gsb_skipped' && !gsbHit && (
        <span className="badge badge--gsb-ok">🛡 GSB: Clean</span>
      )}
      {gsbHit && <span className="badge badge--gsb-hit">🛡 GSB: FLAGGED</span>}

      {/* VT badge */}
      {vtBadge}

      {/* Visual clone badge — can't happen in web app (no screenshot API)
          but shown if server returns it for completeness */}
      {cloneHit && <span className="badge badge--clone">📸 Visual Clone</span>}

      {/* PhishTank/OpenPhish feed signal */}
      {reasons.some(r => r.feature === 'phishing_feed') && (
        <span className="badge badge--feed">⚠️ PhishTank/OpenPhish</span>
      )}
    </div>
  );
}

// ── Reasons list ──────────────────────────────────────────────────────────────
function ReasonsList({ reasons, prediction, status }) {
  if (!reasons || reasons.length === 0) return null;

  // For Legitimate user_reported, show a note instead of hiding silently
  if (prediction === 'Legitimate' && status === 'user_reported') {
    return (
      <p className="user-report-note">
        ✓ This site was marked as safe by a user report. The verdict is valid for 24 hours.
      </p>
    );
  }

  // Show reasons only for Phishing and Uncertain (same as popup.js)
  if (prediction !== 'Phishing' && prediction !== 'Uncertain') return null;

  const title = prediction === 'Uncertain' ? 'Signals detected' : 'Why we flagged this';

  return (
    <div className="reasons">
      <p className="reasons-title">{title}</p>
      <ul className="reasons-list">
        {reasons.map((r, i) => (
          <li key={i} className={`reason reason--${r.severity}`}>
            <span className="reason-icon">{SEVERITY_ICON[r.severity] || '⚪'}</span>
            <span>{r.label}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ── Report button(s) ──────────────────────────────────────────────────────────
// Mirrors popup.js exactly:
//   Phishing   → "Mark as Safe (False Positive)" only
//   Uncertain  → BOTH buttons side by side
//   Legitimate → "Report as Phishing" only
//   trusted / known / skipped → no buttons (system is confident)
//
// After a successful report, auto-refreshes the result from the server
// so the card immediately reflects the corrected verdict.
function ReportButtons({ url, prediction, status, onRefresh }) {
  const [safeState,  setSafeState]  = useState('idle');
  const [phishState, setPhishState] = useState('idle');

  // Don't show buttons for system-confident statuses
  if (status === 'trusted' || status === 'known' || status === 'skipped') return null;

  const sendReport = async (reportType, setStateFn) => {
    setStateFn('sending');
    try {
      const res = await fetch(REPORT_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, report_type: reportType, reported_by: 'webapp' })
      });
      if (!res.ok) throw new Error(`Server ${res.status}`);
      setStateFn('sent');
      // Auto-refresh result after 600ms so user sees the corrected verdict
      setTimeout(() => onRefresh(url), 600);
    } catch (_) {
      setStateFn('error');
    }
  };

  const isPhish     = prediction === 'Phishing';
  const isUncertain = prediction === 'Uncertain';

  // Phishing → one button
  if (isPhish) {
    if (safeState === 'sent')  return <p className="report-thanks">✓ Marked as safe — refreshing…</p>;
    if (safeState === 'error') return <p className="report-thanks report-thanks--error">⚠ Report failed</p>;
    return (
      <button
        className="report-btn"
        onClick={() => sendReport('false_positive', setSafeState)}
        disabled={safeState === 'sending'}
      >
        {safeState === 'sending' ? 'Sending…' : 'Mark as Safe (False Positive)'}
      </button>
    );
  }

  // Uncertain → both buttons
  if (isUncertain) {
    return (
      <div className="report-pair">
        <button
          className="report-btn report-btn--half"
          onClick={() => sendReport('false_positive', setSafeState)}
          disabled={safeState === 'sending' || safeState === 'sent'}
        >
          {safeState === 'sending' ? 'Sending…'
           : safeState === 'sent'  ? '✓ Done'
           : 'Mark as Safe'}
        </button>
        <button
          className="report-btn report-btn--half report-btn--danger"
          onClick={() => sendReport('false_negative', setPhishState)}
          disabled={phishState === 'sending' || phishState === 'sent'}
        >
          {phishState === 'sending' ? 'Sending…'
           : phishState === 'sent'  ? '✓ Done'
           : 'Report as Phishing'}
        </button>
      </div>
    );
  }

  // Legitimate → one button
  if (phishState === 'sent')  return <p className="report-thanks">✓ Reported — refreshing…</p>;
  if (phishState === 'error') return <p className="report-thanks report-thanks--error">⚠ Report failed</p>;
  return (
    <button
      className="report-btn report-btn--danger"
      onClick={() => sendReport('false_negative', setPhishState)}
      disabled={phishState === 'sending'}
    >
      {phishState === 'sending' ? 'Sending…' : 'Report as Phishing'}
    </button>
  );
}

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  const [url,     setUrl]     = useState('');
  const [result,  setResult]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');

  const runScan = async (targetUrl) => {
    setLoading(true); setError(''); setResult(null);
    try {
      const res  = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Prediction failed');
      setResult({ ...data, _submittedUrl: targetUrl });
    } catch (err) {
      setError(err.message || 'Request failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    await runScan(url.trim());
  };

  // Called by ReportButtons after a successful report — re-fetches the
  // corrected cached result so the card updates without user re-submitting.
  const handleRefresh = (targetUrl) => {
    runScan(targetUrl);
  };

  const prediction = result?.prediction ?? null;
  const vc         = prediction ? verdictClass(prediction) : null;

  return (
    <div className="app">
      <header className="header">
        <h1>🔍 PhishGuard</h1>
        <p>Advanced phishing detection</p>
      </header>

      <main className="main">
        <form onSubmit={handleSubmit} className="form">
          <div className="input-row">
            <input
              type="url"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://example.com"
              className={`url-input${
                vc === 'phish'     ? ' url-input--phish' :
                vc === 'uncertain' ? ' url-input--uncertain' : ''}`}
              required
            />
            <button type="submit" disabled={loading} className="submit-btn">
              {loading ? 'Analysing…' : 'Check URL'}
            </button>
          </div>
        </form>

        {error && <div className="error-banner">⚠ {error}</div>}

        {result && (
          <div className={`card card--${vc}`}>

            {/* Verdict */}
            <div className="verdict-row">
              <span className="verdict-emoji">{verdictIcon(prediction)}</span>
              <div>
                <h2 className="verdict-title">{prediction}</h2>
                <p className="verdict-message">{result.message}</p>
              </div>
            </div>

            {/* Source badges */}
            <SourceBadges data={result} />

            {/* Confidence bar */}
            <ConfidenceBar value={result.confidence} prediction={prediction} />

            {/* Reasons */}
            <ReasonsList
              reasons={result.reasons}
              prediction={prediction}
              status={result.status}
            />

            {/* Raw feature vector — only for full ML predictions */}
            {result.status === 'predicted' && result.features &&
              Object.keys(result.features).length > 0 && (
              <details className="feature-details">
                <summary>
                  ▶ Raw feature vector ({Object.keys(result.features).length} features)
                </summary>
                <pre className="feature-pre">
                  {JSON.stringify(result.features, null, 2)}
                </pre>
              </details>
            )}

            {/* Report buttons with auto-refresh */}
            <ReportButtons
              url={result._submittedUrl}
              prediction={prediction}
              status={result.status}
              onRefresh={handleRefresh}
            />
          </div>
        )}
      </main>
    </div>
  );
}