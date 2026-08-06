import React, { useState, useEffect, useCallback } from 'react';
import './App.css';

// ── Status chip — coloured by scan pathway ───────────────────────────────────
const STATUS_META = {
  predicted:    { label: 'Predicted',      cls: 'chip--predicted'    },
  cached:       { label: 'Cached',       cls: 'chip--cached'       },
  trusted:      { label: 'Trusted',      cls: 'chip--trusted'      },
  known:        { label: 'Known URL',    cls: 'chip--known'        },
  skipped:      { label: 'Skipped',      cls: 'chip--skipped'      },
  quick:        { label: 'Quick',        cls: 'chip--quick'        },
  feed_match:   { label: 'Feed Hit',     cls: 'chip--feed'         },
  user_reported:{ label: 'User Reported',     cls: 'chip--reported'     },
  visual_clone: { label: 'Visual Clone', cls: 'chip--visual-clone' },
};
function StatusChip({ s }) {
  const m = STATUS_META[s] || { label: s, cls: '' };
  return <span className={`chip ${m.cls}`}>{m.label}</span>;
}


const BASE = 'http://localhost:8000';
const get  = path => fetch(`${BASE}${path}`).then(r => r.json()).catch(() => null);

const PAGE_SIZE = 10; // rows per page in all tables

// ── Helpers ───────────────────────────────────────────────────────────────────
function timeAgo(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 5)     return 'just now';
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function fmtTime(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function truncUrl(url, max = 52) {
  if (!url || url.length <= max) return url;
  return url.slice(0, max) + '…';
}

// ── Pagination controls ───────────────────────────────────────────────────────
function Pagination({ page, totalPages, onChange }) {
  if (totalPages <= 1) return null;

  const pages = [];
  const delta = 2;
  const left  = Math.max(1, page - delta);
  const right = Math.min(totalPages, page + delta);

  if (left > 1) {
    pages.push(1);
    if (left > 2) pages.push('…');
  }
  for (let i = left; i <= right; i++) pages.push(i);
  if (right < totalPages) {
    if (right < totalPages - 1) pages.push('…');
    pages.push(totalPages);
  }

  return (
    <div className="pagination">
      <button className="pg-btn" onClick={() => onChange(page - 1)} disabled={page === 1}>
        ‹ Prev
      </button>
      {pages.map((p, i) =>
        p === '…'
          ? <span key={`el-${i}`} className="pg-ellipsis">…</span>
          : <button
              key={p}
              className={`pg-btn ${page === p ? 'pg-btn--on' : ''}`}
              onClick={() => onChange(p)}
            >{p}</button>
      )}
      <button className="pg-btn" onClick={() => onChange(page + 1)} disabled={page === totalPages}>
        Next ›
      </button>
    </div>
  );
}

// ── Verdict badge ─────────────────────────────────────────────────────────────
function VBadge({ v }) {
  if (v === 'Phishing')   return <span className="vbadge vbadge--phish">🚨 Phishing</span>;
  if (v === 'Uncertain')  return <span className="vbadge vbadge--uncert">⚠️ Uncertain</span>;
  if (v === 'Legitimate') return <span className="vbadge vbadge--safe">✅ Safe</span>;
  return <span className="vbadge">{v}</span>;
}

// ── Stat card ─────────────────────────────────────────────────────────────────
function StatCard({ icon, label, value, accent, sub }) {
  return (
    <div className={`sc sc--${accent}`}>
      <div className="sc-icon">{icon}</div>
      <div className="sc-body">
        <div className="sc-value">{value ?? '—'}</div>
        <div className="sc-label">{label}</div>
        {sub && <div className="sc-sub">{sub}</div>}
      </div>
      <div className="sc-glow" />
    </div>
  );
}

// ── Theme toggle ──────────────────────────────────────────────────────────────
function ThemeToggle({ theme, onToggle }) {
  const isLight = theme === 'light';
  return (
    <button className="theme-toggle" onClick={onToggle}>
      <span className="theme-toggle-label">
        <span className="theme-toggle-icon">{isLight ? '☀️' : '🌙'}</span>
        {isLight ? 'Light Mode' : 'Dark Mode'}
      </span>
      <span className="theme-toggle-switch" />
    </button>
  );
}

// ── Refresh button ─────────────────────────────────────────────────────────────
function RefreshBtn({ onClick, loading }) {
  return (
    <button className={`refresh-btn ${loading ? 'refresh-btn--spin' : ''}`} onClick={onClick}>
      ↺ {loading ? 'Refreshing…' : 'Refresh'}
    </button>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// OVERVIEW TAB
// ══════════════════════════════════════════════════════════════════════════════
function OverviewTab({ stats, loading, onRefresh }) {
  if (!stats && !loading) return (
    <div className="empty-state">
      <div className="empty-icon">🔌</div>
      <p>Cannot reach the backend at <code>localhost:8000</code>.</p>
      <p className="muted">Make sure the FastAPI server is running.</p>
      <button className="refresh-btn" onClick={onRefresh}>Retry</button>
    </div>
  );

  const s         = stats || {};
  const rate      = s.phishing_rate ?? 0;
  const rateColor = rate > 20 ? 'red' : rate > 8 ? 'amber' : 'green';

  return (
    <div className="tab-content">
      <div className="section-hdr">
        <h2>System Overview</h2>
        <RefreshBtn onClick={onRefresh} loading={loading} />
      </div>

      <div className="sc-grid">
        <StatCard icon="🔍" label="Total Scans"       value={(s.total_scans ?? 0).toLocaleString()} accent="blue" />
        <StatCard icon="🚨" label="Phishing Detected" value={(s.phishing ?? 0).toLocaleString()}     accent="red"
          sub={`${rate}% of all scans`} />
        <StatCard icon="⚠️" label="Uncertain"         value={(s.uncertain ?? 0).toLocaleString()}    accent="amber" />
        <StatCard icon="✅" label="Legitimate"         value={(s.legitimate ?? 0).toLocaleString()}   accent="green" />
        <StatCard icon="📸" label="Hash DB Size"       value={s.hash_db_size ?? 0}                   accent="purple"
          sub="Phishing page hashes" />
        <StatCard icon="📋" label="User Reports"       value={s.reports ?? 0}                        accent="blue"
          sub="False pos / neg" />
      </div>

      {/* Phishing rate bar */}
      <div className="panel">
        <div className="panel-title">📈 Phishing Detection Rate</div>
        <div className="rate-row">
          <div className="rate-bar-wrap">
            <div className={`rate-bar rate-bar--${rateColor}`} style={{ width: `${Math.min(rate, 100)}%` }} />
          </div>
          <span className={`rate-val rate-val--${rateColor}`}>{rate}%</span>
        </div>
        <div className="rate-legend">
          <span><span className="dot dot--green" /> Safe ({(s.legitimate ?? 0).toLocaleString()})</span>
          <span><span className="dot dot--amber" /> Uncertain ({(s.uncertain ?? 0).toLocaleString()})</span>
          <span><span className="dot dot--red"   /> Phishing ({(s.phishing ?? 0).toLocaleString()})</span>
        </div>
      </div>

      {/* Top flagged domains */}
      {s.top_flagged_domains?.length > 0 && (
        <div className="panel">
          <div className="panel-title">🎯 Most Flagged Domains</div>
          <div className="domain-list">
            {s.top_flagged_domains.map(([domain, count], i) => {
              const maxCount = s.top_flagged_domains[0][1];
              return (
                <div key={domain} className="domain-row">
                  <span className="domain-rank mono">#{i + 1}</span>
                  <span className="domain-name mono">{domain}</span>
                  <div className="domain-track">
                    <div className="domain-fill" style={{ width: `${(count / maxCount) * 100}%` }} />
                  </div>
                  <span className="domain-count">{count}×</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Status pills */}
      <div className="status-row">
        <div className={`status-pill ${s.feed_status?.loaded ? 'status-pill--ok' : 'status-pill--err'}`}>
          {s.feed_status?.loaded ? '✅' : '❌'} PhishTank / OpenPhish
          {s.feed_status?.url_count > 0 && (
            <span className="muted"> · {s.feed_status.url_count.toLocaleString()} URLs</span>
          )}
        </div>
        <div className={`status-pill ${s.whitelist?.tranco?.loaded ? 'status-pill--ok' : 'status-pill--warn'}`}>
          {s.whitelist?.tranco?.loaded ? '✅' : '⏳'} Tranco Whitelist
          {s.whitelist?.tranco?.domain_count > 0 && (
            <span className="muted"> · {s.whitelist.tranco.domain_count.toLocaleString()} domains</span>
          )}
        </div>
        <div className="status-pill status-pill--ok">
          🗄️ Cache: {(s.cache_stats?.result_cache ?? 0) + (s.cache_stats?.whois_cache ?? 0) + (s.cache_stats?.vt_cache ?? 0)} entries
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// SCAN HISTORY TAB  — 10 rows per page with pagination
// ══════════════════════════════════════════════════════════════════════════════
function ScanHistoryTab({ history, loading, onRefresh }) {
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [page,   setPage]   = useState(1);

  const handleFilter = (f) => { setFilter(f); setPage(1); };
  const handleSearch = (v) => { setSearch(v);  setPage(1); };

  const filtered = (history || []).filter(h => {
    if (filter !== 'all' && h.prediction.toLowerCase() !== filter) return false;
    if (search && !h.url.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage   = Math.min(page, totalPages);
  const pageItems  = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  const counts = {
    all:        (history || []).length,
    phishing:   (history || []).filter(h => h.prediction === 'Phishing').length,
    uncertain:  (history || []).filter(h => h.prediction === 'Uncertain').length,
    legitimate: (history || []).filter(h => h.prediction === 'Legitimate').length,
  };

  return (
    <div className="tab-content">
      <div className="section-hdr">
        <h2>Scan History</h2>
        <RefreshBtn onClick={onRefresh} loading={loading} />
      </div>

      <div className="toolbar">
        <input
          className="search-inp"
          placeholder="🔍 Filter by URL…"
          value={search}
          onChange={e => handleSearch(e.target.value)}
        />
        <div className="pills">
          {['all', 'phishing', 'uncertain', 'legitimate'].map(f => (
            <button
              key={f}
              className={`pill pill--${f} ${filter === f ? 'pill--on' : ''}`}
              onClick={() => handleFilter(f)}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
              <span className="pill-count">{counts[f]}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th className="th-num">#</th>
              <th>URL</th>
              <th>Verdict</th>
              <th>Confidence</th>
              <th>Status</th>
              <th>When</th>
            </tr>
          </thead>
          <tbody>
            {pageItems.length === 0 && (
              <tr>
                <td colSpan="6" className="tbl-empty">
                  {loading
                    ? 'Loading…'
                    : (history || []).length === 0
                      ? 'No scans recorded yet. Scan a URL using the extension or browser.'
                      : 'No results match the filter.'}
                </td>
              </tr>
            )}
            {pageItems.map((h, i) => {
              // Recent entry = #1, older entries get higher numbers
              const absNum = (safePage - 1) * PAGE_SIZE + i + 1;
              return (
                <tr key={i} className={`trow trow--${h.prediction.toLowerCase()}`}>
                  <td className="mono muted td-num">{absNum}</td>
                  <td className="td-url">
                    <a href={h.url} target="_blank" rel="noopener noreferrer"
                       className="url-link mono" title={h.url}>
                      {truncUrl(h.url)}
                    </a>
                  </td>
                  <td><VBadge v={h.prediction} /></td>
                  <td className="mono td-conf">{(h.confidence * 100).toFixed(1)}%</td>
                  <td><StatusChip s={h.status} /></td>
                  <td className="mono muted td-time" title={h.timestamp}>{timeAgo(h.timestamp)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="tbl-footer tbl-footer--flex">
        <span>
          Showing <strong>{(safePage - 1) * PAGE_SIZE + 1}–{(safePage - 1) * PAGE_SIZE + pageItems.length}</strong> of{' '}
          <strong>{filtered.length}</strong> entries
          {filtered.length !== (history || []).length &&
            ` (filtered from ${(history || []).length} total)`}
        </span>
        <Pagination page={safePage} totalPages={totalPages} onChange={setPage} />
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// HASH MANAGER TAB  — shows URL source for each hash, paginated
// ══════════════════════════════════════════════════════════════════════════════
function HashManagerTab({ hashes, loading, onRefresh }) {
  const [deleting, setDeleting] = useState(null);
  const [msg,      setMsg]      = useState('');
  const [search,   setSearch]   = useState('');
  const [page,     setPage]     = useState(1);

  const deleteHash = async (h) => {
    setDeleting(h);
    setMsg('');
    try {
      const res  = await fetch(`${BASE}/hash/delete?hash_str=${encodeURIComponent(h)}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok) {
        setMsg(`✓ Removed hash for: ${hashUrlMap[h] || h.slice(0, 16) + '…'}`);
        onRefresh();
      } else {
        setMsg(`✗ ${data.detail || 'Delete failed'}`);
      }
    } catch {
      setMsg('✗ Network error');
    } finally {
      setDeleting(null);
    }
  };

  // hash → url lookup (sent by the updated /hash/list endpoint)
  const hashUrlMap = hashes?.hash_url_map || {};

  // Search works across both hash string and the associated URL
  const list = (hashes?.hashes || []).filter(h => {
    if (!search) return true;
    const url = hashUrlMap[h] || '';
    return h.includes(search) || url.toLowerCase().includes(search.toLowerCase());
  });

  const totalPages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
  const safePage   = Math.min(page, totalPages);
  const pageItems  = list.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  return (
    <div className="tab-content">
      <div className="section-hdr">
        <h2>Phishing Hash Database</h2>
        <RefreshBtn onClick={onRefresh} loading={loading} />
      </div>

      {msg && (
        <div className={`alert ${msg.startsWith('✓') ? 'alert--ok' : 'alert--err'}`}>{msg}</div>
      )}

      <div className="panel">
        {/* Header row — count + ImageHash status */}
        <div className="hash-meta-row">
          <div className="hash-meta-stat">
            <span className="hash-meta-num">{hashes?.db_size ?? 0}</span>
            <span className="hash-meta-lbl">hashes stored</span>
          </div>
          <div className={`hash-avail ${hashes?.imagehash_available ? 'hash-avail--ok' : 'hash-avail--err'}`}>
            {hashes?.imagehash_available ? '✅ ImageHash ready' : '❌ ImageHash not installed'}
          </div>
        </div>

        {!hashes?.imagehash_available && (
          <div className="info-box">
            Install ImageHash to enable visual clone detection:<br/>
            <code>pip install Pillow ImageHash --break-system-packages</code>
          </div>
        )}

        <input
          className="search-inp"
          placeholder="🔍 Filter by URL or hash…"
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(1); }}
          style={{ marginBottom: '12px' }}
        />

        {list.length === 0 ? (
          <div className="empty-state" style={{ padding: '2rem 0' }}>
            <div className="empty-icon">📸</div>
            <p>{loading ? 'Loading…' : 'No phishing hashes stored.'}</p>
            <p className="muted">
              When the extension detects a phishing page and you click<br/>
              "Report as Phishing", a perceptual hash of that page's screenshot<br/>
              is stored here for future visual clone detection.
              Most recently added hashes appear at the top.
            </p>
          </div>
        ) : (
          <>
            {/* Column headers */}
            <div className="hash-list-header">
              <span className="hash-col-idx">#</span>
              <span className="hash-col-url">Source URL</span>
              <span className="hash-col-hash">Perceptual Hash</span>
              <span className="hash-col-del" />
            </div>

            <div className="hash-list">
              {pageItems.map((h, i) => {
                const sourceUrl = hashUrlMap[h];
                return (
                  <div key={h} className="hash-row">
                    <span className="hash-idx mono muted hash-col-idx">
                      #{(safePage - 1) * PAGE_SIZE + i + 1}
                    </span>

                    {/* Source URL — clickable link if known, fallback label if not */}
                    <span className="hash-col-url">
                      {sourceUrl
                        ? <a href={sourceUrl} target="_blank" rel="noopener noreferrer"
                             className="hash-url-link" title={sourceUrl}>
                            {sourceUrl.length > 55 ? sourceUrl.slice(0, 55) + '…' : sourceUrl}
                          </a>
                        : <span className="hash-no-url muted">Unknown origin</span>
                      }
                    </span>

                    <span className="hash-val mono hash-col-hash">{h}</span>

                    <button
                      className="btn-del hash-col-del"
                      onClick={() => deleteHash(h)}
                      disabled={deleting === h}
                      title={sourceUrl ? `Remove hash for ${sourceUrl}` : 'Remove this hash'}
                    >
                      {deleting === h ? '…' : '🗑️'}
                    </button>
                  </div>
                );
              })}
            </div>

            <div className="tbl-footer tbl-footer--flex" style={{ marginTop: '10px' }}>
              <span>
                Showing <strong>{pageItems.length}</strong> of <strong>{list.length}</strong> hashes
              </span>
              <Pagination page={safePage} totalPages={totalPages} onChange={setPage} />
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// REPORTS TAB
// — "Reported By" column removed (value is always "popup")
// — summary cards are now clickable filter buttons
// — paginated, 10 rows per page
// ══════════════════════════════════════════════════════════════════════════════
function ReportsTab({ reports, loading, onRefresh }) {
  const [filter, setFilter] = useState('all');  // 'all' | 'false_positive' | 'false_negative'
  const [page,   setPage]   = useState(1);

  const handleFilter = (f) => {
    setFilter(prev => prev === f ? 'all' : f); // clicking active filter deselects it
    setPage(1);
  };

  const all        = [...(reports?.reports || [])].reverse();
  const fpCount    = all.filter(r => r.report_type === 'false_positive').length;
  const fnCount    = all.filter(r => r.report_type === 'false_negative').length;

  const list       = filter === 'all' ? all : all.filter(r => r.report_type === filter);
  const totalPages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
  const safePage   = Math.min(page, totalPages);
  const pageItems  = list.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  return (
    <div className="tab-content">
      <div className="section-hdr">
        <h2>User Reports Log</h2>
        <RefreshBtn onClick={onRefresh} loading={loading} />
      </div>

      {/* Clickable filter cards */}
      <div className="reports-summary">
        <button
          className={`report-stat report-stat--fp ${filter === 'false_positive' ? 'report-stat--on' : ''}`}
          onClick={() => handleFilter('false_positive')}
          title="Click to filter by False Positives"
        >
          <span className="report-stat-num">{fpCount}</span>
          <span className="report-stat-lbl">
            False Positives<br/><small>(marked as safe)</small>
          </span>
          <span className="report-stat-hint">
            {filter === 'false_positive' ? '✕ Clear filter' : 'Click to filter'}
          </span>
        </button>
        <button
          className={`report-stat report-stat--fn ${filter === 'false_negative' ? 'report-stat--on' : ''}`}
          onClick={() => handleFilter('false_negative')}
          title="Click to filter by False Negatives"
        >
          <span className="report-stat-num">{fnCount}</span>
          <span className="report-stat-lbl">
            False Negatives<br/><small>(reported phishing)</small>
          </span>
          <span className="report-stat-hint">
            {filter === 'false_negative' ? '✕ Clear filter' : 'Click to filter'}
          </span>
        </button>
      </div>

      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th className="th-num">#</th>
              <th>URL</th>
              <th>Report Type</th>
              <th>Corrected To</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {pageItems.length === 0 && (
              <tr>
                <td colSpan="5" className="tbl-empty">
                  {loading ? 'Loading…' : 'No reports submitted yet.'}
                </td>
              </tr>
            )}
            {pageItems.map((r, i) => (
              <tr key={i} className={`trow trow--${r.report_type === 'false_positive' ? 'legitimate' : 'phishing'}`}>
                <td className="mono muted td-num">
                  {/* Recent = #1, older = higher numbers */}
                  {(safePage - 1) * PAGE_SIZE + i + 1}
                </td>
                <td className="td-url">
                  <a href={r.url} target="_blank" rel="noopener noreferrer"
                     className="url-link mono" title={r.url}>
                    {truncUrl(r.url)}
                  </a>
                </td>
                <td>
                  <span className={`chip ${r.report_type === 'false_positive' ? 'chip--fp' : 'chip--fn'}`}>
                    {r.report_type === 'false_positive' ? '✓ False Positive' : '⚠ False Negative'}
                  </span>
                </td>
                <td><VBadge v={r.corrected_to} /></td>
                <td className="mono muted td-time" title={r.timestamp}>{timeAgo(r.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="tbl-footer tbl-footer--flex">
        <span>
          {filter !== 'all'
            ? <>Showing <strong>{list.length}</strong> {filter === 'false_positive' ? 'false positive' : 'false negative'} report{list.length !== 1 ? 's' : ''}</>
            : <>{all.length} total report{all.length !== 1 ? 's' : ''}</>
          }
        </span>
        <Pagination page={safePage} totalPages={totalPages} onChange={setPage} />
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// SYSTEM STATUS TAB
// — API Endpoints section removed
// — VT Cache TTL corrected to 24h (matches app.py ttl=86400)
// ══════════════════════════════════════════════════════════════════════════════
function SystemTab({ stats, loading, onRefresh }) {
  const [clearing, setClearing] = useState(false);
  const [clearMsg, setClearMsg] = useState('');

  const clearCache = async () => {
    setClearing(true);
    setClearMsg('');
    try {
      const res  = await fetch(`${BASE}/cache/clear`, { method: 'POST' });
      const data = await res.json();
      const { result_cache: r, whois_cache: w, vt_cache: v } = data.cleared || {};
      setClearMsg(`✓ Cleared ${(r||0)+(w||0)+(v||0)} entries (result: ${r}, whois: ${w}, vt: ${v})`);
      onRefresh();
    } catch {
      setClearMsg('✗ Failed — is the server running?');
    } finally {
      setClearing(false);
    }
  };

  if (!stats && !loading) return (
    <div className="empty-state">
      <div className="empty-icon">🔌</div>
      <p className="muted">Backend unreachable</p>
    </div>
  );

  const { cache_stats, feed_status, whitelist } = stats || {};

  return (
    <div className="tab-content">
      <div className="section-hdr">
        <h2>System Status</h2>
        <RefreshBtn onClick={onRefresh} loading={loading} />
      </div>

      {/* Cache */}
      <div className="panel">
        <div className="panel-title">🗄️ Cache</div>
        <div className="kv-grid">
          {/* All three caches use ttl=86400 (24h) in app.py */}
          <KVRow k="Result Cache" v={`${cache_stats?.result_cache ?? '—'} entries`} icon="📦" note="24h TTL" />
          <KVRow k="WHOIS Cache"  v={`${cache_stats?.whois_cache  ?? '—'} entries`} icon="📋" note="24h TTL" />
          <KVRow k="VT Cache"     v={`${cache_stats?.vt_cache     ?? '—'} entries`} icon="🔬" note="24h TTL" />
        </div>
        {clearMsg && (
          <div className={`alert ${clearMsg.startsWith('✓') ? 'alert--ok' : 'alert--err'}`}>
            {clearMsg}
          </div>
        )}
        <button className="btn-danger" onClick={clearCache} disabled={clearing}>
          {clearing ? '⏳ Clearing…' : '🗑️ Clear All Caches'}
        </button>
        <p className="panel-note">
          Forces fresh scans for all URLs — use after updating detection logic.
        </p>
      </div>

      {/* Phishing feeds */}
      <div className="panel">
        <div className="panel-title">📡 Phishing Feeds (PhishTank + OpenPhish)</div>
        <div className="kv-grid">
          <KVRow
            k="Status"
            v={feed_status?.loaded ? 'Loaded ✅' : 'Not loaded ❌'}
            cls={feed_status?.loaded ? 'text-green' : 'text-red'}
            icon="🟢"
          />
          <KVRow k="URL Count" v={(feed_status?.url_count ?? 0).toLocaleString() + ' known phishing URLs'} icon="🔗" />
          <KVRow k="Sources"   v={feed_status?.sources?.join(', ') || '—'}                                  icon="📌" />
          <KVRow k="Loaded At" v={feed_status?.loaded_at ? fmtTime(feed_status.loaded_at) : '—'}            icon="🕒" />
          {feed_status?.error && <KVRow k="Error" v={feed_status.error} cls="text-red" icon="⚠️" />}
        </div>
        <p className="panel-note">
          Feeds are refreshed on server restart. Restart daily for maximum freshness.
        </p>
      </div>

      {/* Whitelist */}
      <div className="panel">
        <div className="panel-title">🛡️ Domain Whitelist</div>
        <div className="kv-grid">
          <KVRow
            k="Tranco Status"
            v={whitelist?.tranco?.loaded ? 'Loaded ✅' : 'Loading… ⏳'}
            cls={whitelist?.tranco?.loaded ? 'text-green' : 'text-amber'}
            icon="📊"
          />
          <KVRow k="Tranco Domains" v={(whitelist?.tranco?.domain_count ?? 0).toLocaleString() + ' domains'} icon="🌐" />
          <KVRow k="Static Domains" v={(whitelist?.static_count ?? 0).toLocaleString() + ' domains'}         icon="📄" />
          <KVRow k="Source"         v={whitelist?.tranco?.source || '—'}                                     icon="📥" />
          <KVRow
            k="Total Trusted"
            v={((whitelist?.tranco?.domain_count ?? 0) + (whitelist?.static_count ?? 0)).toLocaleString()}
            icon="✅"
          />
          {whitelist?.tranco?.loaded_at && (
            <KVRow k="Loaded At" v={fmtTime(whitelist.tranco.loaded_at)} icon="🕒" />
          )}
        </div>
        <p className="panel-note">
          Tranco Top-5000 domains are trusted automatically — no ML inference needed.
        </p>
      </div>
    </div>
  );
}

function KVRow({ k, v, cls = '', icon = '', note = '' }) {
  return (
    <div className="kv-row">
      <span className="kv-icon">{icon}</span>
      <span className="kv-key">{k}</span>
      <span className={`kv-val mono ${cls}`}>
        {v}{note && <span className="muted"> · {note}</span>}
      </span>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// APP SHELL
// ══════════════════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════════════════


const TABS = [
  { id: 'overview',  icon: '📊', label: 'Overview'     },
  { id: 'history',   icon: '📜', label: 'Scan History' },
  { id: 'hashes',    icon: '📸', label: 'Hash DB'      },
  { id: 'reports',   icon: '📋', label: 'User Reports'      },

  { id: 'system',    icon: '⚙️', label: 'System Status'       },
];

// The 30s poll keeps the dashboard live while the browser extension scans
// URLs in the background — new scan history entries, updated cache counts,
// and new user reports all appear automatically without manual Refresh.
const REFRESH_INTERVAL_MS = 30_000;

export default function App() {
  const [tab,        setTab]        = useState('overview');
  const [loading,    setLoading]    = useState(false);
  const [stats,      setStats]      = useState(null);
  const [history,    setHistory]    = useState(null);
  const [hashes,     setHashes]     = useState(null);
  const [reports,    setReports]    = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [online,     setOnline]     = useState(false);
  const [theme,      setTheme]      = useState(
    () => localStorage.getItem('phishguard-theme') || 'dark'
  );

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('phishguard-theme', theme);
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme(t => (t === 'dark' ? 'light' : 'dark'));
  }, []);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [s, h, hs, r] = await Promise.all([
        get('/admin-stats'),
        get('/scan-history?limit=500'),
        get('/hash/list'),
        get('/reports'),
      ]);
      setStats(s);
      setHistory(h?.history ?? []);
      setHashes(hs);
      setReports(r);
      setOnline(!!s);
      setLastUpdate(new Date().toLocaleTimeString());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const t = setInterval(fetchAll, REFRESH_INTERVAL_MS);
    return () => clearInterval(t);
  }, [fetchAll]);

  return (
    <div className="shell">
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">🛡️</div>
          <div className="brand-text">
            <div className="brand-name">PhishGuard</div>
            <div className="brand-sub">Admin Console</div>
          </div>
        </div>

        <nav className="nav">
          {TABS.map(t => (
            <button
              key={t.id}
              className={`nav-item ${tab === t.id ? 'nav-item--on' : ''}`}
              onClick={() => setTab(t.id)}
            >
              <span className="nav-icon">{t.icon}</span>
              <span className="nav-label">{t.label}</span>
              {tab === t.id && <span className="nav-indicator" />}
            </button>
          ))}
        </nav>

        <div className="sidebar-foot">
          <ThemeToggle theme={theme} onToggle={toggleTheme} />
          <div className={`api-status ${online ? 'api-status--ok' : 'api-status--off'}`}>
            <span className="status-dot" />
            {online ? 'API Online' : 'API Offline'}
          </div>
          {lastUpdate && <div className="last-update">Updated {lastUpdate}</div>}
          <div className="auto-refresh-note">Auto-refresh every 30s</div>
        </div>
      </aside>

      {/* ── Main ── */}
      <main className="main-area">
        <div className="main-inner">
          {tab === 'overview' && <OverviewTab stats={stats}    loading={loading} onRefresh={fetchAll} />}
          {tab === 'history'  && <ScanHistoryTab history={history} loading={loading} onRefresh={fetchAll} />}
          {tab === 'hashes'   && <HashManagerTab hashes={hashes}   loading={loading} onRefresh={fetchAll} />}
          {tab === 'reports'  && <ReportsTab  reports={reports} loading={loading} onRefresh={fetchAll} />}
          {tab === 'system'   && <SystemTab   stats={stats}    loading={loading} onRefresh={fetchAll} />}
        </div>
      </main>
    </div>
  );
}