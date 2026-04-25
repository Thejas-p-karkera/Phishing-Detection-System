from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
import requests
from typing import Dict, Any, Optional
import warnings
import concurrent.futures
import os
import base64
import io
import time
import hashlib
import threading
import json
from dotenv import load_dotenv

# Load .env file from the same directory as app.py
# This reads GOOGLE_SAFE_BROWSING_KEY and any other secrets automatically
# so you don't have to set environment variables manually each session.
load_dotenv()

class _TTLCache:
    def __init__(self):
        self._data = {}
        self._lock = threading.Lock()
    def get(self, key):
        with self._lock:
            entry = self._data.get(key)
            if entry is None: return None
            value, expires = entry
            if time.monotonic() > expires:
                del self._data[key]; return None
            return value
    def set(self, key, value, ttl):
        with self._lock:
            self._data[key] = (value, time.monotonic() + ttl)
    def size(self):
        with self._lock: return len(self._data)

_RESULT_CACHE = _TTLCache()
_WHOIS_CACHE  = _TTLCache()
_VT_CACHE     = _TTLCache()

import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import datetime as dt

try:
    import whois
except ImportError:
    whois = None

# imagehash and Pillow — required for screenshot perceptual hashing.
# Install with:  pip install Pillow ImageHash --break-system-packages
try:
    import imagehash
    from PIL import Image
    _IMAGEHASH_AVAILABLE = True
except ImportError:
    imagehash = None          # type: ignore
    Image     = None          # type: ignore
    _IMAGEHASH_AVAILABLE = False
    print("WARNING: 'imagehash' or 'Pillow' not installed. "
          "Screenshot hashing disabled. "
          "Run:  pip install Pillow ImageHash --break-system-packages")

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

app = FastAPI(title="Advanced Phishing Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://*/*", "http://*/*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==== MODEL + TRAINING DATA ====

MODEL_PATH    = "1LModel.joblib"
PROGRESS_PATH = "1LExtracted.csv"

try:
    model = joblib.load(MODEL_PATH)
    known_urls_df = pd.read_csv(PROGRESS_PATH)
    known_urls_df["url_norm"] = (
        known_urls_df["url"].astype(str).str.strip().str.lower()
    )
    known_urls = set(known_urls_df["url_norm"].tolist())
    print(f"Loaded model. Known URLs: {len(known_urls)}")
except FileNotFoundError:
    model = None
    known_urls_df = None
    known_urls = set()
    print("Model/CSV not found – known-URL shortcut disabled")


class URLRequest(BaseModel):
    url: str

class ScreenshotRequest(BaseModel):
    url: str
    screenshot: str  # base64-encoded PNG from chrome.tabs.captureVisibleTab


# ======================================================================
# === TIER 1: DYNAMIC WHITELIST — TRANCO TOP SITES + STATIC FALLBACK
# ======================================================================
#
# Two-layer whitelist:
#
#   Layer A — Tranco Top N (downloaded at startup, refreshed on restart)
#             Tranco ranks domains by aggregated traffic from multiple
#             sources (Alexa, Cisco Umbrella, Majestic, Chrome UX).
#             Any domain in the top 5,000 most-visited sites on earth
#             is almost certainly legitimate — QuillBot, Humanizer,
#             most AI tools, news sites, regional services all appear here.
#             Free, no API key needed.  https://tranco-list.eu
#
#   Layer B — Static fallback list
#             Catches critical domains that may not rank in Tranco top window
#             (new AI tools, regional Google domains, CDN hostnames).
#
# Subdomain matching: 'chat.openai.com' trusted because ends with '.openai.com'

TRANCO_TOP_N     = 5000          # raise to 10000 to cover more sites
_TRANCO_DOMAINS: set[str] = set()
_tranco_meta: dict = {"loaded": False, "domain_count": 0, "loaded_at": None, "error": None}

_STATIC_DOMAINS: set[str] = {
    # Search engines
    'google.com','google.co.in','google.co.uk','google.com.au','google.de',
    'google.fr','google.co.jp','bing.com','yahoo.com','duckduckgo.com',
    'baidu.com','yandex.com','yandex.ru','ecosia.org','startpage.com',
    # AI assistants & writing tools
    'openai.com','chatgpt.com','claude.ai','anthropic.com',
    'gemini.google.com','bard.google.com','perplexity.ai','you.com',
    'copilot.microsoft.com','meta.ai','x.ai','grok.x.ai',
    'mistral.ai','huggingface.co','cohere.com','deepmind.com',
    'quillbot.com','grammarly.com','writesonic.com','jasper.ai',
    'copy.ai','rytr.me','wordtune.com','hemingwayapp.com',
    'humanizer.com','undetectable.ai','stealthwriter.ai',
    'character.ai','poe.com','phind.com','kagi.com',
    # Microsoft ecosystem
    'microsoft.com','live.com','office.com','outlook.com','hotmail.com',
    'msn.com','azure.com','azurewebsites.net','linkedin.com','skype.com',
    'sharepoint.com','onenote.com','bing.com','xbox.com','windows.com',
    # Google ecosystem
    'youtube.com','gmail.com','googleapis.com','googleusercontent.com',
    'gstatic.com','googlevideo.com',
    # Apple
    'apple.com','icloud.com','apps.apple.com',
    # Amazon / AWS
    'amazon.com','amazon.in','amazon.co.uk','amazon.de',
    'amazonaws.com','cloudfront.net','aws.amazon.com',
    # Social media
    'facebook.com','instagram.com','twitter.com','x.com','threads.net',
    'whatsapp.com','discord.com','telegram.org','reddit.com',
    'tiktok.com','snapchat.com','pinterest.com','tumblr.com',
    'twitch.tv','spotify.com','soundcloud.com',
    # Dev & productivity
    'github.com','gitlab.com','stackoverflow.com','npmjs.com','pypi.org',
    'docker.com','heroku.com','vercel.app','netlify.app','netlify.com',
    'firebase.google.com','firebaseapp.com','web.app','replit.com',
    'codepen.io','codesandbox.io','dev.to','medium.com','notion.so',
    'airtable.com','trello.com','asana.com','figma.com','canva.com',
    'dropbox.com',
    # Cloud & CDN
    'digitalocean.com','cloudflare.com','workers.dev','pages.dev',
    'render.com','railway.app','fly.io',
    # Finance
    'paypal.com','stripe.com','wise.com','revolut.com',
    # Knowledge
    'wikipedia.org','wikimedia.org','quora.com','britannica.com',
    'wolframalpha.com','archive.org',
    # Local
    'localhost','127.0.0.1',
}


def _parse_csv_domains(text: str, top_n: int) -> list[str]:
    """Parse rank,domain CSV text and return up to top_n domain strings."""
    domains = []
    for line in text.strip().splitlines():
        parts = line.strip().split(",", 1)
        if len(parts) == 2:
            domain = parts[1].strip().lower()
            if domain:
                domains.append(domain)
        if len(domains) >= top_n:
            break
    return domains


def _load_tranco_list(top_n: int = TRANCO_TOP_N) -> None:
    """
    Download the latest Tranco top-N list and populate _TRANCO_DOMAINS.

    Tranco changed their API — the old /download/latest/{n} endpoint
    returns 404. The correct flow is now:
      1. GET /api/lists/date/latest  → JSON with {"list_id": "XXXX"}
      2. GET /download/{list_id}/{n} → CSV  rank,domain

    Falls back to Majestic Million if Tranco is unavailable.
    Both are free, no API key required.
    """
    global _tranco_meta
    headers = {"User-Agent": "PhishGuard/1.5"}

    # ── Attempt 1: Tranco (correct two-step API) ──────────────────────
    try:
        print(f"[TRANCO] Fetching latest list ID...")
        meta_resp = requests.get(
            "https://tranco-list.eu/api/lists/date/latest",
            timeout=15, headers=headers
        )
        if meta_resp.status_code == 200:
            list_id = meta_resp.json().get("list_id") or meta_resp.json().get("id")
            if list_id:
                print(f"[TRANCO] Downloading list {list_id} (top {top_n})...")
                csv_resp = requests.get(
                    f"https://tranco-list.eu/download/{list_id}/{top_n}",
                    timeout=30, headers=headers
                )
                if csv_resp.status_code == 200:
                    domains = _parse_csv_domains(csv_resp.text, top_n)
                    _TRANCO_DOMAINS.update(domains)
                    _tranco_meta = {
                        "loaded":       True,
                        "domain_count": len(domains),
                        "source":       f"tranco_list_{list_id}",
                        "loaded_at":    dt.datetime.now(dt.timezone.utc).isoformat(),
                        "error":        None,
                    }
                    print(f"[TRANCO] Loaded {len(domains)} domains from Tranco list {list_id}.")
                    return
    except Exception as e:
        print(f"[TRANCO] Tranco attempt failed: {e}")

    # ── Attempt 2: Majestic Million (free, always available) ──────────
    # Majestic ranks domains by the number of referring subnets (link-based).
    # Top 1M CSV, columns: GlobalRank,TldRank,Domain,TLD,...
    try:
        print("[TRANCO] Falling back to Majestic Million...")
        resp = requests.get(
            "https://downloads.majestic.com/majestic_million.csv",
            timeout=30, headers=headers, stream=True
        )
        if resp.status_code == 200:
            loaded = 0
            lines = []
            for chunk in resp.iter_lines():
                if loaded >= top_n:
                    break
                if isinstance(chunk, bytes):
                    chunk = chunk.decode("utf-8", errors="ignore")
                parts = chunk.strip().split(",")
                # Header row: GlobalRank,TldRank,Domain,...
                if len(parts) >= 3 and not parts[0].strip().isdigit():
                    continue   # skip header
                if len(parts) >= 3:
                    domain = parts[2].strip().lower()
                    if domain:
                        _TRANCO_DOMAINS.add(domain)
                        loaded += 1

            _tranco_meta = {
                "loaded":       True,
                "domain_count": loaded,
                "source":       "majestic_million",
                "loaded_at":    dt.datetime.now(dt.timezone.utc).isoformat(),
                "error":        None,
            }
            print(f"[TRANCO] Loaded {loaded} domains from Majestic Million.")
            return
    except Exception as e:
        print(f"[TRANCO] Majestic Million failed: {e}")

    # ── Attempt 3: Umbrella Top 1M (Cisco) ───────────────────────────
    # Cisco Umbrella ranks by DNS query volume.
    try:
        import zipfile, io as _io
        print("[TRANCO] Falling back to Cisco Umbrella Top 1M...")
        resp = requests.get(
            "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
            timeout=30, headers=headers
        )
        if resp.status_code == 200:
            with zipfile.ZipFile(_io.BytesIO(resp.content)) as z:
                csv_text = z.read(z.namelist()[0]).decode("utf-8", errors="ignore")
            domains = _parse_csv_domains(csv_text, top_n)
            _TRANCO_DOMAINS.update(domains)
            _tranco_meta = {
                "loaded":       True,
                "domain_count": len(domains),
                "source":       "cisco_umbrella",
                "loaded_at":    dt.datetime.now(dt.timezone.utc).isoformat(),
                "error":        None,
            }
            print(f"[TRANCO] Loaded {len(domains)} domains from Cisco Umbrella.")
            return
    except Exception as e:
        print(f"[TRANCO] Umbrella failed: {e}")

    # ── All sources failed ────────────────────────────────────────────
    _tranco_meta["error"] = "All popularity list sources failed"
    print("[TRANCO] All sources failed. Using static whitelist only (136 domains).")


# Start Tranco download in background thread — server starts instantly
_tranco_loader_thread = concurrent.futures.ThreadPoolExecutor(max_workers=1)
_tranco_loader_thread.submit(_load_tranco_list, TRANCO_TOP_N)


# ======================================================================
# === PHISHING URL FEED — PhishTank + OpenPhish
# ======================================================================
#
# Two public feeds of known active phishing URLs are downloaded at startup:
#
#   PhishTank  — community-verified phishing URLs (~30,000 active entries)
#                Updated hourly. No API key needed for JSON feed.
#                https://www.phishtank.com/developer_info.php
#
#   OpenPhish  — ML-curated active phishing URLs (~1,500 entries, free tier)
#                Updated every few hours.
#                https://openphish.com/
#
# These URLs are stored in _PHISHING_URLS (a set of normalised URL strings).
# At predict time, if the submitted URL matches one of these exactly (after
# normalisation), it is immediately returned as Phishing — no ML inference,
# no VT call, no GSB call needed.
#
# Why this is valuable:
#   • Catches brand-new phishing URLs that GSB may not have indexed yet
#   • PhishTank URLs are human-verified — extremely low false positive rate
#   • Zero-latency detection for known URLs (set lookup = O(1))
#
# Limitations:
#   • Only exact URL matches (not domain-wide blacklisting)
#   • Feed is refreshed only on server restart; restart daily for freshness
#   • PhishTank free feed has no authentication (rate-limited)

_PHISHING_URLS: set[str] = set()
_phishing_feed_meta: dict = {
    "loaded":       False,
    "url_count":    0,
    "sources":      [],
    "loaded_at":    None,
    "error":        None,
}

def _normalise_url(url: str) -> str:
    """Normalise a URL for feed matching: lowercase scheme+host, strip trailing slash."""
    try:
        from urllib.parse import urlparse, urlunparse
        p = urlparse(url.strip())
        normalised = urlunparse((
            p.scheme.lower(),
            p.netloc.lower(),
            p.path.rstrip('/') or '/',
            p.params, p.query, ''
        ))
        return normalised
    except Exception:
        return url.strip().lower()


def _load_phishing_feeds() -> None:
    """
    Download PhishTank and OpenPhish feeds at server startup.
    Runs in a background thread — never blocks the server from starting.
    Populates _PHISHING_URLS with normalised phishing URLs.
    """
    global _phishing_feed_meta
    sources_loaded = []
    total = 0

    # ── Source 1: PhishTank JSON feed ────────────────────────────────────────
    # Returns a JSON array of verified phishing entries.
    # Each entry has: url, phish_detail_url, submission_time, verified, online, target
    try:
        print("[PHISH-FEED] Downloading PhishTank feed...")
        resp = requests.get(
            "http://data.phishtank.com/data/online-valid.json",
            timeout=30,
            headers={"User-Agent": "phishguard/1.5 phishtank/1.0"}
        )
        if resp.status_code == 200:
            entries = resp.json()
            count = 0
            for entry in entries:
                raw_url = entry.get("url", "")
                if raw_url:
                    _PHISHING_URLS.add(_normalise_url(raw_url))
                    count += 1
            sources_loaded.append(f"PhishTank ({count} URLs)")
            total += count
            print(f"[PHISH-FEED] PhishTank: loaded {count} verified phishing URLs.")
        else:
            print(f"[PHISH-FEED] PhishTank returned HTTP {resp.status_code}")
    except Exception as e:
        print(f"[PHISH-FEED] PhishTank failed: {e}")

    # ── Source 2: OpenPhish free feed (plain text, one URL per line) ─────────
    try:
        print("[PHISH-FEED] Downloading OpenPhish feed...")
        resp = requests.get(
            "https://openphish.com/feed.txt",
            timeout=20,
            headers={"User-Agent": "phishguard/1.5"}
        )
        if resp.status_code == 200:
            lines = [l.strip() for l in resp.text.splitlines() if l.strip().startswith("http")]
            count = 0
            for url in lines:
                _PHISHING_URLS.add(_normalise_url(url))
                count += 1
            sources_loaded.append(f"OpenPhish ({count} URLs)")
            total += count
            print(f"[PHISH-FEED] OpenPhish: loaded {count} active phishing URLs.")
        else:
            print(f"[PHISH-FEED] OpenPhish returned HTTP {resp.status_code}")
    except Exception as e:
        print(f"[PHISH-FEED] OpenPhish failed: {e}")

    import datetime as _dt
    if total > 0:
        _phishing_feed_meta = {
            "loaded":    True,
            "url_count": total,
            "sources":   sources_loaded,
            "loaded_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "error":     None,
        }
        print(f"[PHISH-FEED] Total: {total} known phishing URLs loaded from {len(sources_loaded)} source(s).")
    else:
        _phishing_feed_meta["error"] = "All phishing feeds failed to load"
        print("[PHISH-FEED] No phishing feeds could be loaded. URL feed matching disabled.")


# Launch phishing feed download in background (parallel with Tranco)
_feed_loader_thread = concurrent.futures.ThreadPoolExecutor(max_workers=1)
_feed_loader_thread.submit(_load_phishing_feeds)


def _is_trusted_domain(url: str) -> tuple[bool, str]:
    """
    Returns (is_trusted, source_label).
    Checks Tranco popularity list first, then static fallback.
    Both check subdomains automatically.
    """
    try:
        hostname = (urlparse(url).hostname or '').lower()
        bare = hostname.removeprefix('www.')

        # Layer A: Tranco popularity list
        if bare in _TRANCO_DOMAINS:
            return True, "tranco_top"
        parts = bare.split('.')
        for i in range(1, len(parts) - 1):
            if '.'.join(parts[i:]) in _TRANCO_DOMAINS:
                return True, "tranco_top_subdomain"

        # Layer B: static fallback
        if bare in _STATIC_DOMAINS:
            return True, "static_whitelist"
        for trusted in _STATIC_DOMAINS:
            if bare.endswith('.' + trusted):
                return True, "static_whitelist_subdomain"

    except Exception:
        pass
    return False, "not_trusted"


# ======================================================================
# === TIER 2: GOOGLE SAFE BROWSING API
# ======================================================================
# Acts as a real-time blacklist — independent of the ML model.
# Even if a hacker crafts a URL that fools the model, GSB may still
# catch it because GSB maintains its own constantly-updated threat intel.
#
# Setup:
#   1. Go to https://console.cloud.google.com
#   2. Enable "Safe Browsing API"
#   3. Create an API key
#   4. Set env var:  GOOGLE_SAFE_BROWSING_KEY=your_key_here
#      (or paste it directly into the string below for local testing)

GSB_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

def check_google_safe_browsing(url: str) -> dict:
    """
    Query Google Safe Browsing API v4.
    Returns:
        { "is_unsafe": bool, "threat_type": str | None, "source": "gsb" }
    Falls back to { "is_unsafe": False } if the key is missing or the call fails.
    """
    if not GSB_API_KEY:
        return {"is_unsafe": False, "threat_type": None, "source": "gsb_skipped"}

    payload = {
        "client":    {"clientId": "phishguard", "clientVersion": "1.5"},
        "threatInfo": {
            "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                 "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        }
    }
    try:
        resp = requests.post(
            f"{GSB_API_URL}?key={GSB_API_KEY}",
            json=payload, timeout=4
        )
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                threat = matches[0].get("threatType", "UNKNOWN")
                return {"is_unsafe": True, "threat_type": threat, "source": "gsb"}
            return {"is_unsafe": False, "threat_type": None, "source": "gsb"}
    except Exception as e:
        print(f"GSB error for {url!r}: {e}")
    return {"is_unsafe": False, "threat_type": None, "source": "gsb_error"}



# ======================================================================
# === TIER 2b: VIRUSTOTAL URL REPUTATION
# ======================================================================
# VirusTotal scans a URL against 70+ security vendors simultaneously
# and returns a vote count: how many flagged it as malicious/suspicious.
#
# Why this is more powerful than GSB alone:
#   - GSB = Google's opinion only
#   - VirusTotal = 70+ independent security companies voting
#   - A site that slips past GSB might be caught by Kaspersky, BitDefender,
#     Fortinet, ESET, etc. who are also in the VirusTotal pool
#
# Free tier: 500 URL lookups/day, 4 requests/minute
# Get your API key at: https://www.virustotal.com/gui/join-us
#
# Trust score interpretation:
#   malicious_votes / total_vendors × 100 = malicious percentage
#   0%        → clean (all vendors agree safe)
#   1–10%     → suspicious (minor flags, treat as warning)
#   10%+      → likely malicious (override ML model to Phishing)
#   25%+      → confirmed threat (high confidence Phishing)

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_API_URL  = "https://www.virustotal.com/api/v3/urls"

# Thresholds — tune these to balance false positives vs false negatives
VT_SUSPICIOUS_THRESHOLD  = 3    # ≥3 vendors flag → add warning reason
VT_MALICIOUS_THRESHOLD   = 8    # ≥8 vendors flag → override to Phishing

def _vt_parse_stats(stats: dict) -> dict:
    """Parse VirusTotal stats dict into our standard result format."""
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total      = malicious + suspicious + harmless + undetected
    # Trust score: malicious vendors count full weight, suspicious count 0.7 weight.
    # Previously suspicious counted only 0.5 — too lenient.
    # A site with 10/100 suspicious vendors now gets trust ~93 (was ~95).
    # A site with 10/100 malicious vendors gets trust ~90.
    score      = (malicious + suspicious * 0.7) / total if total > 0 else 0.0
    trust      = max(0, int(100 - score * 100))
    verdict    = ("malicious"  if malicious  >= VT_MALICIOUS_THRESHOLD  else
                  "suspicious" if (malicious >= VT_SUSPICIOUS_THRESHOLD or
                                   suspicious >= VT_SUSPICIOUS_THRESHOLD) else "clean")
    return {
        "checked":     True,
        "malicious":   malicious,  "suspicious": suspicious,
        "harmless":    harmless,   "total":      total,
        "score":       score,      "trust_score": trust,
        "verdict":     verdict,    "source":     "virustotal",
    }


def check_virustotal(url: str) -> dict:
    """
    Query VirusTotal with a three-stage speed strategy:

    Stage 1 — In-memory cache (~0ms)
        If we scanned this URL in the last hour, return immediately.

    Stage 2 — Existing VT analysis (~0.5s)
        VT stores every URL it has ever scanned.  Most URLs (especially
        popular or previously-reported ones) already have a result.
        GET /urls/{id} returns it instantly — no submission, no polling.
        URL id = base64url(url) without padding.

    Stage 3 — Submit + fast poll (~2-4s)
        Only for truly new URLs.  Poll every 0.8s (was 2s) with max
        3 attempts (was 4), capping VT wait at ~2.4s instead of ~8s.
    """
    _VT_SKIP = {"checked": False, "source": "vt_skipped",
                "malicious": 0, "suspicious": 0, "harmless": 0,
                "total": 0, "score": 0.0, "trust_score": -1, "verdict": "unknown"}
    _VT_ERR  = {**_VT_SKIP, "source": "vt_error"}

    if not VT_API_KEY:
        return _VT_SKIP

    headers = {"x-apikey": VT_API_KEY}

    # ── Stage 1: in-memory cache ──────────────────────────────────────────────
    cache_key = hashlib.sha256(url.encode()).hexdigest()
    cached = _VT_CACHE.get(cache_key)
    if cached is not None:
        print(f"[VT] Cache hit for {url!r}")
        return cached

    try:
        # ── Stage 2: check if VT already has this URL ─────────────────────────
        # VT URL id = base64url(url) stripped of "=" padding
        import base64 as _b64
        url_id = _b64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        existing = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=4
        )
        if existing.status_code == 200:
            attrs = existing.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats")
            if stats:
                result = _vt_parse_stats(stats)
                _VT_CACHE.set(cache_key, result, ttl=86400)  # 24h
                print(f"[VT] Existing result for {url!r}: trust={result['trust_score']}/100")
                return result

        # ── Stage 3: submit + fast poll (new/unknown URL) ─────────────────────
        submit = requests.post(VT_API_URL, headers=headers,
                               data={"url": url}, timeout=6)
        if submit.status_code not in (200, 201):
            raise RuntimeError(f"VT submit HTTP {submit.status_code}")

        analysis_id = submit.json()["data"]["id"]

        for attempt in range(3):          # was range(4)
            time.sleep(0.8)               # was 2s — total max wait 2.4s vs 8s
            poll = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers, timeout=4
            )
            if poll.status_code != 200:
                continue
            poll_data = poll.json()
            if poll_data.get("data", {}).get("attributes", {}).get("status") == "completed":
                result = _vt_parse_stats(poll_data["data"]["attributes"]["stats"])
                _VT_CACHE.set(cache_key, result, ttl=86400)  # 24h
                print(f"[VT] Fresh scan {url!r}: trust={result['trust_score']}/100 (attempt {attempt+1})")
                return result

        raise RuntimeError("Analysis did not complete in 2.4s")

    except Exception as e:
        print(f"[VT] Error for {url!r}: {e}")
        return _VT_ERR


# ======================================================================
# === TIER 3: SCREENSHOT PERCEPTUAL HASH (VISUAL CLONE DETECTION)
# ======================================================================
# Catches phishing sites that copy a legitimate site's design exactly.
# The model checks URL/content features but can't detect pixel-level copying.
#
# How it works:
#   1. content.js captures a screenshot with chrome.tabs.captureVisibleTab
#   2. The base64 PNG is sent to /screenshot endpoint
#   3. Server computes a perceptual hash (pHash) — a 64-bit fingerprint
#      of the image that is robust to minor resizing/compression
#   4. Hash is compared against a database of known phishing page hashes
#      AND against reference screenshots of brand pages (Google, PayPal etc.)
#
# pHash distance: 0 = identical, <10 = visually similar, >20 = different
PHASH_SIMILARITY_THRESHOLD = 10   # hashes within this distance are "the same"

# ── Persistent phishing hash database ────────────────────────────────────────
# Hashes are stored in phishing_hashes.json next to app.py.
# On startup all hashes are loaded into memory.
# /hash/add writes to both memory AND the JSON file so hashes survive restarts.

_HASH_DB_PATH = os.path.join(os.path.dirname(__file__), "phishing_hashes.json")
_HASH_DB_LOCK = threading.Lock()

def _load_hash_db() -> tuple:
    """Load known phishing hashes AND url→hash map from JSON file."""
    if not os.path.exists(_HASH_DB_PATH):
        print("[HASH-DB] phishing_hashes.json not found — starting with empty database.")
        return set(), {}
    try:
        with open(_HASH_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        hashes     = set(data.get("hashes", []))
        url_map    = data.get("url_hash_map", {})
        print(f"[HASH-DB] Loaded {len(hashes)} hashes, {len(url_map)} URL mappings from disk.")
        return hashes, url_map
    except Exception as e:
        print(f"[HASH-DB] Failed to load hash database: {e} — starting empty.")
        return set(), {}

def _save_hash_db(hashes: set, url_map: dict) -> None:
    """Persist hashes AND url→hash map to JSON (thread-safe)."""
    try:
        with _HASH_DB_LOCK:
            with open(_HASH_DB_PATH, "w", encoding="utf-8") as f:
                json.dump({
                    "hashes":       sorted(hashes),
                    "url_hash_map": url_map,
                }, f, indent=2)
    except Exception as e:
        print(f"[HASH-DB] Failed to save hash database: {e}")

# Load into memory at module import time
KNOWN_PHISHING_HASHES, _URL_TO_HASH = _load_hash_db()

def compute_screenshot_hash(b64_png: str) -> Optional[str]:
    """Decode base64 PNG and return its perceptual hash string, or None on failure."""
    if not _IMAGEHASH_AVAILABLE:
        print("Screenshot hash skipped: imagehash/Pillow not installed.")
        return None
    try:
        img_bytes = base64.b64decode(b64_png.split(",")[-1])  # strip data URI prefix
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        return str(imagehash.phash(img))
    except Exception as e:
        print(f"Screenshot hash error: {e}")
        return None

def is_visual_clone(b64_png: str) -> dict:
    """
    Check whether the screenshot matches any known phishing page hash.
    Returns { "is_clone": bool, "matched_hash": str | None }
    """
    current_hash_str = compute_screenshot_hash(b64_png)
    if not current_hash_str:
        return {"is_clone": False, "matched_hash": None, "current_hash": None}

    try:
        current_hash = imagehash.hex_to_hash(current_hash_str)
        for known_str in KNOWN_PHISHING_HASHES:
            try:
                known_hash = imagehash.hex_to_hash(known_str)
                if (current_hash - known_hash) <= PHASH_SIMILARITY_THRESHOLD:
                    return {
                        "is_clone":     True,
                        "matched_hash": known_str,
                        "current_hash": current_hash_str,
                    }
            except Exception:
                continue
    except Exception as e:
        print(f"Visual clone check error: {e}")

    return {"is_clone": False, "matched_hash": None, "current_hash": current_hash_str}


# ======================================================================
# === EXPLAINABILITY — TOP REASONS ENGINE
# ======================================================================
#
# Strategy: for each feature we define
#   • a human-readable label
#   • a "suspicious?" predicate  — is this value pointing toward phishing?
#   • a severity bucket          — HIGH / MEDIUM / LOW (used for icon)
#
# After prediction we score every feature as:
#   score = feature_importance × suspicion_weight
# and return the top N that actually fired (predicate is True).
# This gives per-sample explanations without needing SHAP.

_SEVERITY_HIGH   = "high"
_SEVERITY_MEDIUM = "medium"
_SEVERITY_LOW    = "low"

# (label, suspicious_predicate, severity)
FEATURE_META: dict[str, tuple[str, object, str]] = {
    # ── URL structure ──────────────────────────────────────────────────
    "url_length":          ("URL is unusually long",
                            lambda v: v > 75, _SEVERITY_MEDIUM),
    "url_is_long":         ("URL length exceeds safe threshold",
                            lambda v: v == 1, _SEVERITY_MEDIUM),
    "hostname_length":     ("Hostname is suspiciously long",
                            lambda v: v > 30, _SEVERITY_MEDIUM),
    "hostname_is_long":    ("Hostname length exceeds safe threshold",
                            lambda v: v == 1, _SEVERITY_MEDIUM),
    "num_subdomains":      ("Excessive number of subdomains",
                            lambda v: v > 3, _SEVERITY_HIGH),
    "has_ip":              ("URL uses a raw IP address instead of a domain name",
                            lambda v: v == 1, _SEVERITY_HIGH),
    "valid_ip":            ("URL host is a valid raw IP address",
                            lambda v: v == 1, _SEVERITY_HIGH),
    "tinyurl_like":        ("URL is disguised through a link shortener",
                            lambda v: v == 1, _SEVERITY_HIGH),
    "punycode":            ("Domain uses Punycode — possible homograph attack",
                            lambda v: v == 1, _SEVERITY_HIGH),
    "double_slash_path":   ("Path contains a double-slash redirect trick",
                            lambda v: v == 1, _SEVERITY_MEDIUM),
    "port_present":        ("URL uses an unusual non-standard port",
                            lambda v: v == 1, _SEVERITY_MEDIUM),
    "protocol_relative":   ("URL is protocol-relative — hides the actual scheme",
                            lambda v: v == 1, _SEVERITY_MEDIUM),
    "https_token":         ("'https' appears inside the path, not the scheme — deceptive",
                            lambda v: v == 1, _SEVERITY_HIGH),
    "is_https":            ("Connection is not encrypted (HTTP, not HTTPS)",
                            lambda v: v == 0, _SEVERITY_HIGH),

    # ── Suspicious characters / encoding ──────────────────────────────
    "num_at":              ("URL contains an @ symbol — can hide the real destination",
                            lambda v: v > 0, _SEVERITY_HIGH),
    "num_percent":         ("URL is heavily percent-encoded — obfuscation tactic",
                            lambda v: v > 5, _SEVERITY_MEDIUM),
    "num_hex_encoded":     ("URL contains hex-encoded characters",
                            lambda v: v > 3, _SEVERITY_MEDIUM),
    "homoglyphs_count":    ("URL contains non-ASCII lookalike characters",
                            lambda v: v > 0, _SEVERITY_HIGH),
    "suspicious_char_run": ("URL has a suspicious run of repeated characters",
                            lambda v: v == 1, _SEVERITY_LOW),
    "has_at_in_path":      ("@ symbol appears inside the URL path",
                            lambda v: v == 1, _SEVERITY_HIGH),
    "has_ip_in_path":      ("IP address embedded inside the URL path",
                            lambda v: v == 1, _SEVERITY_HIGH),
    "num_dashes":          ("Excessive dashes in URL — common in typosquatting",
                            lambda v: v > 4, _SEVERITY_LOW),

    # ── Keyword signals ────────────────────────────────────────────────
    "sensitive_words":     ("URL contains sensitive keywords (login, bank, verify…)",
                            lambda v: v > 0, _SEVERITY_HIGH),
    "suspicious_tld":      ("Domain uses a high-risk top-level domain (.xyz, .tk…)",
                            lambda v: v == 1, _SEVERITY_HIGH),
    "repeated_subdomain":  ("Same subdomain appears multiple times — spoofing tactic",
                            lambda v: v == 1, _SEVERITY_HIGH),

    # ── WHOIS / domain age ─────────────────────────────────────────────
    "domain_age_days":     ("Domain was registered very recently — common phishing pattern",
                            lambda v: 0 <= v < 180, _SEVERITY_HIGH),
    "days_to_expiry":      ("Domain expires very soon — typical of throwaway phishing domains",
                            lambda v: 0 <= v < 30, _SEVERITY_MEDIUM),
    "whois_privacy":       ("Domain owner identity is hidden behind a privacy service",
                            lambda v: v == 1, _SEVERITY_MEDIUM),

    # ── Page content ───────────────────────────────────────────────────
    "num_iframes":         ("Page contains hidden iframes",
                            lambda v: v > 2, _SEVERITY_HIGH),
    "iframe_src_external": ("Iframes load content from a different domain",
                            lambda v: v > 0, _SEVERITY_HIGH),
    "external_scripts":    ("Scripts are loaded from external, untrusted domains",
                            lambda v: v > 3, _SEVERITY_MEDIUM),
    "external_favicon":    ("Site favicon is hosted on a different domain — spoofing sign",
                            lambda v: v == 1, _SEVERITY_HIGH),
    "has_favicon":         ("Page has no favicon — legitimate sites almost always do",
                            lambda v: v == 0, _SEVERITY_LOW),
    "external_ratio":      ("Most links on this page point to external domains",
                            lambda v: v > 0.6, _SEVERITY_MEDIUM),
    "external_links":      ("Unusually high number of external links",
                            lambda v: v > 20, _SEVERITY_MEDIUM),
    "input_passwords":     ("Page contains hidden password or credential input fields",
                            lambda v: v > 0, _SEVERITY_HIGH),
    "forms_https":         ("Form action does not use HTTPS — credentials sent unencrypted",
                            lambda v: v == 0, _SEVERITY_HIGH),
    "js_links":            ("Links use javascript: — obfuscated navigation",
                            lambda v: v > 0, _SEVERITY_MEDIUM),
    "meta_refresh":        ("Page auto-redirects via meta refresh tag",
                            lambda v: v > 0, _SEVERITY_MEDIUM),
    "hidden_elements":     ("Page hides elements using display:none — concealment tactic",
                            lambda v: v > 3, _SEVERITY_MEDIUM),
    "suspicious_keywords": ("Page text contains suspicious words (verify, confirm, bank…)",
                            lambda v: v > 2, _SEVERITY_HIGH),
    "title_is_generic":    ("Page title is generic (Welcome, Login, Home…)",
                            lambda v: v == 1, _SEVERITY_LOW),
    "title_domain_match":  ("Page title does not match the domain name",
                            lambda v: v == 0, _SEVERITY_MEDIUM),
    "num_forms":           ("Unusually many forms on a single page",
                            lambda v: v > 3, _SEVERITY_MEDIUM),
    "script_iframe_ratio": ("Disproportionate number of scripts relative to iframes",
                            lambda v: v > 10, _SEVERITY_LOW),
    "html_length":         ("Page HTML is suspiciously short — likely a skeleton phishing page",
                            lambda v: 0 < v < 500, _SEVERITY_MEDIUM),
}

def get_top_reasons(features: dict, prediction: str, top_n: int = 5) -> list[dict]:
    """
    Return the top_n human-readable reasons that explain the prediction.

    For each feature that has a meta entry AND whose value passes the
    'suspicious?' predicate, we score it as:

        score = feature_importance × severity_weight

    Severity weights: HIGH=3, MEDIUM=2, LOW=1
    The top_n highest-scoring fired features are returned.

    For Legitimate predictions we return an empty list — no alarm to explain.
    """
    if prediction != "Phishing":
        return []

    severity_weight = {_SEVERITY_HIGH: 3, _SEVERITY_MEDIUM: 2, _SEVERITY_LOW: 1}
    scored: list[tuple[float, str, str, str]] = []  # (score, label, severity, feat)

    for feat, value in features.items():
        if feat not in FEATURE_META:
            continue
        label, predicate, severity = FEATURE_META[feat]
        try:
            fired = predicate(value)
        except Exception:
            continue
        if not fired:
            continue

        importance = _FEATURE_IMPORTANCE.get(feat, 0.0)
        score = importance * severity_weight[severity]
        scored.append((score, label, severity, feat))

    # Sort descending by score; stable tie-break by feature name
    scored.sort(key=lambda x: (-x[0], x[3]))

    return [
        {"label": label, "severity": severity, "feature": feat, "value": features.get(feat)}
        for _, label, severity, feat in scored[:top_n]
    ]


# ==== URL SCHEME GUARD ====
# FIX: Never attempt to scan browser-internal or non-HTTP URLs.
# These reach the server only from the popup manual scan, but guard anyway.
UNSCANNABLE_PREFIXES = (
    "chrome://", "chrome-extension://",
    "edge://",   "edge-extension://",
    "about:",    "data:",    "javascript:",
    "file://",   "blob://",
    "moz-extension://",
)

def is_scannable_url(url: str) -> bool:
    if not url or not url.strip():
        return False
    if any(url.startswith(p) for p in UNSCANNABLE_PREFIXES):
        return False
    if not url.startswith("http://") and not url.startswith("https://"):
        return False
    return True


# ==== SAFE REQUEST HELPER ====

def safe_get_text(url: str, timeout: int = 5, max_retries: int = 2) -> str:
    for _ in range(max_retries):
        try:
            resp = requests.get(
                url, timeout=timeout, verify=False,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                return resp.text
        except Exception:
            continue
    return ""


# ======================================================================
# === URL FEATURES
# ======================================================================

def _safe_hostname(url):
    try: return urlparse(url).hostname or ''
    except: return ''

def _safe_netloc(url):
    try: return urlparse(url).netloc or ''
    except: return ''

def _safe_path(url):
    try: return urlparse(url).path or ''
    except: return ''

def _safe_query(url):
    try: return urlparse(url).query or ''
    except: return ''

def _safe_fragment(url):
    try: return urlparse(url).fragment or ''
    except: return ''

def _count_char(s, ch): return s.count(ch)

def _ratio(fn, s):
    n = len(s)
    return fn(s) / n if n > 0 else 0.0

def _tokens(url):
    return [t for t in re.split(r'[/\\-_.?&=]', url) if t]

def _entropy(s):
    if not s: return 0.0
    from collections import Counter
    c = Counter(s)
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in c.values() if v > 0)

def _domain_from_url(url):
    return _safe_hostname(url) or ''

def _whois_record(domain):
    """WHOIS lookup with 24-hour domain cache to avoid repeat network calls."""
    if not whois or not domain:
        return None
    cached = _WHOIS_CACHE.get(domain)
    if cached is not None:
        return cached   # instant — no network call
    try:
        rec = whois.whois(domain)
        _WHOIS_CACHE.set(domain, rec, ttl=86400)  # cache 24 hours
        return rec
    except Exception:
        _WHOIS_CACHE.set(domain, None, ttl=86400)  # cache failure 24h too
        return None

def _normalize_whois_date(d):
    if isinstance(d, list) and d: d = d[0]
    if isinstance(d, dt.datetime): return d.date()
    if isinstance(d, dt.date):     return d
    if isinstance(d, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y", "%Y.%m.%d"):
            try: return dt.datetime.strptime(d, fmt).date()
            except: continue
    return None

def _fetch_whois_features(url: str) -> tuple[int, int, int]:
    """
    Make exactly ONE WHOIS network call and return all three derived values:
        (domain_age_days, days_to_expiry, whois_privacy)

    Previously each was a separate helper that called _whois_record()
    independently — meaning 3 network round-trips for the same domain.
    Now it's a single call, reducing WHOIS latency by ~2/3.
    Returns (-1, -1, -1) when the lookup fails or whois is not installed.
    """
    domain = _domain_from_url(url)
    rec    = _whois_record(domain)   # ← single network call

    if not rec:
        return -1, -1, -1

    today = dt.datetime.now(dt.timezone.utc).date()

    # domain_age_days
    try:
        cd  = _normalize_whois_date(rec.creation_date)
        age = max((today - cd).days, 0) if cd else -1
    except Exception:
        age = -1

    # days_to_expiry
    try:
        ed     = _normalize_whois_date(rec.expiration_date)
        expiry = max((ed - today).days, 0) if ed else -1
    except Exception:
        expiry = -1

    # whois_privacy
    try:
        text    = str(rec).lower()
        privacy = 1 if any(w in text for w in
                           ['privacy', 'whoisguard', 'contactprivacy', 'protecteddomain']) else 0
    except Exception:
        privacy = -1

    return age, expiry, privacy


URL_FEATURE_KEYS = [
    "url_length","hostname_length","path_length","query_length","fragment_length",
    "num_dots","num_dots_host","num_slashes","num_dashes","num_underscores","num_equals",
    "num_ampersands","num_percent","num_tilde","num_question","num_hash","num_at","num_colon",
    "num_semicolon","num_comma","num_plus","num_backslash","num_parens_open","num_parens_close",
    "num_brackets_open","num_brackets_close","num_triple_dots","num_double_dots",
    "digit_ratio","upper_ratio","lower_ratio","special_ratio","vowel_ratio","consonant_ratio",
    "url_entropy","num_tokens","avg_token_len","longest_token_len","num_unique_chars",
    "max_repeated_run","num_hex_encoded","hex_ratio",
    "num_subdomains","longest_subdomain","tld_length","domain_length","path_depth",
    "query_params","has_ip","valid_ip","port_present","is_https","double_slash_path",
    "tinyurl_like","https_token","sensitive_words","punycode","protocol_relative",
    "has_www","path_has_extension","filename_length","fragment_params",
    "num_letters","num_digits","num_specials","letters_ratio","hostname_num_digits",
    "path_num_digits","query_num_digits","hostname_num_dashes","path_num_dashes",
    "url_is_long","hostname_is_long","path_is_long","suspicious_char_run","has_at_in_path",
    "has_ip_in_path",
    "domain_age_days","days_to_expiry","whois_privacy",
    "edit_distance_proxy","homoglyphs_count","suspicious_tld","repeated_subdomain"
]


def extract_url_features(url: str) -> dict:
    feats = {k: 0 for k in URL_FEATURE_KEYS}
    u = url or ""
    host     = _safe_hostname(u)
    path     = _safe_path(u)
    query    = _safe_query(u)
    fragment = _safe_fragment(u)
    netloc   = _safe_netloc(u)

    def _safe_set(key, fn):
        try: feats[key] = fn()
        except: pass

    _safe_set("url_length",      lambda: len(u))
    _safe_set("hostname_length", lambda: len(host))
    _safe_set("path_length",     lambda: len(path))
    _safe_set("query_length",    lambda: len(query))
    _safe_set("fragment_length", lambda: len(fragment))

    for ch, key in [
        ('.','num_dots'),('.','num_dots_host'),('/','num_slashes'),('-','num_dashes'),
        ('_','num_underscores'),('=','num_equals'),('&','num_ampersands'),('%','num_percent'),
        ('~','num_tilde'),('?','num_question'),('#','num_hash'),('@','num_at'),(':','num_colon'),
        (';','num_semicolon'),(',','num_comma'),('+','num_plus'),('\\','num_backslash'),
        ('(','num_parens_open'),(')','num_parens_close'),('[','num_brackets_open'),(']','num_brackets_close'),
    ]:
        if key == 'num_dots_host':
            _safe_set(key, lambda h=host: _count_char(h, '.'))
        else:
            _safe_set(key, lambda c=ch, k=key: _count_char(u, c))

    _safe_set("num_triple_dots", lambda: u.count('...'))
    _safe_set("num_double_dots", lambda: u.count('..'))

    _safe_set("digit_ratio",     lambda: _ratio(lambda s: sum(c.isdigit() for c in s), u))
    _safe_set("upper_ratio",     lambda: _ratio(lambda s: sum(c.isupper() for c in s), u))
    _safe_set("lower_ratio",     lambda: _ratio(lambda s: sum(c.islower() for c in s), u))
    _safe_set("special_ratio",   lambda: _ratio(lambda s: sum(not c.isalnum() for c in s), u))
    _safe_set("vowel_ratio",     lambda: _ratio(lambda s: sum(c.lower() in 'aeiou' for c in s), u))
    _safe_set("consonant_ratio", lambda: _ratio(
        lambda s: sum(c.isalpha() and c.lower() not in 'aeiou' for c in s), u))

    try:    toks = _tokens(u)
    except: toks = []

    _safe_set("url_entropy",       lambda: _entropy(u))
    _safe_set("num_tokens",        lambda: len(toks))
    _safe_set("avg_token_len",     lambda: (sum(len(t) for t in toks)/len(toks)) if toks else 0)
    _safe_set("longest_token_len", lambda: max((len(t) for t in toks), default=0))
    _safe_set("num_unique_chars",  lambda: len(set(u)))

    def _max_repeated_run():
        if not u: return 0
        run = max_run = 1
        for i in range(1, len(u)):
            run = run+1 if u[i]==u[i-1] else 1
            if run > max_run: max_run = run
        return max_run

    _safe_set("max_repeated_run", _max_repeated_run)
    _safe_set("num_hex_encoded",  lambda: len(re.findall(r'%[0-9A-Fa-f]{2}', u)))
    _safe_set("hex_ratio",        lambda: _ratio(lambda s: sum(c in '0123456789abcdefABCDEF' for c in s), u))

    host_parts = host.split('.') if host else []
    subs       = host_parts[:-2] if len(host_parts) >= 2 else []

    _safe_set("num_subdomains",    lambda: max(len(host_parts)-2, 0))
    _safe_set("longest_subdomain", lambda: max((len(s) for s in subs), default=0))
    _safe_set("tld_length",        lambda: len(host_parts[-1]) if len(host_parts)>1 else 0)

    def _domain_str():
        return '.'.join(host_parts[-2:]) if len(host_parts)>=2 else host

    _safe_set("domain_length", lambda: len(_domain_str()))
    _safe_set("path_depth",    lambda: len([p for p in path.split('/') if p]) if path else 0)
    _safe_set("query_params",  lambda: len(parse_qs(query)) if query else 0)

    def _ip_flags():
        has_ip = valid_ip = 0
        try:
            dom = netloc.split(':')[0]
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', dom): has_ip = 1
            try: ipaddress.ip_address(dom); valid_ip = 1
            except: pass
        except: pass
        return has_ip, valid_ip

    _safe_set("has_ip",   lambda: _ip_flags()[0])
    _safe_set("valid_ip", lambda: _ip_flags()[1])
    _safe_set("port_present", lambda: 1 if urlparse(u).port and urlparse(u).port not in (80,443) else 0)
    _safe_set("is_https",     lambda: 1 if urlparse(u).scheme == 'https' else 0)
    _safe_set("double_slash_path", lambda: 1 if '//' in (path or '') else 0)

    shorteners = ['bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','is.gd']
    _safe_set("tinyurl_like", lambda: 1 if any(s in u.lower() for s in shorteners) else 0)

    def _rest_after_scheme():
        p = urlparse(u)
        return u[len(p.scheme)+3:] if p.scheme and u.startswith(p.scheme+'://') else u

    _safe_set("https_token", lambda: 1 if 'https' in _rest_after_scheme().lower() else 0)

    sensitive_words_list = ['login','bank','password','account','verify','update','secure']
    _safe_set("sensitive_words",    lambda: sum(w in u.lower() for w in sensitive_words_list))
    _safe_set("punycode",           lambda: 1 if 'xn--' in u.lower() else 0)
    _safe_set("protocol_relative",  lambda: 1 if u.startswith('//') else 0)
    _safe_set("has_www",            lambda: 1 if host.lower().startswith('www.') else 0)
    _safe_set("path_has_extension", lambda: 1 if '.' in (path.split('/')[-1] if path else '') else 0)
    _safe_set("filename_length",    lambda: len(path.split('/')[-1]) if path else 0)
    _safe_set("fragment_params",    lambda: len(fragment.split('&')) if fragment else 0)

    _safe_set("num_letters",  lambda: sum(c.isalpha() for c in u))
    _safe_set("num_digits",   lambda: sum(c.isdigit() for c in u))
    _safe_set("num_specials", lambda: sum(not c.isalnum() for c in u))
    _safe_set("letters_ratio",lambda: _ratio(lambda s: sum(c.isalpha() for c in s), u))

    _safe_set("hostname_num_digits", lambda: sum(c.isdigit() for c in host))
    _safe_set("path_num_digits",     lambda: sum(c.isdigit() for c in path))
    _safe_set("query_num_digits",    lambda: sum(c.isdigit() for c in query))
    _safe_set("hostname_num_dashes", lambda: _count_char(host, '-'))
    _safe_set("path_num_dashes",     lambda: _count_char(path, '-'))

    _safe_set("url_is_long",      lambda: 1 if feats["url_length"] > 75 else 0)
    _safe_set("hostname_is_long", lambda: 1 if feats["hostname_length"] > 30 else 0)
    _safe_set("path_is_long",     lambda: 1 if feats["path_length"] > 50 else 0)
    _safe_set("suspicious_char_run", lambda: 1 if feats["max_repeated_run"] >= 3 else 0)
    _safe_set("has_at_in_path",   lambda: 1 if '@' in (path or '') else 0)
    _safe_set("has_ip_in_path",   lambda: 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', path or '') else 0)

    # NOTE: WHOIS features (domain_age_days, days_to_expiry, whois_privacy) are
    # NOT set here. They are fetched by _fetch_whois_features() running in its
    # own parallel thread in the /predict endpoint and merged in afterwards.
    # Defaults (-1 sentinel) are already set at the top of this function.

    def _domain_core():
        ds = _domain_str()
        return ds.split('.')[0] if ds else ''

    def _last_path_seg_core():
        if not path: return ''
        seg = path.split('/')[-1]
        return seg.split('.')[0] if '.' in seg else seg

    def _lev(a, b):
        if not a or not b: return max(len(a), len(b))
        dp = [[0]*(len(b)+1) for _ in range(len(a)+1)]
        for i in range(len(a)+1): dp[i][0] = i
        for j in range(len(b)+1): dp[0][j] = j
        for i in range(1, len(a)+1):
            for j in range(1, len(b)+1):
                cost = 0 if a[i-1]==b[j-1] else 1
                dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)
        return dp[-1][-1]

    _safe_set("edit_distance_proxy",
        lambda: (
            _lev(_domain_core().lower(), _last_path_seg_core().lower()) /
            max(len(_domain_core()), len(_last_path_seg_core()))
        ) if _domain_core() and _last_path_seg_core() else 0.0
    )

    _safe_set("homoglyphs_count",  lambda: sum(ord(c)>127 for c in u))
    suspicious_tlds = ['xyz','top','gq','cf','tk','ml']
    _safe_set("suspicious_tld",    lambda: 1 if host_parts and host_parts[-1].lower() in suspicious_tlds else 0)
    _safe_set("repeated_subdomain",lambda: 1 if len(subs)!=len(set(subs)) and len(subs)>0 else 0)

    return feats


# ======================================================================
# === CONTENT FEATURES
# ======================================================================

def get_page_content(url: str) -> str:
    try:
        resp = requests.get(
            url, timeout=3,                   # was 5s
            headers={"User-Agent": "Mozilla/5.0 (compatible; PhishGuard/1.5)"},
            verify=False
        )
        return resp.text if resp.status_code == 200 else ""
    except Exception:
        return ""


CONTENT_FEATURE_KEYS = [
    "html_length","head_length","body_length","num_tags","num_inputs","num_forms","num_links",
    "num_scripts","num_iframes","num_embeds","forms_https","forms_get","input_passwords",
    "input_emails","external_links","external_ratio","mailto_count","js_links","internal_links",
    "num_images","external_images","has_favicon","external_favicon","external_scripts",
    "title_domain_match","title_length","title_is_generic","word_count","avg_word_len",
    "suspicious_keywords","text_entropy","iframe_src_external","hidden_elements","meta_refresh",
    "num_div","num_span","num_h1","num_h2","num_h3","num_table","num_tr","num_td","num_ul",
    "num_ol","num_li","num_p","num_button","num_meta","num_script_inline","num_script_external",
    "unique_tag_count","link_img_ratio","script_iframe_ratio","external_link_ratio",
    "text_link_ratio","form_input_ratio","script_body_ratio","dom_depth_approx"
]

# Pre-compute the global feature importance array once at startup.
# Placed here so both URL_FEATURE_KEYS and CONTENT_FEATURE_KEYS are already
# defined — referencing them above their definition caused a NameError.
# Works for XGBoost, RandomForest, GradientBoosting, DecisionTree, ExtraTrees.
# Falls back gracefully to equal weights if the model doesn't expose importances.
_FEATURE_ORDER: list[str]        = list(URL_FEATURE_KEYS) + list(CONTENT_FEATURE_KEYS)
_FEATURE_IMPORTANCE: dict[str, float] = {}

def _build_importance_map() -> None:
    global _FEATURE_IMPORTANCE
    if model is None:
        return
    try:
        imps = model.feature_importances_           # numpy array
        _FEATURE_IMPORTANCE = {
            feat: float(imp)
            for feat, imp in zip(_FEATURE_ORDER, imps)
        }
    except AttributeError:
        # Model doesn't have feature_importances_ — equal weights
        n = len(_FEATURE_ORDER)
        _FEATURE_IMPORTANCE = {feat: 1.0 / n for feat in _FEATURE_ORDER}

_build_importance_map()


def extract_content_features(url: str) -> dict:
    """
    Extract all content features from the page at `url`.
    Never bails out early — every feature is attempted independently.
    Features that cannot be computed keep their default value of 0.
    """
    feats = {k: 0 for k in CONTENT_FEATURE_KEYS}

    def _safe_set(key, fn):
        try:
            feats[key] = fn()
        except Exception:
            pass  # leave default; keep going

    # ── Fetch HTML ────────────────────────────────────────────────────────────
    html = get_page_content(url)
    # Set html_length from the raw string regardless of what comes next
    _safe_set("html_length", lambda: len(html))

    # ── Parse with BeautifulSoup (try lxml first, fall back to html.parser) ──
    soup = None
    if html:
        for parser in ("lxml", "html.parser"):
            try:
                soup = BeautifulSoup(html, parser)
                break
            except Exception as e:
                print(f"[CONTENT WARN] {parser} failed for {url!r}: {e}")

    # If soup is still None (both parsers failed or html was empty), all
    # soup-dependent _safe_set calls below will raise and be silently caught,
    # leaving those features at their default 0 values. Extraction continues.

    # ── Soup-dependent collections (each wrapped so one failure can't cascade) ─
    try: all_tags = soup.find_all() if soup else []
    except Exception: all_tags = []

    try: inputs  = soup.find_all("input")          if soup else []
    except Exception: inputs  = []
    try: forms   = soup.find_all("form")           if soup else []
    except Exception: forms   = []
    try: links   = soup.find_all("a", href=True)   if soup else []
    except Exception: links   = []
    try: scripts = soup.find_all("script")         if soup else []
    except Exception: scripts = []
    try: iframes = soup.find_all("iframe")         if soup else []
    except Exception: iframes = []
    try: embeds  = soup.find_all(["embed","object"]) if soup else []
    except Exception: embeds  = []
    try: images  = soup.find_all("img", src=True)  if soup else []
    except Exception: images  = []

    _safe_set("head_length", lambda: len(str(soup.head)) if soup and soup.head else 0)
    _safe_set("body_length", lambda: len(str(soup.body)) if soup and soup.body else 0)
    _safe_set("num_tags",    lambda: len(all_tags))

    _safe_set("num_inputs",  lambda: len(inputs))
    _safe_set("num_forms",   lambda: len(forms))
    _safe_set("num_links",   lambda: len(links))
    _safe_set("num_scripts", lambda: len(scripts))
    _safe_set("num_iframes", lambda: len(iframes))
    _safe_set("num_embeds",  lambda: len(embeds))

    domain = urlparse(url).netloc

    def _forms_https():
        for f in forms:
            action = f.get("action","")
            if action and not action.startswith("https"):
                return 0
        return 1

    _safe_set("forms_https", _forms_https)
    _safe_set("forms_get",       lambda: len([f for f in forms if f.get("method","").lower()=="get"]))
    _safe_set("input_passwords", lambda: len([i for i in inputs if i.get("type","").lower() in ("password","hidden")]))
    _safe_set("input_emails",    lambda: len([i for i in inputs if i.get("type","").lower()=="email"]))

    def _ext_links(): return [a for a in links if domain and domain not in a["href"]]

    _safe_set("external_links", lambda: len(_ext_links()))
    _safe_set("external_ratio", lambda: len(_ext_links())/len(links) if links else 0)
    _safe_set("mailto_count",   lambda: len([a for a in links if a["href"].lower().startswith("mailto:")]))
    _safe_set("js_links",       lambda: len([a for a in links if a["href"].lower().startswith("javascript:")]))
    _safe_set("internal_links", lambda: len(links)-len(_ext_links()))

    _safe_set("num_images",      lambda: len(images))
    _safe_set("external_images", lambda: len([img for img in images if domain and domain not in img["src"]]))

    def _fav(): return soup.find_all("link", rel=lambda x: x and "icon" in x.lower())

    _safe_set("has_favicon",      lambda: 1 if _fav() else 0)
    _safe_set("external_favicon", lambda: 1 if any(domain and domain not in f.get("href","") for f in _fav()) else 0)
    _safe_set("external_scripts", lambda: len([s for s in scripts if s.get("src") and domain and domain not in s["src"]]))

    def _title():
        try: return soup.title.string.strip() if soup.title and soup.title.string else ""
        except: return ""

    def _domain_core():
        parts = domain.split('.')
        return parts[-2] if len(parts)>=2 else domain

    _safe_set("title_length",       lambda: len(_title()))
    _safe_set("title_domain_match", lambda: 1 if _title() and _domain_core().lower() in _title().lower() else 0)
    _safe_set("title_is_generic",   lambda: 1 if any(w in _title().lower() for w in ['home','index','welcome','login','sign in']) else 0)

    def _text():  return soup.get_text(separator=" ").strip()
    def _words(): return [w for w in re.split(r'\s+', _text()) if w]

    _safe_set("word_count",   lambda: len(_words()))
    _safe_set("avg_word_len", lambda: sum(len(w) for w in _words())/len(_words()) if _words() else 0)

    kw = ['login','verify','password','bank','update','account','secure','confirm','click']
    _safe_set("suspicious_keywords", lambda: sum(_text().lower().count(k) for k in kw))
    _safe_set("text_entropy",        lambda: _entropy(_text()))

    _safe_set("iframe_src_external", lambda: len([i for i in iframes if i.get("src") and domain and domain not in i["src"]]))
    _safe_set("hidden_elements",     lambda: len([t for t in all_tags
        if t.get("style") and 'display:none' in t.get("style").replace(" ","").lower()]))
    _safe_set("meta_refresh",        lambda: len([m for m in soup.find_all("meta")
        if m.get("http-equiv","").lower()=="refresh"]))

    for tag, key in [
        ("div","num_div"),("span","num_span"),("h1","num_h1"),("h2","num_h2"),("h3","num_h3"),
        ("table","num_table"),("tr","num_tr"),("td","num_td"),("ul","num_ul"),("ol","num_ol"),
        ("li","num_li"),("p","num_p"),("button","num_button"),("meta","num_meta"),
    ]:
        _safe_set(key, lambda t=tag: len(soup.find_all(t)))

    _safe_set("num_script_inline",   lambda: len([s for s in scripts if not s.get("src")]))
    _safe_set("num_script_external", lambda: len([s for s in scripts if s.get("src")]))
    _safe_set("unique_tag_count",    lambda: len(set(t.name for t in all_tags)))

    def _ni(): return feats["num_images"]
    def _nf(): return feats["num_iframes"]
    def _ns(): return feats["num_scripts"]
    def _bl(): return feats["body_length"]
    def _wc(): return feats["word_count"]
    def _nl(): return feats["num_links"]

    _safe_set("link_img_ratio",      lambda: _nl()/_ni() if _ni()>0 else 0)
    _safe_set("script_iframe_ratio", lambda: _ns()/_nf() if _nf()>0 else 0)
    _safe_set("external_link_ratio", lambda: feats["external_ratio"])
    _safe_set("text_link_ratio",     lambda: _nl()/_wc() if _wc()>0 else 0)
    _safe_set("form_input_ratio",    lambda: feats["num_inputs"]/feats["num_forms"] if feats["num_forms"]>0 else 0)
    _safe_set("script_body_ratio",   lambda: _ns()/_bl() if _bl()>0 else 0)

    def _dom_depth():
        def _depth(el):
            d = 0
            while el and el.parent and getattr(el.parent,'name',None):
                d += 1; el = el.parent
            return d
        return max((_depth(t) for t in all_tags[:200]), default=0)

    _safe_set("dom_depth_approx", _dom_depth)

    return feats


# ======================================================================
# === ENDPOINTS
# ======================================================================

@app.post("/predict")
async def predict_url(request: URLRequest):
    if model is None:
        raise HTTPException(status_code=500, detail="Model not loaded on server")

    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Empty URL")

    # FIX: Reject browser-internal URLs immediately
    if not is_scannable_url(url):
        return {
            "status": "skipped",
            "message": "This page type is not scannable",
            "prediction": "Legitimate",
            "confidence": 1.0,
        }

    # ── Tier 0: full result cache ─────────────────────────────────────────────
    # If we've predicted this exact URL in the last hour, return instantly.
    result_cache_key = url.lower().strip()
    cached_result = _RESULT_CACHE.get(result_cache_key)
    if cached_result is not None:
        print(f"[CACHE] Hit for {url!r}")
        return cached_result

    # ── Tier 1: trusted domain whitelist ─────────────────────────────────────
    # Checks Tranco Top 5000 (popularity-based) + static fallback list.
    # Returns immediately without running the model — zero false positives
    # for QuillBot, Humanizer, AI sites, popular tools etc.
    trusted, trust_source = _is_trusted_domain(url)
    if trusted:
        source_label = (
            "This site ranks in the world's top 5,000 most-visited domains"
            if "tranco" in trust_source
            else "This site is on our verified safe list"
        )
        return {
            "status":       "trusted",
            "message":      source_label,
            "prediction":   "Legitimate",
            "confidence":   1.0,
            "reasons":      [],
            "trust_source": trust_source,
        }

    url_lower = url.lower()

    # Fast path: already seen in training CSV
    if url_lower in known_urls:
        row = known_urls_df[known_urls_df["url_norm"] == url_lower].iloc[0]
        pred = int(row["label"])
        result = "Phishing" if pred == 1 else "Legitimate"
        message = (
            "This is a known phishing site"
            if result == "Phishing"
            else "This site is verified safe"
        )
        return {
            "status":     "known",
            "message":    message,
            "prediction": result,
            "confidence": 1.0,
            "reasons":    [],
        }

    # ── 4-way parallel extraction ─────────────────────────────────────────────
    #
    #   Thread 1 — CPU URL features      ~10ms   pure computation
    #   Thread 2 — WHOIS lookup          1–3s    network
    #   Thread 3 — Content fetch/parse   1–5s    network
    #   Thread 4 — Google Safe Browsing  0.5–2s  network (independent API)
    #
    # All five run simultaneously. Total time = max of the five, not their sum.
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_url     = executor.submit(extract_url_features, url)
        future_whois   = executor.submit(_fetch_whois_features, url)
        future_content = executor.submit(extract_content_features, url)
        future_gsb     = executor.submit(check_google_safe_browsing, url)
        future_vt      = executor.submit(check_virustotal, url)

        try:
            url_feats = future_url.result(timeout=3)   # CPU only
        except Exception as e:
            print(f"URL feature error for {url!r}: {e}")
            url_feats = {k: 0 for k in URL_FEATURE_KEYS}

        try:
            age, expiry, privacy = future_whois.result(timeout=3)  # was 5s; WHOIS now cached
        except Exception as e:
            print(f"WHOIS error for {url!r}: {e}")
            age, expiry, privacy = -1, -1, -1

        url_feats["domain_age_days"] = age
        url_feats["days_to_expiry"]  = expiry
        url_feats["whois_privacy"]   = privacy

        try:
            content_feats = future_content.result(timeout=4)  # was 6s
        except Exception as e:
            print(f"Content feature error for {url!r}: {e}")
            content_feats = {k: 0 for k in CONTENT_FEATURE_KEYS}

        try:
            gsb_result = future_gsb.result(timeout=4)   # was 5s
        except Exception as e:
            print(f"GSB error for {url!r}: {e}")
            gsb_result = {"is_unsafe": False, "threat_type": None, "source": "gsb_error"}

        try:
            vt_result = future_vt.result(timeout=6)   # was 15s; VT now max ~2.4s with fast poll
        except Exception as e:
            print(f"VT error for {url!r}: {e}")
            vt_result = {"checked": False, "source": "vt_error",
                         "malicious": 0, "suspicious": 0, "total": 0,
                         "trust_score": -1, "verdict": "unknown"}

    all_features   = {**url_feats, **content_feats}
    feature_order  = list(URL_FEATURE_KEYS) + list(CONTENT_FEATURE_KEYS)
    features_df    = pd.DataFrame([[all_features[k] for k in feature_order]], columns=feature_order)

    pred       = int(model.predict(features_df)[0])
    proba      = model.predict_proba(features_df)[0]
    confidence = float(max(proba))
    ml_result  = "Phishing" if pred == 1 else "Legitimate"
    reasons    = get_top_reasons(all_features, ml_result)

    # ══════════════════════════════════════════════════════════════════
    # SINGLE-SOURCE DECISION ENGINE
    # ══════════════════════════════════════════════════════════════════
    #
    # Three possible verdicts returned to both popup.js and background.js:
    #   "Phishing"   → red alert  (badge=PHSH, notification, red overlay)
    #   "Uncertain"  → orange warning (badge=WARN, notification, orange overlay)
    #   "Legitimate" → all clear  (badge=SAFE, no notification, green popup)
    #
    # Decision order (first match wins):
    #   Rule 1: GSB flagged                              → Phishing
    #   Rule 2: VT ≥ 8 malicious vendors                → Phishing
    #   Rule 3: VT suspicious (3–7) + ML missed it      → Uncertain  ← FIX: was silently Legitimate
    #   Rule 4: ML ≥ 80% + VT trust ≥ 85               → Uncertain  (ML says bad, VT clears = conflict)
    #   Rule 5: ML ≥ 80% + VT trust < 70               → Phishing   (both agree it's risky)
    #   Rule 6: ML ≥ 80% + VT unchecked/middle          → Phishing   (trust ML alone)
    #   Rule 7: ML < 80%                                → Legitimate (not confident enough)
    #   Rule 8: ML = Legitimate                         → Legitimate

    CONFIDENCE_THRESHOLD = 0.80   # ML must be at least this confident to trigger an alert
    VT_CLEAR_THRESHOLD   = 85     # VT trust ≥ this → reputation considered clean
    VT_DANGER_THRESHOLD  = 70     # VT trust < this → reputation considered risky

    vt_trust   = vt_result.get("trust_score", -1)
    vt_verdict = vt_result.get("verdict", "unknown")
    vt_mal     = vt_result.get("malicious", 0)
    vt_sus     = vt_result.get("suspicious", 0)
    vt_total   = vt_result.get("total", 0)
    vt_checked = vt_result.get("checked", False)

    # ── Rule 1: GSB definitive blacklist ──────────────────────────────
    if gsb_result.get("is_unsafe"):
        threat     = gsb_result.get("threat_type", "UNKNOWN")
        result     = "Phishing"
        confidence = max(confidence, 0.97)
        message    = f"Confirmed threat by Google Safe Browsing ({threat.replace('_', ' ').title()})"
        reasons    = [
            {"label": f"Flagged by Google Safe Browsing as {threat.replace('_', ' ').title()}",
             "severity": "high", "feature": "gsb", "value": 1}
        ] + reasons

    # ── Rule 2: VirusTotal multi-vendor consensus ─────────────────────
    # Fires regardless of what ML thinks — 8+ security vendors is strong evidence.
    elif vt_verdict == "malicious":
        result     = "Phishing"
        confidence = max(confidence, 0.95)
        message    = f"Flagged as malicious by {vt_mal} of {vt_total} security vendors"
        reasons    = [
            {"label": f"Detected as malicious by {vt_mal}/{vt_total} security vendors (VirusTotal)",
             "severity": "high", "feature": "virustotal", "value": vt_mal}
        ] + reasons

    # ── Rule 3: VT suspicious + ML didn't catch it → Uncertain ────────
    # BUG FIX: previously this fell silently to Legitimate (Rule 7/8).
    # If 3–7 vendors flag it as suspicious but ML says it's fine,
    # something is off — show a warning rather than a green light.
    elif vt_verdict == "suspicious" and vt_checked and ml_result == "Legitimate":
        result  = "Uncertain"
        message = (f"{vt_mal + vt_sus} security vendors flagged this site as suspicious. "
                   f"Our model considers it legitimate — proceed with caution.")
        reasons = [
            {"label": f"Flagged as suspicious by {vt_mal+vt_sus} of {vt_total} security vendors",
             "severity": "medium", "feature": "virustotal", "value": vt_mal + vt_sus}
        ]

    # ── Rules 4–8: ML-based decisions ─────────────────────────────────
    elif ml_result == "Phishing":
        if confidence >= CONFIDENCE_THRESHOLD:

            # Rule 4: ML confident + VT clears the site → genuine conflict
            if vt_checked and vt_trust >= VT_CLEAR_THRESHOLD:
                result  = "Uncertain"
                message = (f"Our model flagged this site ({round(confidence*100)}% confidence) "
                           f"but {vt_total} security vendors rate it as trustworthy "
                           f"(trust score {vt_trust}/100). Proceed with caution.")

            # Rule 5: ML confident + VT reputation also risky → Phishing
            elif vt_checked and vt_trust < VT_DANGER_THRESHOLD:
                result  = "Phishing"
                message = "This site shows multiple signs of a phishing attack"
                reasons = reasons + [
                    {"label": f"VirusTotal trust score is low ({vt_trust}/100 — below safe threshold)",
                     "severity": "medium", "feature": "virustotal", "value": vt_trust}
                ]

            # Rule 6: ML confident + VT not checked or trust in middle range
            else:
                result  = "Phishing"
                message = "This site shows multiple signs of a phishing attack"
                if vt_verdict == "suspicious" and vt_checked:
                    reasons = reasons + [
                        {"label": f"Also flagged as suspicious by {vt_mal+vt_sus} security vendors",
                         "severity": "medium", "feature": "virustotal", "value": vt_mal+vt_sus}
                    ]

        else:
            # Rule 7: ML confidence below threshold → not certain enough to alert
            result  = "Legitimate"
            message = "No threats detected on this page"
            print(f"[DECISION] ML Phishing at {confidence:.2f} < {CONFIDENCE_THRESHOLD} threshold → Legitimate")

    # ── Rule 8: ML says Legitimate ────────────────────────────────────
    else:
        result  = "Legitimate"
        message = "No threats detected on this page"

    # ── PhishTank / OpenPhish feed — weak signal only ────────────────────────
    # The feed is NOT used as a verdict bypass (see decision comment above).
    # If the URL appears in the feed, it is added as a medium-severity reason
    # that feeds into the reasons list. The decision engine still runs normally
    # using ML + GSB + VT — the feed just adds one more piece of evidence.
    if _PHISHING_URLS:
        norm_url = _normalise_url(url)
        if norm_url in _PHISHING_URLS:
            feed_reason = {
                "label":    "URL was previously reported in PhishTank / OpenPhish phishing database",
                "severity": "medium",
                "feature":  "phishing_feed",
                "value":    1,
            }
            # Prepend to reasons so it appears near the top
            reasons = [feed_reason] + [r for r in reasons if r.get("feature") != "phishing_feed"]
            print(f"[FEED] {url!r} matched phishing feed — added as signal (not bypass)")

    # Build VT summary for frontend
    vt_summary = {
        "checked":     vt_checked,
        "trust_score": vt_trust,
        "malicious":   vt_mal,
        "suspicious":  vt_sus,
        "total":       vt_total,
        "verdict":     vt_verdict,
        "source":      vt_result.get("source", "vt_skipped"),
    }

    response_data = {
        "status":      "predicted",
        "message":     message,
        "prediction":  result,
        "confidence":  confidence,
        "reasons":     reasons,
        "gsb_checked": gsb_result.get("source", "unknown"),
        "vt":          vt_summary,
        "features":    all_features,
    }
    # Write to result cache — next identical URL returns instantly (~5ms)
    _RESULT_CACHE.set(result_cache_key, response_data, ttl=86400)  # 24h
    return response_data


@app.post("/quick")
async def quick_predict(request: URLRequest):
    """URL features only — fast scan for the extension."""
    if model is None:
        raise HTTPException(status_code=500, detail="Model not loaded")

    url = request.url.strip()

    # FIX: Guard non-HTTP URLs
    if not is_scannable_url(url):
        return {
            "prediction": "Legitimate",
            "confidence": 1.0,
            "message":    "This page type is not scannable"
        }

    try:
        feats       = extract_url_features(url)
        features_df = pd.DataFrame([[feats[k] for k in URL_FEATURE_KEYS]], columns=URL_FEATURE_KEYS)
        pred        = int(model.predict(features_df)[0])
        proba       = model.predict_proba(features_df)[0]
        confidence  = float(max(proba))
        result      = "Phishing" if pred == 1 else "Legitimate"
        reasons     = get_top_reasons(feats, result)
        message     = (
            "Suspicious URL pattern detected"
            if result == "Phishing"
            else "URL appears safe"
        )
        return {
            "prediction": result,
            "confidence": confidence,
            "message":    message,
            "reasons":    reasons,
        }
    except Exception as e:
        print(f"Quick scan error: {e}")
        raise HTTPException(status_code=500, detail=f"Quick scan failed: {str(e)}")


@app.post("/screenshot")
async def analyze_screenshot(request: ScreenshotRequest):
    """
    Receive a base64 PNG screenshot from the extension, compute its
    perceptual hash, and check it against KNOWN_PHISHING_HASHES.

    The extension calls this alongside /predict using chrome.tabs.captureVisibleTab.
    Results are merged client-side in background.js.

    To populate the hash database: visit a confirmed phishing page, call
    POST /hash/add with its screenshot, and the hash is stored for future checks.
    """
    if not request.screenshot:
        raise HTTPException(status_code=400, detail="No screenshot provided")

    result = is_visual_clone(request.screenshot)
    current_hash = result.get("current_hash")

    return {
        "is_clone":     result["is_clone"],
        "matched_hash": result.get("matched_hash"),
        "current_hash": current_hash,
        "db_size":      len(KNOWN_PHISHING_HASHES),
        "message": (
            "Screenshot matches a known phishing page design"
            if result["is_clone"]
            else "Page design does not match known phishing templates"
        )
    }


@app.post("/hash/add")
async def add_phishing_hash(request: ScreenshotRequest):
    """
    Add the screenshot of a confirmed phishing page to the persistent hash database.

    The hash is stored in:
      - KNOWN_PHISHING_HASHES (in-memory, used immediately for checks)
      - phishing_hashes.json  (on disk, survives server restarts)

    Next time the server starts, this hash will be loaded automatically.
    """
    h = compute_screenshot_hash(request.screenshot)
    if not h:
        raise HTTPException(status_code=400, detail="Could not compute hash from screenshot")

    already_existed = h in KNOWN_PHISHING_HASHES
    KNOWN_PHISHING_HASHES.add(h)

    # Store URL→hash mapping for reliable removal later
    # (removing by URL lookup is far more reliable than recomputing screenshot hash)
    url_key = request.url.strip().lower()
    _URL_TO_HASH[url_key] = h

    # Persist both to disk
    _save_hash_db(KNOWN_PHISHING_HASHES, _URL_TO_HASH)

    return {
        "added":          h,
        "already_existed": already_existed,
        "db_size":        len(KNOWN_PHISHING_HASHES),
        "persisted_to":   _HASH_DB_PATH,
        "message":        f"Hash {h} added and mapped to URL"
                          if not already_existed
                          else f"Hash {h} already in database"
    }


@app.post("/hash/remove-by-url")
async def remove_hash_by_url(request: URLRequest):
    """
    Remove a phishing hash by URL lookup (primary removal method).

    When a hash is added via /hash/add, the URL→hash mapping is stored.
    This endpoint looks up the hash by URL — much more reliable than
    recomputing a screenshot hash (which changes with scroll position,
    popup overlays, screen resolution, etc.).

    Called by popup.js and content.js when "Mark as Safe" is clicked.
    """
    url_key = request.url.strip().lower()
    h = _URL_TO_HASH.get(url_key)

    if not h:
        return {
            "removed":  False,
            "hash":     None,
            "db_size":  len(KNOWN_PHISHING_HASHES),
            "message":  "No hash mapping found for this URL — nothing to remove"
        }

    KNOWN_PHISHING_HASHES.discard(h)
    _URL_TO_HASH.pop(url_key, None)
    _save_hash_db(KNOWN_PHISHING_HASHES, _URL_TO_HASH)

    return {
        "removed":      True,
        "hash":         h,
        "db_size":      len(KNOWN_PHISHING_HASHES),
        "persisted_to": _HASH_DB_PATH,
        "message":      f"Hash {h} removed from DB and URL mapping cleared"
    }


@app.post("/hash/remove-by-screenshot")
async def remove_hash_by_screenshot(request: ScreenshotRequest):
    """
    Fallback: remove hash by recomputing screenshot pHash.
    Less reliable than /hash/remove-by-url — use that instead when possible.
    """
    if not request.screenshot:
        raise HTTPException(status_code=400, detail="No screenshot provided")

    h = compute_screenshot_hash(request.screenshot)
    if not h:
        return {"removed": False, "hash": None, "db_size": len(KNOWN_PHISHING_HASHES),
                "message": "Could not compute hash"}

    if h not in KNOWN_PHISHING_HASHES:
        return {"removed": False, "hash": h, "db_size": len(KNOWN_PHISHING_HASHES),
                "message": f"Hash not in database — nothing removed"}

    KNOWN_PHISHING_HASHES.discard(h)
    # Also remove any URL mapping that points to this hash
    for k, v in list(_URL_TO_HASH.items()):
        if v == h:
            _URL_TO_HASH.pop(k, None)
    _save_hash_db(KNOWN_PHISHING_HASHES, _URL_TO_HASH)

    return {"removed": True, "hash": h, "db_size": len(KNOWN_PHISHING_HASHES),
            "message": f"Hash {h} removed"}


@app.get("/hash/list")
async def list_phishing_hashes():
    """List all known phishing page hashes currently in the database."""
    return {
        "db_size":    len(KNOWN_PHISHING_HASHES),
        "db_path":    _HASH_DB_PATH,
        "hashes":     sorted(KNOWN_PHISHING_HASHES),
        "imagehash_available": _IMAGEHASH_AVAILABLE,
    }


@app.delete("/hash/delete")
async def delete_phishing_hash(hash_str: str):
    """
    Remove a specific hash from the database (useful for false positives).
    Pass the hash string as a query parameter:
      DELETE /hash/delete?hash_str=abc123...
    """
    if hash_str not in KNOWN_PHISHING_HASHES:
        raise HTTPException(status_code=404, detail=f"Hash {hash_str!r} not found in database")
    KNOWN_PHISHING_HASHES.discard(hash_str)
    _save_hash_db(KNOWN_PHISHING_HASHES)
    return {
        "deleted":  hash_str,
        "db_size":  len(KNOWN_PHISHING_HASHES),
        "message":  f"Hash removed from memory and disk"
    }


@app.post("/cache/update")
async def update_cache_entry(request: dict):
    """
    Write a client-side overridden result back to the server cache.
    Called by background.js and popup.js after visual clone override fires,
    so all clients (popup, overlay, next scan) see the same consistent result.
    """
    url    = request.get("url", "").strip()
    result = request.get("result", {})
    if not url or not result:
        raise HTTPException(status_code=400, detail="url and result required")
    _RESULT_CACHE.set(url.lower(), result, ttl=86400)
    return {"status": "updated", "url": url, "prediction": result.get("prediction")}


@app.post("/cache/clear")
async def clear_cache():
    """
    Clears all in-memory caches. Call this after updating decision logic
    so old cached verdicts don't get served.
    POST http://localhost:8000/cache/clear
    """
    r = _RESULT_CACHE.size()
    w = _WHOIS_CACHE.size()
    v = _VT_CACHE.size()
    _RESULT_CACHE._data.clear()
    _WHOIS_CACHE._data.clear()
    _VT_CACHE._data.clear()
    return {
        "cleared": {"result_cache": r, "whois_cache": w, "vt_cache": v},
        "message": "All caches cleared. Next request will be a fresh scan."
    }


@app.get("/cache-stats")
async def cache_stats():
    """Shows current cache sizes. Visit http://localhost:8000/cache-stats"""
    return {
        "result_cache":  {"entries": _RESULT_CACHE.size(), "ttl_hours": 24},
        "whois_cache":   {"entries": _WHOIS_CACHE.size(),  "ttl_hours": 24},
        "vt_cache":      {"entries": _VT_CACHE.size(),     "ttl_hours": 24},
        "note": "Hit the same URL twice to see result_cache grow by 1."
    }


@app.get("/feed-status")
async def feed_status():
    """
    Shows status of the phishing URL feeds (PhishTank + OpenPhish).
    Visit http://localhost:8000/feed-status to verify feeds loaded correctly.
    """
    return {
        "phishing_feed": _phishing_feed_meta,
        "url_count":     len(_PHISHING_URLS),
        "note": (
            "Feeds are downloaded at server startup. "
            "Restart the server to refresh them. "
            "A URL matching the feed is immediately returned as Phishing (no ML needed)."
        )
    }


@app.get("/whitelist-status")
async def whitelist_status():
    """
    Shows how many domains are in each whitelist layer.
    Useful for checking whether the Tranco download succeeded at startup.
    Visit http://localhost:8000/whitelist-status in your browser.
    """
    return {
        "tranco": {
            "loaded":       _tranco_meta["loaded"],
            "domain_count": _tranco_meta["domain_count"],
            "top_n":        TRANCO_TOP_N,
            "loaded_at":    _tranco_meta["loaded_at"],
            "error":        _tranco_meta["error"],
        },
        "static": {
            "domain_count": len(_STATIC_DOMAINS),
        },
        "total_trusted": _tranco_meta["domain_count"] + len(_STATIC_DOMAINS),
        "note": "Tranco domains are loaded at server startup. "
                "Restart the server to refresh."
    }


@app.get("/")
async def root():
    return {"message": "Advanced Phishing Detection API ready"}


# ── In-memory report log (replace with a database in production) ───────────────
_REPORTS: list[dict] = []

class ReportRequest(BaseModel):
    url:         str
    report_type: str = "false_positive"   # "false_positive" or "false_negative"
    reported_by: str = "user"

@app.post("/report")
async def report_url(request: ReportRequest):
    """
    Accept a user-submitted false positive or false negative report.

    Critical behaviour: immediately overwrites the cached result for this URL
    so the next visit shows the user-corrected verdict for 24 hours.

      false_positive → user says this is safe  → cache as Legitimate
      false_negative → user says this is phishing → cache as Phishing
    """
    url         = request.url.strip()
    report_type = request.report_type
    cache_key   = url.lower().strip()

    # Build a corrected cached result based on what the user reported
    if report_type == "false_positive":
        corrected_prediction = "Legitimate"
        corrected_message    = "Marked as safe by user report"
    else:  # false_negative
        corrected_prediction = "Phishing"
        corrected_message    = "Marked as phishing by user report"

    corrected_result = {
        "status":      "user_reported",
        "message":     corrected_message,
        "prediction":  corrected_prediction,
        "confidence":  1.0,
        "reasons":     [{
            "label":    corrected_message,
            "severity": "high" if corrected_prediction == "Phishing" else "low",
            "feature":  "user_report",
            "value":    1,
        }],
        "gsb_checked": "user_reported",
        "vt":          {"checked": False, "source": "user_reported",
                        "malicious": 0, "suspicious": 0, "total": 0,
                        "trust_score": -1, "verdict": "unknown"},
        "features":    {},
    }

    # Overwrite cache — next visit within 24h returns corrected verdict instantly
    _RESULT_CACHE.set(cache_key, corrected_result, ttl=86400)

    # If marking as safe: also remove the phishing hash for this URL
    # so visual clone detection doesn't override the correction
    if report_type == "false_positive":
        h = _URL_TO_HASH.pop(url.lower(), None)
        if h:
            KNOWN_PHISHING_HASHES.discard(h)
            _save_hash_db(KNOWN_PHISHING_HASHES, _URL_TO_HASH)
            print(f"[REPORT] Hash {h} removed for false_positive on {url!r}")

    entry = {
        "url":         url,
        "report_type": report_type,
        "corrected_to": corrected_prediction,
        "reported_by": request.reported_by,
        "timestamp":   dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    _REPORTS.append(entry)
    print(f"[REPORT] {entry} → cache overwritten for 24h")

    return {
        "status":  "received",
        "corrected_to": corrected_prediction,
        "message": f"Thank you — this site will show as {corrected_prediction} for 24 hours",
        "total_reports": len(_REPORTS),
    }


@app.get("/reports")
async def get_reports():
    """View all submitted reports (protect this endpoint in production)."""
    return {"count": len(_REPORTS), "reports": _REPORTS}