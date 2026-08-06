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
from collections import Counter, deque          # ← ADDED for admin stats
from dotenv import load_dotenv

# Load .env file from the same directory as app.py
# This reads all secrets automatically so you don't have to set
# environment variables manually each session.
#
# Required keys in .env:
#   GOOGLE_SAFE_BROWSING_KEY=your_gsb_key
#   VIRUSTOTAL_API_KEYS=key1,key2,...
#   PHISHS_CREDENTIALS=pub1:sec1,pub2:sec2,...
#     (each pair is publicKey:secretKey, comma-separated for multiple accounts)
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

_RESULT_CACHE  = _TTLCache()
_WHOIS_CACHE   = _TTLCache()
_VT_CACHE      = _TTLCache()
_PHISHS_CACHE  = _TTLCache()   # 24-h cache for Phishs.com results

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

# tldextract gives correct registrable-domain + suffix splitting for ANY ccTLD
# (e.g.  mgmpu.mgmudupi.ac.in  →  subdomain='mgmpu', domain='mgmudupi', suffix='ac.in')
# Without it, naive .split('.') treats multi-label ccTLDs like 'ac.in' as one label
# and misidentifies the domain and subdomain count, producing noisy feature vectors
# that push legitimate institutional sites toward "Phishing".
# Ships an offline snapshot so it never needs live internet access at request time.
try:
    import tldextract as _tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _tldextract = None          # type: ignore
    _TLDEXTRACT_AVAILABLE = False
    print("WARNING: 'tldextract' not installed. Domain-parsing will fall back to "
          "naive split — multi-label ccTLD sites (.ac.in, .co.uk, etc.) may be "
          "misclassified. Run:  pip install tldextract --break-system-packages")

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
    # Only the React admin dashboard (localhost:3000) is allowed to make
    # cross-origin requests. The browser extension bypasses CORS entirely
    # via host_permissions in manifest.json — it does not need to be listed here.
    # "https://*/*" and "http://*/*" have been removed — they allowed ANY website
    # on the internet to query your API, which defeats the purpose of CORS.
    allow_origins=["http://localhost:3000"],
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
    # Normalise stored URLs the same way we normalise browser URLs at lookup time.
    # This strips tracking params, fragments, trailing slashes — so
    # "http://evil.com/?utm_source=bing" matches "http://evil.com" in the CSV.
    known_urls_df["url_norm"] = (
        known_urls_df["url"].astype(str)
        .str.strip().str.lower()
        .str.rstrip('/')   # strip trailing slash at load time too
        .str.split('#').str[0]  # drop fragment
    )
    known_urls = set(known_urls_df["url_norm"].tolist())
    print(f"Loaded model. Known URLs: {len(known_urls)}")
except FileNotFoundError:
    model = None
    known_urls_df = None
    known_urls = set()
    print("Model/CSV not found – known-URL shortcut disabled")


def _cache_key(url: str) -> str:
    """
    Compute the result-cache key: scheme + host + path ONLY (no query params).

    Why strip all query params for caching (but not for known-URL lookup):
      • Ad networks (Bing, Google) append unique tracking params on every click:
        utm_source, utm_medium, campaignid, language, matchtype, network, etc.
        Many of these are NOT in the TRACKING removal set, so _normalise_for_lookup
        leaves them in — causing a different cache key every single visit.
      • The ML model, WHOIS, and content features all operate on the page
        at scheme://host/path.  Query parameters never change what the page
        looks like to our detector.
      • Result: using scheme+host+path as the key guarantees a cache hit on
        any second visit to the same page regardless of which ad params are present.

    _normalise_for_lookup() is still used for known-URL matching (training CSV)
    because the CSV URLs may legitimately include query params that distinguish
    different pages on the same domain.
    """
    try:
        from urllib.parse import urlparse
        p    = urlparse(url.strip().lower())
        path = p.path.rstrip('/') or '/'
        return f"{p.scheme}://{p.netloc}{path}"
    except Exception:
        return url.strip().lower()


class URLRequest(BaseModel):
    url: str
    # True only when the user explicitly clicks "Scan Current Page" in the
    # popup. False (default) means this came from the extension's automatic
    # background scan on page load/navigation. Used to suppress logging of
    # routine "trusted" verdicts from auto-scan (see /predict Tier 1 below) —
    # every page load/refresh of a trusted site was otherwise spamming
    # Total Scans and Scan History with entries the user never asked for.
    manual: bool = False


def _normalise_for_lookup(url: str) -> str:
    """
    Normalise a URL to a canonical form for known-URL and feed matching.

    URLs in the training CSV are plain bare URLs (no UTM params, no fragment,
    no trailing slash variations). But browsers send full URLs with tracking
    params (utm_source, fbclid, gclid etc.) and trailing slashes. Without
    normalisation, `http://evil.com` in the CSV never matches
    `http://evil.com/?utm_source=bing&utm_medium=cpc` from the browser.

    Steps:
      1. Lowercase the entire URL
      2. Strip scheme-normalised trailing slash from path ("/")
      3. Remove the fragment (#...) entirely
      4. Drop common tracking query parameters
         (utm_*, fbclid, gclid, msclkid, mc_*, ref, referrer, etc.)
      5. If all query params were tracking-only, drop the "?" too
    """
    try:
        from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
        p = urlparse(url.strip().lower())

        # Remove tracking-only query params — keep non-tracking ones
        TRACKING = {
            'utm_source','utm_medium','utm_campaign','utm_term','utm_content',
            'utm_id','utm_funnel','utm_match_type','fbclid','gclid','msclkid',
            'mc_cid','mc_eid','ref','referrer','source','partner','id',
            'adgroupid','adid','campaignid','ad_id','ad_set_id','adset_id',
        }
        params = parse_qs(p.query, keep_blank_values=True)
        filtered = {k: v for k, v in params.items() if k not in TRACKING}
        new_query = urlencode(filtered, doseq=True)

        # Normalise path: collapse // and strip trailing slash (except bare /)
        path = p.path or '/'
        while '//' in path:
            path = path.replace('//', '/')
        if path != '/' and path.endswith('/'):
            path = path.rstrip('/')

        normalised = urlunparse((
            p.scheme, p.netloc, path, p.params, new_query, ''  # drop fragment
        ))
        return normalised
    except Exception:
        return url.strip().lower()

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

TRANCO_TOP_N     = 50000          # raise to 10000 to cover more sites
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
# ========== VirusTotal with API KEY ROTATION + PER‑KEY RATE LIMIT + COOLDOWN ==========

VT_API_KEYS = [k.strip() for k in os.environ.get("VIRUSTOTAL_API_KEYS", "").split(",") if k.strip()]
VT_API_URL = "https://www.virustotal.com/api/v3/urls"

VT_SUSPICIOUS_THRESHOLD = 3
VT_MALICIOUS_THRESHOLD = 8

# Rate limit: 4 requests per minute per key (free tier)
VT_REQUESTS_PER_WINDOW = 4
VT_WINDOW_SECONDS = 60

class VTKey:
    def __init__(self, key):
        self.key = key
        self.request_times = deque()      # from collections import deque
        self.lock = threading.Lock()

    def wait_if_needed(self, max_wait: float = 5.0):
        """
        Block until a rate-limit slot is available, or max_wait seconds elapse.

        PERF FIX: Was an infinite `while True` — when all 4 slots were used it
        slept up to 60 s per iteration with no exit. Under rate pressure this was
        a primary cause of 45–80 s response times (the executor shutdown(wait=True)
        couldn't return while this thread was stuck in here).

        Returns True when a slot is obtained, False when max_wait expires.
        Returning False is safe: check_virustotal moves to the next key; if all
        keys are exhausted it falls through to the cached-miss default —
        identical behaviour to receiving a 429, which was already handled.
        """
        deadline = time.time() + max_wait
        while True:
            with self.lock:
                now = time.time()
                while self.request_times and now - self.request_times[0] >= VT_WINDOW_SECONDS:
                    self.request_times.popleft()
                if len(self.request_times) < VT_REQUESTS_PER_WINDOW:
                    self.request_times.append(now)
                    return True
                if now >= deadline:
                    return False          # give up; caller handles gracefully
                wait = min(
                    VT_WINDOW_SECONDS - (now - self.request_times[0]) + 0.1,
                    deadline - now        # never sleep past our own deadline
                )
            time.sleep(max(0.1, wait))

# Create key objects
_vt_keys = [VTKey(k) for k in VT_API_KEYS]
_vt_key_counter = 0
_vt_key_lock = threading.Lock()
_vt_cooldown = {}          # key -> timestamp when cooldown expires
_vt_cooldown_lock = threading.Lock()

def _get_next_vt_key():
    """Round‑robin selection of next VT key, skipping keys that are in cooldown."""
    if not _vt_keys:
        return None
    with _vt_key_lock, _vt_cooldown_lock:
        global _vt_key_counter
        for _ in range(len(_vt_keys)):
            key_obj = _vt_keys[_vt_key_counter % len(_vt_keys)]
            _vt_key_counter += 1
            # Skip if key is in cooldown (from a recent 429)
            if key_obj.key in _vt_cooldown:
                if time.time() < _vt_cooldown[key_obj.key]:
                    continue
                else:
                    del _vt_cooldown[key_obj.key]
            return key_obj
    return None

def _mark_vt_cooldown(key, seconds=60):
    """Mark a key as rate‑limited, do not use it for `seconds`."""
    with _vt_cooldown_lock:
        _vt_cooldown[key] = time.time() + seconds
        print(f"[VT] Key ...{key[-4:]} is now in cooldown for {seconds}s")

def _remove_vt_key(key_obj):
    """Permanently remove an invalid key from the pool."""
    with _vt_key_lock:
        if key_obj in _vt_keys:
            _vt_keys.remove(key_obj)
            print(f"[VT] Removed invalid key ...{key_obj.key[-4:]}")

def _vt_parse_stats(stats: dict) -> dict:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    score = (malicious + suspicious * 0.7) / total if total > 0 else 0.0
    trust = max(0, int(100 - score * 100))
    verdict = ("malicious" if malicious >= VT_MALICIOUS_THRESHOLD else
               "suspicious" if (malicious >= VT_SUSPICIOUS_THRESHOLD or
                                suspicious >= VT_SUSPICIOUS_THRESHOLD) else "clean")
    return {
        "checked": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "total": total,
        "score": score,
        "trust_score": trust,
        "verdict": verdict,
        "source": "virustotal",
    }

def check_virustotal(url: str) -> dict:
    _VT_SKIP = {"checked": False, "source": "vt_skipped",
                "malicious": 0, "suspicious": 0, "harmless": 0,
                "total": 0, "score": 0.0, "trust_score": -1, "verdict": "unknown"}
    _VT_ERR = {**_VT_SKIP, "source": "vt_error"}

    if not _vt_keys:
        return _VT_SKIP

    cache_key = hashlib.sha256(url.encode()).hexdigest()
    cached = _VT_CACHE.get(cache_key)
    if cached is not None:
        return cached

    # Try each key in round‑robin order, respecting cooldown and rate limits
    for _ in range(len(_vt_keys) * 3):   # extra attempts for cooldown
        key_obj = _get_next_vt_key()
        if not key_obj:
            break

        # Wait for this key's rate limit slot (successful requests only)
        key_obj.wait_if_needed()

        headers = {"x-apikey": key_obj.key}
        try:
            import base64 as _b64
            url_id = _b64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            # Check if VT already has this URL
            existing = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers, timeout=4
            )
            if existing.status_code == 200:
                attrs = existing.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats")
                if stats:
                    result = _vt_parse_stats(stats)
                    _VT_CACHE.set(cache_key, result, ttl=86400)
                    return result
            elif existing.status_code == 429:
                _mark_vt_cooldown(key_obj.key)
                continue
            elif existing.status_code == 401:
                _remove_vt_key(key_obj)
                continue
            elif not existing.ok:
                continue   # other error, try next key

            # Submit new URL for analysis
            submit = requests.post(VT_API_URL, headers=headers, data={"url": url}, timeout=6)
            if submit.status_code == 429:
                _mark_vt_cooldown(key_obj.key)
                continue
            if submit.status_code == 401:
                _remove_vt_key(key_obj)
                continue
            if submit.status_code not in (200, 201):
                continue

            analysis_id = submit.json()["data"]["id"]

            # Poll for completion (max 3 attempts)
            # PERF: Reduced from 0.8s to 0.5s per poll — saves 0.9s total
            # (3 × 0.5 = 1.5s vs 3 × 0.8 = 2.4s). VT analysis typically
            # completes within 1-2s; polling sooner catches it faster.
            for _ in range(3):
                time.sleep(0.5)
                poll = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers, timeout=4
                )
                if poll.status_code == 429:
                    _mark_vt_cooldown(key_obj.key)
                    break   # try another key
                if poll.status_code == 200:
                    poll_data = poll.json()
                    if poll_data.get("data", {}).get("attributes", {}).get("status") == "completed":
                        result = _vt_parse_stats(poll_data["data"]["attributes"]["stats"])
                        _VT_CACHE.set(cache_key, result, ttl=86400)
                        return result
            # If we get here, this key failed to complete – try next key
        except Exception as e:
            print(f"[VT] Error with key ...{key_obj.key[-4:]}: {e}")
            continue

    # All keys exhausted or all failed
    if not _vt_keys:
        print("[VT] All API keys have been exhausted or invalidated.")
    return _VT_ERR


# ======================================================================
# === TIER 2c: PHISHS.COM URL REPUTATION  (CONFIDENTIAL — not exposed to UI)
# ======================================================================
# Phishs.com is used as a silent backend signal.
# Its verdict is NEVER surfaced to the frontend or extension popup.
# When it overrides to Phishing, the reason shown to the user is:
#   "URL matches known phishing patterns and flagged by threat intelligence"
#
# Key rotation follows the same per-key sliding-window approach used in
# evaluate.py: each key gets at most PHISHS_RATE_LIMIT calls per
# PHISHS_RATE_WINDOW seconds.  Keys are round-robined; invalid keys are
# removed permanently; rate-limited keys are skipped for that call.
#
# Team IDs are fetched once at startup (one API call per credential pair).
#
# Credentials are read from .env:
#   PHISHS_CREDENTIALS=pub1:sec1,pub2:sec2,...

PHISHS_RATE_LIMIT  = 5    # calls per key per window
PHISHS_RATE_WINDOW = 70   # seconds (slightly above 60 for safety)
PHISHS_TIMEOUT     = 6    # seconds per HTTP call

class PhishsKey:
    """One Phishs.com credential pair with its own sliding-window rate limiter."""
    def __init__(self, public_key: str, secret_key: str):
        self.public_key = public_key
        self.secret_key = secret_key
        self.team_id    = None          # filled at startup
        self.call_times = deque()       # timestamps of recent successful slots
        self.lock       = threading.Lock()

    def wait_and_record(self, max_wait: float = 5.0) -> bool:
        """
        Block until a rate-limit slot is available, then record the call.

        PERF FIX: Was an infinite `while True` — same root cause as VTKey.
        wait_if_needed(). Returning False is safe: check_phishs moves to the
        next key or falls through to the cached-miss default.

        Returns True when a slot was obtained, False when max_wait expires.
        """
        deadline = time.time() + max_wait
        while True:
            with self.lock:
                now = time.time()
                while self.call_times and now - self.call_times[0] >= PHISHS_RATE_WINDOW:
                    self.call_times.popleft()
                if len(self.call_times) < PHISHS_RATE_LIMIT:
                    self.call_times.append(now)
                    return True
                if now >= deadline:
                    return False          # give up; caller handles gracefully
                wait = min(
                    PHISHS_RATE_WINDOW - (now - self.call_times[0]) + 0.1,
                    deadline - now
                )
            time.sleep(max(0.1, wait))

    def __repr__(self):
        return f"PhishsKey(public={self.public_key[:8]}...)"


# ── Key pool (populated at startup) ──────────────────────────────────────────
_phishs_keys: list = []
_phishs_key_counter = 0
_phishs_key_lock    = threading.Lock()


def _fetch_phishs_team_id(public_key: str, secret_key: str):
    """
    Fetch the first team ID for a Phishs.com credential pair.
    Returns (team_id, error_string).  Called once per key at startup.
    """
    try:
        r = requests.post(
            "https://api.phishs.com/v1/entity/team/list",
            json={},
            headers={
                "Content-Type": "application/json",
                "Public-Key":   public_key,
                "Secret-Key":   secret_key,
            },
            timeout=PHISHS_TIMEOUT,
        )
        if not r.ok:
            return None, f"HTTP {r.status_code}"
        teams = r.json().get("teams", [])
        if not teams:
            return None, "No teams in response"
        return teams[0]["id"], None
    except Exception as e:
        return None, str(e)


def _init_phishs_keys() -> None:
    """
    Parse PHISHS_CREDENTIALS from .env, fetch team IDs, and populate
    the global _phishs_keys pool.  Called once at module load time.

    .env format:
        PHISHS_CREDENTIALS=pub1:sec1,pub2:sec2,...
    """
    global _phishs_keys
    raw = os.environ.get("PHISHS_CREDENTIALS", "").strip()
    if not raw:
        print("[PHISHS] No credentials found in PHISHS_CREDENTIALS env var — Phishs.com disabled.")
        return

    pairs = []
    for part in raw.split(","):
        part = part.strip()
        if ":" in part:
            pub, sec = part.split(":", 1)
            pairs.append((pub.strip(), sec.strip()))

    if not pairs:
        print("[PHISHS] PHISHS_CREDENTIALS found but could not parse any pub:sec pairs.")
        return

    usable = []
    for pub, sec in pairs:
        team_id, err = _fetch_phishs_team_id(pub, sec)
        if team_id:
            key_obj         = PhishsKey(pub, sec)
            key_obj.team_id = team_id
            usable.append(key_obj)
            print(f"[PHISHS] Key {pub[:8]}... → team {team_id}  ✓")
        else:
            print(f"[PHISHS] Key {pub[:8]}... failed: {err}  ✗")

    _phishs_keys = usable
    if usable:
        print(f"[PHISHS] {len(usable)} usable key(s) loaded.")
    else:
        print("[PHISHS] No usable Phishs.com keys — Phishs.com layer disabled.")


# Initialise at module load (same moment the model and Tranco list load)
_init_phishs_keys()


def _get_next_phishs_key():
    """Round-robin selection across the live key pool."""
    if not _phishs_keys:
        return None
    with _phishs_key_lock:
        global _phishs_key_counter
        key = _phishs_keys[_phishs_key_counter % len(_phishs_keys)]
        _phishs_key_counter += 1
        return key


def check_phishs(url: str) -> dict:
    """
    Query Phishs.com for the given URL using round-robin key rotation and
    per-key sliding-window rate limiting (identical to evaluate.py logic).

    Returns:
        { "verdict": 1 | 0 | -1, "url_status": int | None }

        verdict  1  → Phishs says Phishing
        verdict  0  → Phishs says Legitimate
        verdict -1  → error / unknown / exhausted
        verdict -2  → Phishs disabled (no keys)

    Results are cached for 24 h (same TTL as VT and the result cache).
    rescan=False  →  re-use Phishs' own cached analysis for this URL.
    """
    _PHISHS_SKIP = {"verdict": -2, "url_status": None}
    _PHISHS_ERR  = {"verdict": -1, "url_status": None}

    if not _phishs_keys:
        return _PHISHS_SKIP

    # 24-h cache: avoid hitting the API for the same URL repeatedly
    cache_key = hashlib.sha256(url.encode()).hexdigest()
    cached = _PHISHS_CACHE.get(cache_key)
    if cached is not None:
        return cached

    # Try each key in round-robin order
    for _ in range(len(_phishs_keys) * 2):
        key_obj = _get_next_phishs_key()
        if not key_obj:
            break

        # Per-key rate limit — blocks if this key has hit its window cap
        key_obj.wait_and_record()

        try:
            resp = requests.post(
                "https://api.phishs.com/v1/scan/url",
                json={
                    "teamId": key_obj.team_id,
                    "url":    url,
                    "rescan": True,    # force fresh scan for accurate results
                },
                headers={
                    "Content-Type": "application/json",
                    "Public-Key":   key_obj.public_key,
                    "Secret-Key":   key_obj.secret_key,
                },
                timeout=PHISHS_TIMEOUT,
            )
        except requests.exceptions.Timeout:
            # Timeout = Phishs API is unreachable for this URL right now.
            # No point retrying other keys -- they hit the same endpoint.
            # Cache with very short TTL (5 min) so next scan retries fresh.
            print(f"[PHISHS] Timeout for {url!r} -- skipping remaining keys")
            _PHISHS_CACHE.set(cache_key, _PHISHS_ERR, ttl=300)  # 5 min TTL
            return _PHISHS_ERR
        except Exception as e:
            print(f"[PHISHS] Request error for {url!r}: {e}")
            continue

        if resp.status_code == 429:
            # This key is momentarily rate-limited — skip to the next one
            continue

        if resp.status_code in (401, 403):
            # Invalid / revoked key — remove permanently
            with _phishs_key_lock:
                if key_obj in _phishs_keys:
                    _phishs_keys.remove(key_obj)
                    print(f"[PHISHS] Removed invalid key {key_obj.public_key[:8]}...")
            continue

        if resp.status_code == 400:
            # 400 = URL rejected by Phishs API (malformed/unsupported).
            # Every key returns the same 400 for this URL - no point retrying.
            # Cache with short TTL (1h) so next scan retries fresh.
            print(f"[PHISHS] HTTP 400 (URL rejected) for {url!r} -- skipping all keys")
            _PHISHS_CACHE.set(cache_key, _PHISHS_ERR, ttl=3600)  # 1h TTL
            return _PHISHS_ERR

        if not resp.ok:
            print(f"[PHISHS] HTTP {resp.status_code} for {url!r}")
            continue

        try:
            data       = resp.json()
            url_status = data.get("urlStatus")
            if url_status is None:
                continue
            status_code = url_status.get("status")
            if status_code == 1:
                result = {"verdict": 1, "url_status": status_code}
                _PHISHS_CACHE.set(cache_key, result, ttl=86400)  # 24h for definitive
            elif status_code == 0:
                result = {"verdict": 0, "url_status": status_code}
                _PHISHS_CACHE.set(cache_key, result, ttl=86400)  # 24h for definitive
            else:
                # Unknown status -- cache briefly so we retry soon
                result = {"verdict": -1, "url_status": status_code}
                _PHISHS_CACHE.set(cache_key, result, ttl=300)    # 5 min only
            return result

        except Exception as e:
            print(f"[PHISHS] Parse error for {url!r}: {e}")
            continue

    if not _phishs_keys:
        print("[PHISHS] All API keys have been invalidated or exhausted.")
    return _PHISHS_ERR


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
    """
    Load known phishing hashes, url→hash map, AND insertion order from JSON.
    Returns: (hashes_set, url_to_hash_dict, ordered_hashes_list)

    Orphan policy: hashes with no URL mapping are silently dropped on load.
    This cleans up pre-existing "Unknown origin" entries automatically —
    they are absent from the in-memory set and removed from disk the next
    time _save_hash_db() is called.
    """
    if not os.path.exists(_HASH_DB_PATH):
        print("[HASH-DB] phishing_hashes.json not found — starting with empty database.")
        return set(), {}, []
    try:
        with open(_HASH_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        ordered_raw = data.get("hashes_ordered", data.get("hashes", []))
        url_map     = data.get("url_hash_map", {})

        # Build set of hashes that have a URL mapping (invert url_map values)
        mapped_hashes = set(url_map.values())

        # Keep only mapped hashes — drop orphans silently
        orphan_count = sum(1 for h in ordered_raw if h not in mapped_hashes)
        ordered      = [h for h in ordered_raw if h in mapped_hashes]
        hashes       = set(ordered)

        if orphan_count:
            print(f"[HASH-DB] Dropped {orphan_count} orphaned hash(es) with no URL mapping.")
        print(f"[HASH-DB] Loaded {len(hashes)} hashes, {len(url_map)} URL mappings from disk.")
        return hashes, url_map, list(ordered)
    except Exception as e:
        print(f"[HASH-DB] Failed to load hash database: {e} — starting empty.")
        return set(), {}, []

def _save_hash_db(hashes: set, url_map: dict, ordered: list) -> None:
    """
    Persist hashes, url→hash map, and insertion order to JSON (thread-safe).

    Orphan policy: only hashes that have a URL mapping are written to disk.
    Any hash without a corresponding entry in url_map is silently excluded,
    so "Unknown origin" entries can never accumulate in the JSON file.
    """
    try:
        with _HASH_DB_LOCK:
            # Build the set of hashes that are referenced by the url_map
            mapped_hashes = set(url_map.values())

            # Filter both the ordered list and the url_map to exclude orphans
            clean_ordered = [h for h in ordered  if h in mapped_hashes]
            clean_url_map = {url: h for url, h in url_map.items() if h in hashes}

            with open(_HASH_DB_PATH, "w", encoding="utf-8") as f:
                json.dump({
                    "hashes_ordered": clean_ordered,
                    "url_hash_map":   clean_url_map,
                }, f, indent=2)
    except Exception as e:
        print(f"[HASH-DB] Failed to save hash database: {e}")

# Load into memory at module import time
KNOWN_PHISHING_HASHES, _URL_TO_HASH, _HASH_INSERT_ORDER = _load_hash_db()

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
        print("[CLONE-CHECK] compute_screenshot_hash returned None — "
              "imagehash/Pillow missing or image decode failed.")
        return {"is_clone": False, "matched_hash": None, "current_hash": None}

    print(f"[CLONE-CHECK] current_hash={current_hash_str}  "
          f"db_size={len(KNOWN_PHISHING_HASHES)}  threshold={PHASH_SIMILARITY_THRESHOLD}")

    try:
        current_hash = imagehash.hex_to_hash(current_hash_str)
        if not KNOWN_PHISHING_HASHES:
            print("[CLONE-CHECK] KNOWN_PHISHING_HASHES is EMPTY — nothing to compare against.")
        best_dist = None
        best_hash = None
        for known_str in KNOWN_PHISHING_HASHES:
            try:
                known_hash = imagehash.hex_to_hash(known_str)
                dist = current_hash - known_hash
                if best_dist is None or dist < best_dist:
                    best_dist, best_hash = dist, known_str
                print(f"[CLONE-CHECK]   vs known={known_str}  distance={dist}")
                if dist <= PHASH_SIMILARITY_THRESHOLD:
                    print(f"[CLONE-CHECK] MATCH — distance {dist} <= threshold {PHASH_SIMILARITY_THRESHOLD}")
                    return {
                        "is_clone":     True,
                        "matched_hash": known_str,
                        "current_hash": current_hash_str,
                    }
            except Exception as e:
                print(f"[CLONE-CHECK]   compare error for known={known_str!r}: {e}")
                continue
        if best_dist is not None:
            print(f"[CLONE-CHECK] NO MATCH — closest distance was {best_dist} "
                  f"(needed <= {PHASH_SIMILARITY_THRESHOLD}) against {best_hash}")
    except Exception as e:
        print(f"[CLONE-CHECK] Visual clone check error: {e}")

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
                            lambda v: v == 0, _SEVERITY_LOW),
                            # Downgraded MEDIUM→LOW: even after improved fuzzy matching,
                            # many legitimate institutional sites use full organisation
                            # names in titles that bear no substring relation to the
                            # domain label.  High false-positive rate makes this
                            # unsuitable as a MEDIUM-weight reason.
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
    from collections import Counter, deque
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
        # PERF FIX: whois.whois() makes raw TCP connections with NO built-in
        # timeout. Slow or unresponsive WHOIS servers hang for 30–60 s, which
        # (combined with the executor shutdown(wait=True) bug) was a primary
        # source of the 45–80 s delays.
        #
        # Wrap the call in a daemon thread capped at 6 seconds.  socket.
        # setdefaulttimeout() is not thread-safe so we use a thread+join instead.
        # The daemon thread is lightweight; if it outlives the 6 s window it
        # continues quietly in the background and we simply discard its result.
        _res: list = [None]
        def _do_whois():
            try:
                _res[0] = whois.whois(domain)
            except Exception:
                pass
        _t = threading.Thread(target=_do_whois, daemon=True)
        _t.start()
        _t.join(timeout=6)          # hard 6-second cap
        rec = _res[0]               # None if timed out or exception
        _WHOIS_CACHE.set(domain, rec, ttl=86400)  # cache 24 hours (even None)
        return rec
    except Exception:
        _WHOIS_CACHE.set(domain, None, ttl=86400)
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


# ======================================================================
# === DOMAIN PARSING HELPERS (tldextract-based)
# ======================================================================
#
# _tld_extract_parts(hostname) → (subdomain, domain, suffix)
#
# Examples (naive split vs. tldextract):
#   mgmpu.mgmudupi.ac.in  naive → domain='ac',      subs=2  (WRONG)
#                         tld   → domain='mgmudupi', subs=1  (CORRECT)
#   www.google.co.uk      naive → domain='co',       subs=2  (WRONG)
#                         tld   → domain='google',   subs=1  (CORRECT)
#   evil.free.com         both  → domain='free',     subs=1  (same)
#
# Falls back to naive heuristic when tldextract is not installed.

def _tld_extract_parts(hostname: str) -> tuple[str, str, str]:
    """
    Return (subdomain, domain, suffix) for the given hostname using
    tldextract when available, or a best-effort naive fallback.

    All three parts are lowercase strings; any may be empty.
    """
    if not hostname:
        return '', '', ''
    hostname = hostname.lower()
    if _TLDEXTRACT_AVAILABLE:
        try:
            ext = _tldextract.extract(hostname)
            return ext.subdomain, ext.domain, ext.suffix
        except Exception:
            pass
    # ── Naive fallback (used only if tldextract is missing) ──────────
    # Known multi-label ccTLD second-levels so the most common cases
    # are at least partially correct even without the library.
    _KNOWN_SLD = {
        'ac','co','com','edu','gov','net','org','mil','nic','res',
    }
    parts = hostname.split('.')
    if len(parts) >= 3 and parts[-2].lower() in _KNOWN_SLD:
        # e.g. ['mgmpu','mgmudupi','ac','in'] → suffix='ac.in', domain='mgmudupi'
        suffix    = '.'.join(parts[-2:])
        domain    = parts[-3]
        subdomain = '.'.join(parts[:-3])
    elif len(parts) >= 2:
        suffix    = parts[-1]
        domain    = parts[-2]
        subdomain = '.'.join(parts[:-2])
    else:
        suffix    = ''
        domain    = hostname
        subdomain = ''
    return subdomain, domain, suffix


# ======================================================================
# === TIER 1.5: INSTITUTIONAL DOMAIN CONFIDENCE DAMPENER
# ======================================================================
#
# Institutional registries (academic, government, military) require verified
# organisational identity — they are almost never used for throwaway phishing.
# Yet small institutional sites (.ac.in colleges, govt portals, school sites)
# are frequently absent from popularity lists (Tranco / Majestic) AND have
# many benign features that the ML model was not well-trained on (no favicon
# in markup, title mismatch due to naive domain parsing, etc.).
#
# This tier does NOT bypass scanning — it acts as a confidence dampener:
#   • ML confidence is reduced by INSTITUTIONAL_CONFIDENCE_PENALTY (default 0.20)
#   • The effective threshold to trigger a Phishing verdict is raised by
#     INSTITUTIONAL_THRESHOLD_RAISE (default 0.08)
#
# Combined effect: a confidence of 0.99 on an institutional site becomes
# 0.79, checked against an effective threshold of 0.83 → falls through to
# Rule 7 (below threshold) → returned as Legitimate unless VT/GSB/feed also
# disagree.  A genuinely high-confidence phishing result (say 0.97 after
# penalty = 0.77, threshold 0.83) also falls through.  Only truly extreme
# scores (>= 1.03 before capping, i.e. impossible) would still fire — in
# practice, the dampener effectively requires both ML AND an external signal
# to confirm a Phishing verdict for institutional domains.

INSTITUTIONAL_CONFIDENCE_PENALTY = 0.20   # subtract from raw ML confidence
INSTITUTIONAL_THRESHOLD_RAISE    = 0.08   # add to CONFIDENCE_THRESHOLD

# Suffix patterns that indicate institutional/government/academic registrations.
# Multi-label ccTLD suffixes use the full suffix string as returned by tldextract.
_INSTITUTIONAL_SUFFIXES: set[str] = {
    # Generic institutional TLDs (global)
    'edu', 'gov', 'mil', 'ac',
    # India
    'ac.in', 'edu.in', 'gov.in', 'mil.in', 'res.in', 'nic.in',
    # UK
    'ac.uk', 'gov.uk', 'mod.uk', 'nhs.uk', 'police.uk', 'sch.uk',
    # Australia
    'edu.au', 'gov.au', 'csiro.au', 'act.edu.au', 'nsw.edu.au',
    # New Zealand
    'ac.nz', 'govt.nz', 'school.nz',
    # Other common ones
    'edu.sg', 'gov.sg',
    'ac.za', 'gov.za',
    'edu.my', 'gov.my',
    'edu.pk', 'gov.pk', 'ac.pk',
    'edu.bd', 'gov.bd', 'ac.bd',
    'edu.lk', 'gov.lk', 'ac.lk',
    'ac.jp', 'go.jp',
    'edu.cn', 'gov.cn',
    'edu.br', 'gov.br',
    'edu.ar', 'gob.ar',
    'edu.mx', 'gob.mx',
    'ac.kr', 'go.kr',
}


def _is_institutional_domain(url: str) -> bool:
    """
    Return True if the URL's hostname uses an institutional/government/
    academic TLD suffix (as defined in _INSTITUTIONAL_SUFFIXES).

    Uses tldextract for correct multi-label ccTLD handling.
    """
    try:
        hostname = (urlparse(url).hostname or '').lower()
        if not hostname:
            return False
        _, _, suffix = _tld_extract_parts(hostname)
        return suffix.lower() in _INSTITUTIONAL_SUFFIXES
    except Exception:
        return False


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

    # ── tldextract-aware domain parsing ──────────────────────────────────
    # Replaces the old naive host.split('.') approach that broke for any
    # multi-label ccTLD (e.g. .ac.in, .co.uk, .gov.au).
    #
    # Old (WRONG) for  mgmpu.mgmudupi.ac.in :
    #   host_parts = ['mgmpu','mgmudupi','ac','in']
    #   subs = ['mgmpu','mgmudupi']  → num_subdomains=2 (should be 1)
    #   _domain_str() = 'ac.in'      → domain='ac' (should be 'mgmudupi')
    #
    # New (CORRECT):
    #   subdomain='mgmpu', domain='mgmudupi', suffix='ac.in'
    #   num_subdomains=1, domain_length=len('mgmudupi.ac.in')=14
    _url_sub, _url_dom, _url_sfx = _tld_extract_parts(host)
    subs = [s for s in _url_sub.split('.') if s]   # list of subdomain labels

    _safe_set("num_subdomains",    lambda: len(subs))
    _safe_set("longest_subdomain", lambda: max((len(s) for s in subs), default=0))
    _safe_set("tld_length",        lambda: len(_url_sfx))

    def _domain_str():
        # Registrable domain = domain label + suffix  (e.g. 'mgmudupi.ac.in')
        if _url_dom and _url_sfx:
            return f"{_url_dom}.{_url_sfx}"
        return _url_dom or host

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

    # PERF: Call _ip_flags() once and unpack — previously called twice (once per feature)
    try:
        _ip_has, _ip_valid = _ip_flags()
    except Exception:
        _ip_has, _ip_valid = 0, 0
    feats["has_ip"]   = _ip_has
    feats["valid_ip"] = _ip_valid
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
        # Correct registrable-domain label (e.g. 'mgmudupi' not 'ac')
        return _url_dom or (_domain_str().split('.')[0] if _domain_str() else '')

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
    # Use tldextract suffix for TLD check — correct for multi-label ccTLDs
    _safe_set("suspicious_tld",    lambda: 1 if _url_sfx.split('.')[-1].lower() in suspicious_tlds else 0)
    _safe_set("repeated_subdomain",lambda: 1 if len(subs) != len(set(subs)) and len(subs) > 0 else 0)

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

    # PERF: Compute ext_links ONCE. Previously called 3× via lambdas
    # (external_links, external_ratio, internal_links), each doing a full
    # list comprehension over all <a> tags.
    try:
        _ext_links_cached = [a for a in links if domain and domain not in a["href"]]
    except Exception:
        _ext_links_cached = []

    _safe_set("external_links", lambda: len(_ext_links_cached))
    _safe_set("external_ratio", lambda: len(_ext_links_cached)/len(links) if links else 0)
    _safe_set("mailto_count",   lambda: len([a for a in links if a["href"].lower().startswith("mailto:")]))
    _safe_set("js_links",       lambda: len([a for a in links if a["href"].lower().startswith("javascript:")]))
    _safe_set("internal_links", lambda: len(links)-len(_ext_links_cached))

    _safe_set("num_images",      lambda: len(images))
    _safe_set("external_images", lambda: len([img for img in images if domain and domain not in img["src"]]))

    # PERF: Compute favicon link tags ONCE. Previously called 2× via _fav()
    # (inside _has_favicon_fn and external_favicon), each triggering a fresh
    # soup.find_all() traversal of the entire DOM.
    try:
        _fav_cached = soup.find_all("link", rel=lambda x: x and "icon" in x.lower()) if soup else []
    except Exception:
        _fav_cached = []

    def _has_favicon_fn():
        # 1. Explicit <link rel="icon"> or <link rel="shortcut icon"> in markup
        if _fav_cached:
            return 1
        # 2. Browsers automatically request /favicon.ico even without a <link> tag.
        #    Many legitimate (especially older/simpler) sites rely solely on this
        #    implicit fallback and have NO favicon declaration in their HTML —
        #    this was incorrectly flagging them as suspicious.
        try:
            parsed = urlparse(url)
            fav_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
            # PERF: Reduced timeout 3s → 1.5s. Saves ~1.5s when favicon.ico
            # is absent or slow to respond. Feature logic is unchanged.
            r = requests.head(fav_url, timeout=1.5, verify=False,
                              headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code in (200, 301, 302):
                return 1
        except Exception:
            pass
        return 0

    _safe_set("has_favicon",      _has_favicon_fn)
    _safe_set("external_favicon", lambda: 1 if any(domain and domain not in f.get("href","") for f in _fav_cached) else 0)
    _safe_set("external_scripts", lambda: len([s for s in scripts if s.get("src") and domain and domain not in s["src"]]))

    # PERF: Compute title string ONCE. Previously _title() was called 3×
    # (title_length, title_domain_match, title_is_generic), each accessing soup.
    try:
        _title_cached = soup.title.string.strip() if soup and soup.title and soup.title.string else ""
    except Exception:
        _title_cached = ""

    def _domain_core():
        # Use tldextract to get the correct registrable-domain label.
        # Old: parts = domain.split('.'); return parts[-2]
        #   → for 'mgmpu.mgmudupi.ac.in' returns 'ac'  (WRONG)
        # New: tldextract → returns 'mgmudupi'           (CORRECT)
        hostname = domain.lower()
        _, dom_label, _ = _tld_extract_parts(hostname)
        return dom_label or (domain.split('.')[-2] if domain.count('.') >= 1 else domain)

    def _title_matches_domain():
        """
        Improved title→domain matching.

        Old logic: strict substring  ('mgmudupi' in 'Mahatma Gandhi Memorial College')
          → always 0 for institutional sites whose title is their full name, not their
            domain abbreviation.

        New logic (any of these counts as a match):
          1. Domain label is a substring of the title (original check, now on correct label)
          2. Title contains any token from the domain label of length >= 4
             (catches 'mgm' fragments, abbreviations like 'mgmudupi' split as words)
          3. Domain label starts with or is an acronym of the title words
             (e.g. 'mgm' ≈ first-letters of 'Mahatma Gandhi Memorial')
          4. Title is entirely empty → treat as 'no match' (0) regardless
        """
        title = _title_cached.lower()   # uses pre-computed cache
        if not title:
            return 0
        core  = _domain_core().lower()
        if not core:
            return 0
        # Check 1: simple substring
        if core in title:
            return 1
        # Check 2: any 4+-char token within core appears in title
        core_tokens = re.findall(r'[a-z]{4,}', core)
        title_tokens = set(re.findall(r'[a-z]+', title))
        if core_tokens and any(t in title_tokens for t in core_tokens):
            return 1
        # Check 3: core looks like an acronym of the title words
        # (e.g. core='mgm', title_words=['mahatma','gandhi','memorial','...'])
        title_words = re.findall(r'[a-z]+', title)
        if len(core) >= 2 and len(title_words) >= len(core):
            initials = ''.join(w[0] for w in title_words)
            if core in initials:
                return 1
        return 0

    _safe_set("title_length",       lambda: len(_title_cached))
    _safe_set("title_domain_match", _title_matches_domain)
    _safe_set("title_is_generic",   lambda: 1 if any(w in _title_cached.lower() for w in ['home','index','welcome','login','sign in']) else 0)

    # PERF: Compute page text and word list ONCE each.
    # _text() was called 2× (suspicious_keywords, text_entropy) — each triggers
    # soup.get_text() which walks the entire DOM tree.
    # _words() was called 2× (word_count, avg_word_len) — each re-runs _text()
    # AND re.split on the full text.
    try:
        _text_cached  = soup.get_text(separator=" ").strip() if soup else ""
    except Exception:
        _text_cached  = ""
    try:
        _words_cached = [w for w in re.split(r'\s+', _text_cached) if w]
    except Exception:
        _words_cached = []

    _safe_set("word_count",   lambda: len(_words_cached))
    _safe_set("avg_word_len", lambda: sum(len(w) for w in _words_cached)/len(_words_cached) if _words_cached else 0)

    kw = ['login','verify','password','bank','update','account','secure','confirm','click']
    _safe_set("suspicious_keywords", lambda: sum(_text_cached.lower().count(k) for k in kw))
    _safe_set("text_entropy",        lambda: _entropy(_text_cached))

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

def _apply_visual_clone_if_known(url: str, result: dict) -> dict:
    """
    If the URL path matches any entry in the pHash DB (_URL_TO_HASH), upgrade
    the result to visual_clone regardless of what ML / feeds decided.

    This is the DEFINITIVE visual-clone check.  It runs inside /predict so it
    fires whether the result is fresh or served from the cache — and it works
    even when /screenshot is unavailable or the pHash comparison fails due to
    screenshot-quality differences between visits.

    The check is path-based (_cache_key = scheme+host+path, no query params)
    so it matches the same page even when ad-tracking query strings change
    between visits.
    """
    req_cache_key = _cache_key(url)
    for stored_url_key in list(_URL_TO_HASH):
        if _cache_key(stored_url_key) == req_cache_key:
            result = dict(result)                              # copy — never mutate in-place
            result["status"]     = "visual_clone"
            result["prediction"] = "Phishing"
            result["confidence"] = max(result.get("confidence") or 0.0, 0.99)
            result["message"]    = "Page design matches a known phishing template"
            clone_reason = {
                "label":    "Page visually clones a known phishing site",
                "severity": "high",
                "feature":  "visual_clone",
                "value":    1,
            }
            existing = result.get("reasons") or []
            if not any(r.get("feature") == "visual_clone" for r in existing):
                result["reasons"] = [clone_reason, *existing]
            break
    return result


@app.post("/predict")
async def predict_url(request: URLRequest):
    if model is None:
        raise HTTPException(status_code=500, detail="Model not loaded on server")

    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Empty URL")

    # FIX: Reject browser-internal URLs immediately
    if not is_scannable_url(url):
        # "skipped" = non-HTTP URL submitted to the web app (chrome://, about:, etc.)
        # The extension never reaches this path (background.js guards isScannable).
        # BUGFIX: this is never a phishing detection — it's just "nothing to
        # scan here" — so only log it when the user manually asked to scan.
        if request.manual:
            _log_scan(url, "Legitimate", 1.0, "skipped")
        return {
            "status": "skipped",
            "message": "This page type is not scannable",
            "prediction": "Legitimate",
            "confidence": 1.0,
        }

    # ── Tier 0: full result cache ─────────────────────────────────────────────
    # Keyed by scheme+host+path only (_cache_key) — no query params.
    # This ensures any second visit to the same page hits the cache even if
    # Bing/Google Ads append different tracking params each time.
    # known-URL lookup (Tier 2) still uses _normalise_for_lookup separately.
    result_cache_key = _cache_key(url)
    cached_result = _RESULT_CACHE.get(result_cache_key)
    if cached_result is not None:
        print(f"[CACHE] Hit for {url!r}")
        # NOTE: deliberately NOT calling _apply_visual_clone_if_known() here.
        #
        # Why: a hash can be added to _URL_TO_HASH *after* this URL's result
        # was already cached in the same server session (e.g. the auto-scan
        # that just ran fires off a fire-and-forget /hash/add call once it
        # sees prediction == 'Phishing'). If every cache hit re-checked
        # _URL_TO_HASH, a plain repeat visit within the same session would
        # flip from "cached" to "visual_clone" a few seconds after the first
        # scan — even though nothing about the detection method changed.
        #
        # The intended behaviour: visual-clone detection is the DEFINITIVE
        # check for a genuinely FRESH scan (empty cache — e.g. right after a
        # server restart) where the hash DB persisted across the restart but
        # the in-memory result cache did not. Within a live session, once a
        # result is cached, repeat visits should just serve that cached
        # verdict and log "cached" — matching original behaviour.
        #
        # Log status for cache hits:
        #   "user_reported" → preserve it (user explicitly corrected this URL)
        #   everything else → log as "cached" (this visit was served from cache,
        #                     regardless of how it was originally obtained)
        cached_status = cached_result.get("status", "")
        PRESERVE_STATUSES = {"user_reported", "known", "feed_match", "trusted"}
        log_status = cached_status if cached_status in PRESERVE_STATUSES else "cached"

        # BUGFIX: a repeat auto-scan hitting a cached "known"-Legitimate
        # result is the same noise as a fresh known-safe hit (Patch A) —
        # suppress it unless manual. Every other cached status (including
        # "known"-Phishing) still logs unconditionally, same as before.
        is_noise_verdict = (log_status == "known"
                             and cached_result.get("prediction") == "Legitimate")
        if request.manual or not is_noise_verdict:
            _log_scan(url,
                      cached_result.get("prediction", "Unknown"),
                      cached_result.get("confidence", 0),
                      log_status)
        
        # FIX: the returned JSON's own "status" must match what we just logged.
        # Previously `return cached_result` sent back the *original* status
        # ("predicted", "visual_clone", "feed_match", ...) forever, never the
        # literal string "cached" — even though the scan-history log correctly
        # said "cached". popup.js / background.js both gate the visual-clone
        # re-application on `data.status !== 'cached'`, so that guard never
        # actually matched on a repeat scan, and every rescan within the same
        # session re-triggered "Visual Clone" even though nothing new happened.
        result_to_return = dict(cached_result)
        result_to_return["status"] = log_status
        return result_to_return

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
        trusted_result = {
            "status":       "trusted",
            "message":      source_label,
            "prediction":   "Legitimate",
            "confidence":   1.0,
            "reasons":      [],
            "trust_source": trust_source,
        }
        # Do NOT cache trusted results — every visit should log "trusted" directly.
        # The whitelist check is O(1) set lookup, so skipping cache costs nothing.
        #
        # BUGFIX: only log this to Scan History / Total Scans when the user
        # explicitly triggered a manual scan. Auto-scan fires on every page
        # load and every refresh — for trusted sites that meant Total Scans
        # and Scan History grew on every navigation/refresh, even though
        # nothing noteworthy happened. Phishing/Uncertain verdicts from
        # auto-scan are NOT affected by this — they still log normally,
        # since those are the results the user actually needs to see.
        if request.manual:
            _log_scan(url, "Legitimate", 1.0, "trusted")
        return trusted_result

    url_lower  = url.lower()
    url_normed = _normalise_for_lookup(url)   # strips tracking params, fragment, trailing slash

    # Fast path: already seen in training CSV
    # Use normalised URL so browser-added UTM params don't break the match.
    if url_normed in known_urls:
        row = known_urls_df[known_urls_df["url_norm"] == url_normed].iloc[0]
        pred = int(row["label"])
        result = "Phishing" if pred == 1 else "Legitimate"
        message = (
            "This is a known phishing site"
            if result == "Phishing"
            else "This site is verified safe"
        )
        known_result = {
            "status":     "known",
            "message":    message,
            "prediction": result,
            "confidence": 1.0,
            "reasons":    [],
            "gsb_checked": "skipped_known",
            "vt":          {"checked": False, "source": "skipped_known",
                            "malicious": 0, "suspicious": 0, "total": 0,
                            "trust_score": -1, "verdict": "unknown"},
            "features":   {},
        }
        # Cache the known result — repeat visits return instantly AND still
        # show status="known" in scan history (not "cached").
        _RESULT_CACHE.set(result_cache_key, known_result, ttl=86400)
        # BUGFIX: same rule as the Tier 1 trusted-domain check above — a
        # known-SAFE site shouldn't spam Total Scans/Scan History on every
        # auto-scan (page load/refresh). A known-PHISHING site must always
        # log, auto-scan or not, since that's a real detection the user
        # needs to see.
        if request.manual or result == "Phishing":
            _log_scan(url, result, 1.0, "known")
        return known_result

    # ── Parallel extraction — hard 10-second wall-clock cap ───────────────────
    #
    #   Thread 1 — CPU URL features      ~10ms   pure computation
    #   Thread 2 — WHOIS lookup          1–6s    network (now capped at 6 s)
    #   Thread 3 — Content fetch/parse   1–5s    network
    #   Thread 4 — Google Safe Browsing  0.5–2s  network (independent API)
    #   Thread 5 — VirusTotal            0.5–5s  network (multi-key rotation)
    #   Thread 6 — Phishs.com            0.5–3s  network (silent intel layer)
    #
    # WHY THE OLD CODE WAS TAKING 45–80 SECONDS:
    #
    #   `with concurrent.futures.ThreadPoolExecutor(…) as executor:` calls
    #   executor.__exit__() → shutdown(wait=True) when the block exits.
    #   shutdown(wait=True) BLOCKS until EVERY submitted thread finishes —
    #   even threads we already gave up on via .result(timeout=N).
    #
    #   The per-future timeouts (.result(timeout=3), .result(timeout=8), etc.)
    #   only limit how long the MAIN THREAD waits for each result.  They do NOT
    #   stop the background thread.  So after we timed out on future_whois at 3 s,
    #   the WHOIS thread kept running whois.whois() for another 30–57 s — and the
    #   with-block exit sat there waiting for it.  Same for VT's wait_if_needed()
    #   (which was an infinite loop that could sleep 60 s) and Phishs.
    #
    # THE FIX:
    #   1. Use concurrent.futures.wait(timeout=10) for a single hard wall-clock
    #      deadline across ALL tasks simultaneously.
    #   2. Call shutdown(wait=False) immediately after — this releases the
    #      executor without blocking.  Threads that didn't finish in 10 s keep
    #      running in the background, update their caches when done, and will
    #      make the NEXT request to the same URL faster.
    #   3. Collect results with _collect(): non-blocking for done futures,
    #      returns the safe default for anything that timed out.
    #
    _scan_exec = concurrent.futures.ThreadPoolExecutor(max_workers=6)
    future_url     = _scan_exec.submit(extract_url_features, url)
    future_whois   = _scan_exec.submit(_fetch_whois_features, url)
    future_content = _scan_exec.submit(extract_content_features, url)
    future_gsb     = _scan_exec.submit(check_google_safe_browsing, url)
    future_vt      = _scan_exec.submit(check_virustotal, url)
    future_phishs  = _scan_exec.submit(check_phishs, url)

    _done, _ = concurrent.futures.wait(
        [future_url, future_whois, future_content, future_gsb, future_vt, future_phishs],
        timeout=10          # hard 10-second cap for ALL tasks combined
    )
    _scan_exec.shutdown(wait=False)   # release immediately — don't block on stragglers

    def _collect(fut, default):
        """Return the future's result if it finished; default otherwise. Never blocks."""
        if fut in _done:
            try:
                return fut.result()
            except Exception:
                pass
        return default

    url_feats = _collect(future_url, {k: 0 for k in URL_FEATURE_KEYS})

    try:
        age, expiry, privacy = _collect(future_whois, (-1, -1, -1))
    except Exception:
        age, expiry, privacy = -1, -1, -1

    url_feats["domain_age_days"] = age
    url_feats["days_to_expiry"]  = expiry
    url_feats["whois_privacy"]   = privacy

    content_feats = _collect(future_content, {k: 0 for k in CONTENT_FEATURE_KEYS})

    gsb_result = _collect(
        future_gsb,
        {"is_unsafe": False, "threat_type": None, "source": "gsb_error"}
    )

    vt_result = _collect(
        future_vt,
        {"checked": False, "source": "vt_timeout",
         "malicious": 0, "suspicious": 0, "total": 0,
         "trust_score": -1, "verdict": "unknown"}
    )

    phishs_result = _collect(future_phishs, {"verdict": -1, "url_status": None})

    all_features   = {**url_feats, **content_feats}
    feature_order  = list(URL_FEATURE_KEYS) + list(CONTENT_FEATURE_KEYS)
    features_df    = pd.DataFrame([[all_features[k] for k in feature_order]], columns=feature_order)

    pred       = int(model.predict(features_df)[0])
    proba      = model.predict_proba(features_df)[0]
    confidence = float(max(proba))
    ml_result  = "Phishing" if pred == 1 else "Legitimate"
    reasons    = get_top_reasons(all_features, ml_result)

    # ══════════════════════════════════════════════════════════════════
    # TIER 1.5: INSTITUTIONAL DOMAIN CONFIDENCE DAMPENER
    # ══════════════════════════════════════════════════════════════════
    #
    # Institutional TLD registrations (academic, government, military) require
    # verified organisational identity — they are almost never used for throwaway
    # phishing.  Yet small college/government portals frequently lack features the
    # ML model weighs heavily (favicon in markup, title verbatim matching domain),
    # causing inflated confidence scores.
    #
    # This tier does NOT bypass scanning. It only dampens confidence so that
    # genuine external signals (VT, GSB, Phishs) can still escalate to Phishing.
    #
    # Applied only when ML says "Phishing" — if ML already says Legitimate,
    # no dampening is needed (we don't want to suppress correct Legitimate verdicts).
    #
    # Effective thresholds after dampening (defaults):
    #   raw confidence 0.99  → 0.79  vs. effective threshold 0.83 → falls below → Legitimate
    #   raw confidence 0.85  → 0.65  vs. effective threshold 0.83 → falls below → Legitimate
    #   raw confidence 0.98  → 0.78  vs. effective threshold 0.83 → falls below → Legitimate
    #   (external signals like VT/GSB/Phishs can still override to Phishing)
    _is_institutional = _is_institutional_domain(url)
    if _is_institutional and ml_result == "Phishing":
        dampened_confidence = confidence - INSTITUTIONAL_CONFIDENCE_PENALTY
        print(f"[TIER1.5] Institutional domain detected for {url!r}. "
              f"ML confidence dampened: {confidence:.3f} → {dampened_confidence:.3f}")
        confidence = dampened_confidence

    # Safe defaults so result/message are always defined.
    # Every branch in the engine overwrites these; defaults prevent NameError
    # if an unexpected path is ever reached.
    result  = ml_result
    message = (
        "No threats detected on this page"
        if ml_result == "Legitimate"
        else "This site shows multiple signs of a phishing attack"
    )

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
    #   Rule 0: Phishs.com says Phishing                → Phishing   (overrides all, reason is hidden)
    #   Rule 0: Phishs.com says Legitimate              → Reduces ML confidence by 15pp
    #   Rule 1: GSB flagged                             → Phishing
    #   Rule 2: VT ≥ 8 malicious vendors               → Phishing
    #   Rule 3: VT suspicious (3-7) + ML missed it     → Uncertain
    #   Rule 4: ML ≥ 85% + VT trust ≥ 85              → Uncertain  (ML says bad, VT clears = conflict)
    #   Rule 5: ML ≥ 85% + VT trust < 65              → Phishing   (both agree it's risky)
    #   Rule 6: ML ≥ 85% + VT unchecked/middle         → Phishing   (trust ML alone)
    #   Rule 6b: ML ≥ 75% and < 85%                    → Uncertain (ML not confident enough for a hard verdict)
    #   Rule 7: ML < 75%                               → Legitimate (not confident enough)
    #   Rule 8: ML = Legitimate                        → Legitimate

    # ── PhishTank / OpenPhish feed check (runs BEFORE decision engine) ──
    # PhishTank URLs are human-verified. If matched:
    #   - If ML also says Phishing -> override to Phishing (both agree)
    #   - If ML says Legitimate    -> upgrade to Uncertain (human feed vs ML conflict)
    # Running before the engine lets it influence Rule 7/8 outcomes.
    _feed_matched = False
    _feed_reason  = None
    if _PHISHING_URLS:
        _norm_url = _normalise_url(url)
        if _norm_url in _PHISHING_URLS:
            _feed_matched = True
            _feed_reason  = {
                "label":    "URL found in PhishTank / OpenPhish verified phishing database",
                "severity": "high",
                "feature":  "phishing_feed",
                "value":    1,
            }
            reasons = [_feed_reason] + [r for r in reasons if r.get("feature") != "phishing_feed"]
            if ml_result == "Phishing":
                # Both ML and feed agree -> definite Phishing
                result     = "Phishing"
                confidence = max(confidence, 0.95)
                message    = "This site shows multiple signs of a phishing attack"
                _phishs_fired = True  # guard: skip Rules 1-8 (already decided)
                print(f"[FEED] {url!r} matched feed + ML Phishing -> Phishing override")
            else:
                # ML says Legitimate but human feed disagrees -> Uncertain
                result     = "Uncertain"
                confidence = max(confidence, 0.75)
                message    = ("This URL was reported in a verified phishing database. "
                              "Our model considers it safe \xe2\x80\x94 proceed with caution.")
                _phishs_fired = True  # guard: skip Rules 1-8 (already decided)
                print(f"[FEED] {url!r} matched feed but ML says Legit -> Uncertain")

    CONFIDENCE_THRESHOLD      = 0.75   # ML must be at least this confident to trigger an alert at all (Rule 7 gate)
    HIGH_CONFIDENCE_THRESHOLD = 0.85   # ML must reach this for Rules 4/5/6 (VT cross-checks) to run
    VT_CLEAR_THRESHOLD   = 85     # VT trust ≥ this → reputation considered clean
    VT_DANGER_THRESHOLD  = 65     # VT trust < this → reputation considered risky

    # For institutional domains the threshold is raised further so that only
    # very high (post-dampening) confidence still fires as Phishing.
    # Combined with the penalty above, this makes a genuine alarm require
    # either very high ML confidence OR corroboration from an external signal.
    if _is_institutional:
        CONFIDENCE_THRESHOLD = CONFIDENCE_THRESHOLD + INSTITUTIONAL_THRESHOLD_RAISE
        print(f"[TIER1.5] Effective CONFIDENCE_THRESHOLD raised to {CONFIDENCE_THRESHOLD:.2f} "
              f"for institutional domain {url!r}")

    vt_trust   = vt_result.get("trust_score", -1)
    vt_verdict = vt_result.get("verdict", "unknown")
    vt_mal     = vt_result.get("malicious", 0)
    vt_sus     = vt_result.get("suspicious", 0)
    vt_total   = vt_result.get("total", 0)
    vt_checked = vt_result.get("checked", False)

    # ── Phishs.com silent override (Rule 0) ──────────────
    # Phishs verdict is applied BEFORE all other rules.
    # It is NEVER mentioned in reasons shown to the user (kept confidential).
    # verdict=1  -> override to Phishing (reason hidden behind generic label)
    # verdict=0  -> reduce suspicion (lower confidence by 15pp, floor 0.50)
    phishs_verdict = phishs_result.get("verdict", -1)
    _phishs_fired  = False   # flag: True when Phishs overrides to Phishing

    if phishs_verdict == 1:
        # Phishs says Phishing -> override immediately, no other rules needed
        result     = "Phishing"
        confidence = max(confidence, 0.96)
        message    = "This site shows multiple signs of a phishing attack"
        # Generic reason label: reveals nothing about the source
        phishs_reason = {
            "label":    "URL matches known phishing patterns and flagged by threat intelligence",
            "severity": "high",
            "feature":  "threat_intel",
            "value":    1,
        }
        reasons       = [phishs_reason] + reasons
        _phishs_fired = True
        print(f"[PHISHS] Override -> Phishing for {url!r}")

    elif phishs_verdict == 0:
        # Phishs says Legitimate -> reduce ML suspicion
        # Only meaningful when ML is ABOVE threshold and would have fired.
        # Below threshold it is already heading to Legitimate anyway.
        if ml_result == "Phishing" and confidence >= CONFIDENCE_THRESHOLD:
            confidence = max(CONFIDENCE_THRESHOLD - 0.01, confidence - 0.15)
            print(f"[PHISHS] Legit signal -> ML confidence reduced to {confidence:.2f} for {url!r}")

    # ── Rule 1: GSB definitive blacklist ──────────────────────────────
    # ── Rules 1-8: only run if Phishs has NOT already fired ──────────
    # Wrapping all rules in "if not _phishs_fired" ensures the Phishs verdict
    # can never be overwritten by GSB/VT/ML rules below.
    if not _phishs_fired:

        # ── Rule 1: GSB definitive blacklist ──────────────
        if gsb_result.get("is_unsafe"):
            threat     = gsb_result.get("threat_type", "UNKNOWN")
            result     = "Phishing"
            confidence = max(confidence, 0.97)
            message    = f"Confirmed threat by Google Safe Browsing ({threat.replace('_', ' ').title()})"
            reasons    = [
                {"label": f"Flagged by Google Safe Browsing as {threat.replace('_', ' ').title()}",
                 "severity": "high", "feature": "gsb", "value": 1}
            ] + reasons

        # ── Rule 2: VirusTotal multi-vendor consensus ──────
        # Fires regardless of what ML thinks — 8+ security vendors is strong evidence.
        elif vt_verdict == "malicious":
            result     = "Phishing"
            confidence = max(confidence, 0.95)
            message    = f"Flagged as malicious by {vt_mal} of {vt_total} security vendors"
            reasons    = [
                {"label": f"Detected as malicious by {vt_mal}/{vt_total} security vendors (VirusTotal)",
                 "severity": "high", "feature": "virustotal", "value": vt_mal}
            ] + reasons

        # ── Rule 3: VT suspicious + ML missed it → Uncertain ────
        # If 3-7 vendors flag it suspicious but ML says fine,
        # show a warning rather than a silent green light.
        elif vt_verdict == "suspicious" and vt_checked and ml_result == "Legitimate":
            result  = "Uncertain"
            message = (f"{vt_mal + vt_sus} security vendors flagged this site as suspicious. "
                       f"Our model considers it legitimate — proceed with caution.")
            reasons = [
                {"label": f"Flagged as suspicious by {vt_mal+vt_sus} of {vt_total} security vendors",
                 "severity": "medium", "feature": "virustotal", "value": vt_mal + vt_sus}
            ]

        # ── Rules 4-8: ML-based decisions ────────────────
        elif ml_result == "Phishing":
            if confidence >= HIGH_CONFIDENCE_THRESHOLD:

                # Rule 4: ML confident + VT clears the site → genuine conflict → Uncertain
                # When ML is >=85% sure it is phishing AND VT trust is high,
                # that is a real conflict. Show Uncertain so the user can decide.
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

            elif confidence >= CONFIDENCE_THRESHOLD:
                # Rule 6b: ML flagged Phishing but confidence is in the 75-85% band.
                # Not low enough to dismiss (Rule 7), but not high enough to run the
                # VT cross-checks (Rules 4/5/6) or issue a hard Phishing verdict.
                # `reasons` already holds the ML feature-based signals from
                # get_top_reasons(), so the user still sees concrete explanations.
                result  = "Uncertain"
                message = (f"Our model flagged this site but is not highly confident "
                           f"({round(confidence*100)}% confidence). Proceed with caution.")
                print(f"[DECISION] Rule 6b: ML Phishing at {confidence:.2f} "
                      f"(75-85% band) → Uncertain for {url!r}")

            else:
                # Rule 7: ML confidence below threshold
                # Sub-rule 7a: VT also suspicious -> both signals agree -> Uncertain
                # Sub-rule 7b: VT clean or unchecked -> not enough evidence -> Legitimate
                if vt_verdict in ("suspicious", "malicious") and vt_checked:
                    result  = "Uncertain"
                    message = (f"Multiple signals suggest this site may be unsafe "
                               f"({vt_mal+vt_sus} security vendors flagged it, model at "
                               f"{round(confidence*100)}% confidence). Proceed with caution.")
                    if not any(r.get("feature") == "virustotal" for r in reasons):
                        reasons = reasons + [
                            {"label": f"Flagged by {vt_mal+vt_sus} of {vt_total} security vendors",
                             "severity": "medium", "feature": "virustotal", "value": vt_mal+vt_sus}
                        ]
                    print(f"[DECISION] ML Phishing at {confidence:.2f} + VT {vt_verdict} → Uncertain")
                else:
                    result  = "Legitimate"
                    message = "No threats detected on this page"
                    print(f"[DECISION] ML Phishing at {confidence:.2f} < {CONFIDENCE_THRESHOLD} threshold → Legitimate")

        # ── Rule 8: ML says Legitimate ────────────────────
        else:
            result  = "Legitimate"
            message = "No threats detected on this page"

    # end: if not _phishs_fired

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
    # BUGFIX: apply visual-clone upgrade BEFORE caching so the cached entry
    # already carries the correct status on all future cache hits.
    response_data = _apply_visual_clone_if_known(url, response_data)
    # Write to result cache — next identical URL returns instantly (~5ms)
    # Only cache the full result when we have a definitive verdict.
    # If Phishs errored (verdict=-1) AND no other strong signal fired
    # (GSB/VT/feed), use a short 5-min cache so the next scan retries Phishs.
    phishs_was_error = (phishs_result.get("verdict", -1) == -1)
    strong_signal_fired = (
        gsb_result.get("is_unsafe") or
        vt_result.get("verdict") == "malicious" or
        _feed_matched or
        _phishs_fired  # Phishs or feed set this to True
    )
    cache_ttl = 86400 if (not phishs_was_error or strong_signal_fired) else 300
    _RESULT_CACHE.set(result_cache_key, response_data, ttl=cache_ttl)
    if cache_ttl == 300:
        print(f"[CACHE] Short TTL (5min) for {url!r} -- Phishs was inconclusive")
    # BUGFIX: log using response_data's FINAL values, not the pre-override
    # local variables `result`/`confidence`. Previously this line ignored
    # whatever _apply_visual_clone_if_known() had just done — so a fresh scan
    # that got upgraded to status="visual_clone" (hash matched) was logged to
    # Scan History as "predicted"/"feed_match" instead, contradicting the
    # "Visual Clone" badge the user saw in the popup for that same scan.
    _final_status = response_data.get("status", "predicted")
    if _final_status not in ("visual_clone",):
        _final_status = "feed_match" if _feed_matched else "predicted"
    _log_scan(url,
              response_data.get("prediction", result),
              response_data.get("confidence", confidence),
              _final_status)
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
        # NOTE: /quick does NOT call _log_scan.
        # It is a fast pre-check called by the extension before /predict.
        # Only /predict logs to scan history to avoid double-counting.
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

    # ── URL-based fast path ───────────────────────────────────────────────────
    # If this URL's path (scheme+host+path, no query params) already appears in
    # _URL_TO_HASH it was previously confirmed as a phishing page.  Return a
    # visual-clone hit immediately WITHOUT relying on screenshot pHash comparison.
    #
    # Why this is needed:
    #   popup.js's captureCleanScreenshot() previously used requestAnimationFrame
    #   (which fires on the *popup* window's paint cycle, not the tab's).  This
    #   meant the orange overlay banner could still be pixel-visible in the tab
    #   when captureVisibleTab fired, baking the banner into the stored pHash.
    #   background.js always captures a clean page (fresh load, no overlay yet),
    #   so the pHash distance exceeded PHASH_SIMILARITY_THRESHOLD and
    #   is_visual_clone() returned False even though the hash WAS in the DB.
    #
    #   The timing bug is now fixed in popup.js, but hashes stored before the
    #   fix may still be "dirty" (overlay baked in).  The URL fast path makes
    #   detection reliable regardless of screenshot quality.
    req_cache_key = _cache_key(request.url)            # scheme://host/path only
    url_fast_hash: Optional[str] = None
    for stored_url_key, stored_hash in list(_URL_TO_HASH.items()):
        if _cache_key(stored_url_key) == req_cache_key:
            url_fast_hash = stored_hash
            break

    if url_fast_hash is not None:
        current_hash = compute_screenshot_hash(request.screenshot)
        print(f"[CLONE-CHECK] URL fast-path HIT for {request.url!r} "
              f"→ matched stored hash {url_fast_hash}")

        # ── Self-healing: repair dirty stored hashes automatically ────────────
        # The stored hash may have been captured with popup.js's old buggy code
        # (requestAnimationFrame timing — orange overlay baked into the PNG).
        # If the current screenshot's pHash differs from the stored one by more
        # than the similarity threshold, the stored hash is "dirty".  We add the
        # current clean hash to KNOWN_PHISHING_HASHES so that subsequent scans
        # can match via normal pHash comparison without needing the URL fast-path.
        if (current_hash
                and current_hash != url_fast_hash
                and current_hash not in KNOWN_PHISHING_HASHES
                and _IMAGEHASH_AVAILABLE):
            try:
                dist = (imagehash.hex_to_hash(current_hash)
                        - imagehash.hex_to_hash(url_fast_hash))
                if dist > PHASH_SIMILARITY_THRESHOLD:
                    # Stored hash is dirty — register the current clean hash
                    KNOWN_PHISHING_HASHES.add(current_hash)
                    if current_hash not in _HASH_INSERT_ORDER:
                        _HASH_INSERT_ORDER.append(current_hash)
                    _save_hash_db(KNOWN_PHISHING_HASHES, _URL_TO_HASH, _HASH_INSERT_ORDER)
                    print(f"[CLONE-CHECK] Dirty hash detected (dist={dist} > "
                          f"{PHASH_SIMILARITY_THRESHOLD}). "
                          f"Registered clean hash {current_hash} — "
                          f"pHash comparison will work on next scan.")
            except Exception as _heal_err:
                print(f"[CLONE-CHECK] Self-healing error: {_heal_err}")

        cached_before    = _RESULT_CACHE.get(_cache_key(request.url))
        already_phishing = (cached_before is not None
                            and cached_before.get("prediction") == "Phishing")
        if not already_phishing:
            updated = _update_last_scan_for_url(request.url, "Phishing", 0.99, "visual_clone")
            if not updated:
                _log_scan(request.url, "Phishing", 0.99, "visual_clone")
        return {
            "is_clone":     True,
            "matched_hash": url_fast_hash,
            "current_hash": current_hash,
            "db_size":      len(KNOWN_PHISHING_HASHES),
            "message":      "Screenshot matches a known phishing page design"
        }

    # ── pHash image comparison (fallback) ────────────────────────────────────
    result       = is_visual_clone(request.screenshot)
    current_hash = result.get("current_hash")

    if result["is_clone"]:
        # Visual clone override: only update scan history when correcting a
        # non-Phishing verdict (Uncertain → Phishing).
        #
        # If the verdict was ALREADY Phishing (cache hit from previous detection):
        #   - /predict already logged "cached"
        #   - We must NOT update that to "visual_clone"
        #   - The popup/overlay still shows Visual Clone because the cached result
        #     has prediction="Phishing" + visual_clone in reasons
        #
        # Since background.js now runs /predict BEFORE /screenshot (sequential),
        # /predict has always logged by the time we get here — no race condition.
        cached_before = _RESULT_CACHE.get(_cache_key(request.url))
        already_phishing = cached_before is not None and cached_before.get("prediction") == "Phishing"

        if not already_phishing:
            # Genuine correction: Uncertain (or first scan) → Phishing via clone
            updated = _update_last_scan_for_url(
                request.url, "Phishing", 0.99, "visual_clone"
            )
            if not updated:
                _log_scan(request.url, "Phishing", 0.99, "visual_clone")

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

    print(f"[HASH-DB] /hash/add called for url={request.url!r}  computed_hash={h}")

    already_existed = h in KNOWN_PHISHING_HASHES
    KNOWN_PHISHING_HASHES.add(h)

    # Track insertion order — append only if hash is new
    if not already_existed:
        _HASH_INSERT_ORDER.append(h)

    # Require a valid URL — reject the request if none is provided.
    # A hash without a URL mapping would show as "Unknown origin" in the dashboard
    # and provides no actionable information for the admin. We never store such hashes.
    if not request.url.strip():
        raise HTTPException(
            status_code=400,
            detail="URL is required when adding a phishing hash. "
                   "A hash without a source URL cannot be stored."
        )

    # Store URL→hash mapping — with orphan prevention:
    # If this URL already maps to a DIFFERENT hash, don't overwrite.
    # Overwriting causes the old hash to lose its URL mapping → "Unknown origin".
    # Root cause: background.js re-scans take new screenshots → slightly different
    # pHash each time. We keep the FIRST hash for each URL (the original detection).
    url_key       = _normalise_for_lookup(request.url)
    existing_hash = _URL_TO_HASH.get(url_key)
    if existing_hash and existing_hash != h:
        # URL already has a hash — don't create an orphan; return the existing one
        print(f"[HASH-DB] URL already mapped to {existing_hash} — skipping new hash {h}")
        return {
            "added":           existing_hash,
            "already_existed": True,
            "db_size":         len(KNOWN_PHISHING_HASHES),
            "persisted_to":    _HASH_DB_PATH,
            "message":         f"URL already has hash {existing_hash} — no change made"
        }
    _URL_TO_HASH[url_key] = h

    # Persist set + order + url map to disk
    _save_hash_db(KNOWN_PHISHING_HASHES, _URL_TO_HASH, _HASH_INSERT_ORDER)

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
    # BUGFIX: must use the SAME normalisation as /hash/add (_normalise_for_lookup),
    # which strips tracking params (utm_source, campaignid, adgroupid, etc.).
    # Using a different key here means this lookup almost never finds what
    # /hash/add stored for any URL with tracking params attached (i.e. nearly
    # every ad-driven page visit) — the hash silently never gets removed, and
    # subsequent /hash/add calls for the same URL are then blocked by the
    # orphan-prevention check, which thinks a hash is already mapped.
    url_key = _normalise_for_lookup(request.url)
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
    # Remove from insertion order list
    try: _HASH_INSERT_ORDER.remove(h)
    except ValueError: pass
    _save_hash_db(KNOWN_PHISHING_HASHES, _URL_TO_HASH, _HASH_INSERT_ORDER)

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
    for k, v in list(_URL_TO_HASH.items()):
        if v == h:
            _URL_TO_HASH.pop(k, None)
    try: _HASH_INSERT_ORDER.remove(h)
    except ValueError: pass
    _save_hash_db(KNOWN_PHISHING_HASHES, _URL_TO_HASH, _HASH_INSERT_ORDER)

    return {"removed": True, "hash": h, "db_size": len(KNOWN_PHISHING_HASHES),
            "message": f"Hash {h} removed"}


@app.get("/hash/list")
async def list_phishing_hashes():
    """
    List all known phishing page hashes currently in the database.
    Also returns hash_url_map (hash → url) so the admin dashboard can
    display which site each hash was captured from.
    """
    # Invert _URL_TO_HASH (url→hash) to hash→url for easy frontend lookup
    hash_url_map = {v: k for k, v in _URL_TO_HASH.items()}
    # Return in reverse insertion order: most recently added hash is first (#1 in UI)
    ordered_newest_first = list(reversed(_HASH_INSERT_ORDER))
    # Include any hashes that were added directly (not via /hash/add) and
    # therefore aren't in _HASH_INSERT_ORDER yet
    all_hashes_in_order  = ordered_newest_first + [
        h for h in sorted(KNOWN_PHISHING_HASHES)
        if h not in set(_HASH_INSERT_ORDER)
    ]
    return {
        "db_size":             len(KNOWN_PHISHING_HASHES),
        "db_path":             _HASH_DB_PATH,
        "hashes":              all_hashes_in_order,   # newest first
        "hash_url_map":        hash_url_map,
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

    # 1. Remove from the hash set (used for pHash comparison at scan time)
    KNOWN_PHISHING_HASHES.discard(hash_str)

    # 2. Remove from insertion-order list (controls display order in Hash DB tab)
    try: _HASH_INSERT_ORDER.remove(hash_str)
    except ValueError: pass

    # 3. Remove every URL→hash mapping whose value IS this hash.
    #    Without this step the hash string remains visible in phishing_hashes.json
    #    under "url_hash_map" even after deletion, making it look like it wasn't removed.
    stale_urls = [url for url, h in list(_URL_TO_HASH.items()) if h == hash_str]
    for url in stale_urls:
        _URL_TO_HASH.pop(url, None)

    # 4. Persist — all three data structures are now clean
    _save_hash_db(KNOWN_PHISHING_HASHES, _URL_TO_HASH, _HASH_INSERT_ORDER)

    return {
        "deleted":      hash_str,
        "url_mappings_removed": stale_urls,
        "db_size":      len(KNOWN_PHISHING_HASHES),
        "message":      "Hash fully removed from memory, url_map, and disk"
    }


@app.post("/cache/update")
async def update_cache_entry(request: dict):
    """
    Write a client-side overridden result back to the server cache.
    Called by background.js and popup.js after visual clone override fires.

    Scan history is NOT updated here — the /screenshot endpoint is the single
    place that handles scan history for visual clone corrections. This endpoint
    is purely a cache write.
    """
    url    = request.get("url", "").strip()
    result = request.get("result", {})
    if not url or not result:
        raise HTTPException(status_code=400, detail="url and result required")

    # Ensure the stored status reflects the clone override
    reasons = result.get("reasons", [])
    if any(r.get("feature") == "visual_clone" for r in reasons):
        result["status"] = "visual_clone"

    _RESULT_CACHE.set(_cache_key(url), result, ttl=86400)
    return {
        "status":     "updated",
        "url":        url,
        "prediction": result.get("prediction"),
    }


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



# ══════════════════════════════════════════════════════════════════════════════
#  INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════
#
# PhishGuard proxies every GoPhish API call through FastAPI so:
#   1. The GoPhish API key never leaves the server
#   2. React frontend has no CORS issue (same origin as /admin-stats)
#   3. We can enrich GoPhish data with PhishGuard ML risk scores
#
# Configuration — set these in your .env file:
#   PHISHGUARD_UNUSED = http://localhost:3333   (GoPhish server address)
#   PHISHGUARD_UNUSED = <your GoPhish API key>  (from GoPhish Settings page)
#


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



@app.get("/static-whitelist")
async def get_static_whitelist():
    """
    Returns the full _STATIC_DOMAINS list as a JSON array.
    This is the single source of truth for the trusted-domain whitelist.
    background.js fetches this on service worker startup so the extension
    always stays in sync with the server — no more maintaining two separate lists.
    Example: GET http://localhost:8000/static-whitelist
    """
    return {
        "domains": sorted(_STATIC_DOMAINS),
        "count":   len(_STATIC_DOMAINS),
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
    screenshot:  str = ""                 # optional base64 PNG — if provided on false_negative,
                                          # hash is added immediately without a separate /hash/add call

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
    cache_key   = _cache_key(url)   # same key as /predict uses

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
    # Use _normalise_for_lookup so tracking-param variants find the same key.
    if report_type == "false_positive":
        norm_key = _normalise_for_lookup(url)
        h = _URL_TO_HASH.pop(norm_key, None)
        if h:
            KNOWN_PHISHING_HASHES.discard(h)
            try: _HASH_INSERT_ORDER.remove(h)
            except ValueError: pass
            _save_hash_db(KNOWN_PHISHING_HASHES, _URL_TO_HASH, _HASH_INSERT_ORDER)
            print(f"[REPORT] Hash {h} removed (false_positive) for {url!r}")

    # If reporting as phishing AND a screenshot was provided, add its hash now.
    # This makes /report self-contained — popup.js still calls /hash/add separately
    # (belt-and-suspenders), but the web app can also trigger hash addition
    # if it ever gains screenshot capability.
    hash_added = None
    if report_type == "false_negative" and request.screenshot:
        h = compute_screenshot_hash(request.screenshot)
        if h and h not in KNOWN_PHISHING_HASHES:
            KNOWN_PHISHING_HASHES.add(h)
            _HASH_INSERT_ORDER.append(h)
            url_key = _normalise_for_lookup(url)
            _URL_TO_HASH[url_key] = h
            _save_hash_db(KNOWN_PHISHING_HASHES, _URL_TO_HASH, _HASH_INSERT_ORDER)
            hash_added = h
            print(f"[REPORT] Hash {h} added for false_negative on {url!r}")

    entry = {
        "url":          url,
        "report_type":  report_type,
        "corrected_to": corrected_prediction,
        "reported_by":  request.reported_by,
        "hash_added":   hash_added,
        "timestamp":    dt.datetime.now(dt.timezone.utc).isoformat(),
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


# ======================================================================
# === ADMIN DASHBOARD — SCAN HISTORY + AGGREGATED STATS
# ======================================================================

# In-memory scan event log.
# deque(maxlen) gives O(1) bounded append — oldest entry auto-evicted.
# _SCAN_HISTORY_LOCK protects iteration in /admin-stats and /scan-history.
_MAX_SCAN_HISTORY   = 2000            # keep at most 2,000 entries in RAM
_SCAN_HISTORY: deque = deque(maxlen=_MAX_SCAN_HISTORY)
_SCAN_HISTORY_LOCK  = threading.Lock()


def _log_scan(url: str, prediction: str, confidence: float, status: str) -> None:
    """Append one scan event to the bounded thread-safe history log."""
    entry = {
        "url":        url,
        "prediction": prediction,
        "confidence": round(float(confidence), 4),
        "status":     status,
        "timestamp":  dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    with _SCAN_HISTORY_LOCK:
        _SCAN_HISTORY.append(entry)


def _update_last_scan_for_url(url: str, prediction: str, confidence: float, status: str) -> bool:
    """
    Find the most recent scan history entry for this URL and update it in-place.
    Called by the /screenshot endpoint when a visual clone is detected AFTER
    /predict already logged the pre-override verdict (e.g. "Uncertain").

    Returns True if an existing entry was found and updated, False if not found
    (in which case the caller should call _log_scan to add a new entry).
    """
    key = _cache_key(url)
    with _SCAN_HISTORY_LOCK:
        history_list = list(_SCAN_HISTORY)
        # Scan from most-recent (end) backwards to find the latest entry for this URL
        for i in range(len(history_list) - 1, -1, -1):
            if _cache_key(history_list[i]["url"]) == key:
                history_list[i] = {
                    **history_list[i],
                    "prediction": prediction,
                    "confidence": round(float(confidence), 4),
                    "status":     status,
                    # Keep original timestamp; add updated_at to show it was corrected
                    "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                }
                # Rebuild the deque from the updated list
                _SCAN_HISTORY.clear()
                _SCAN_HISTORY.extend(history_list)
                return True
    return False


@app.post("/log-trusted")
async def log_trusted_visit(request: URLRequest):
    """
    Called by background.js when a URL is bypassed via the trusted-domain
    shortcut (isTrustedDomain() returned true) so those visits appear in
    the admin dashboard Scan History — they were previously invisible because
    the trusted-domain shortcut never reached the /predict endpoint.

    This is a fire-and-forget call — background.js does not await a response.
    The endpoint is intentionally lightweight: no ML, no whitelist check,
    just a log entry.
    """
    url = request.url.strip()
    if url:
        _log_scan(url, "Legitimate", 1.0, "trusted")
    return {"logged": True}



@app.get("/scan-history")
async def get_scan_history(limit: int = 500):
    """
    Return recent scan events in reverse-chronological order.
    Used by the Admin Dashboard Scan History tab.

    Query param:
        limit — max entries to return (default 500, max 2,000)

    Example:
        GET http://localhost:8000/scan-history?limit=100
    """
    limit = min(limit, _MAX_SCAN_HISTORY)
    with _SCAN_HISTORY_LOCK:
        snapshot = list(_SCAN_HISTORY)
    recent = list(reversed(snapshot))[:limit]
    return {
        "total":   len(snapshot),
        "count":   len(recent),
        "history": recent,
    }


@app.get("/admin-stats")
async def get_admin_stats():
    """
    Aggregated statistics for the Admin Dashboard overview card.
    Combines scan history, cache sizes, feed / whitelist metadata, and reports.

    Example:
        GET http://localhost:8000/admin-stats
    """
    with _SCAN_HISTORY_LOCK:
        snap = list(_SCAN_HISTORY)

    total     = len(snap)
    phishing  = sum(1 for s in snap if s["prediction"] == "Phishing")
    uncertain = sum(1 for s in snap if s["prediction"] == "Uncertain")
    legit     = sum(1 for s in snap if s["prediction"] == "Legitimate")

    domain_ctr: Counter = Counter()
    for s in snap:
        if s["prediction"] == "Phishing":
            try:
                domain = urlparse(s["url"]).netloc or s["url"]
                if domain:
                    domain_ctr[domain] += 1
            except Exception:
                pass

    return {
        # Scan counts
        "total_scans":         total,
        "phishing":            phishing,
        "uncertain":           uncertain,
        "legitimate":          legit,
        "phishing_rate":       round(phishing / total * 100, 1) if total else 0.0,

        # Top flagged domains
        "top_flagged_domains": domain_ctr.most_common(10),

        # Cache sizes
        "cache_stats": {
            "result_cache": _RESULT_CACHE.size(),
            "whois_cache":  _WHOIS_CACHE.size(),
            "vt_cache":     _VT_CACHE.size(),
        },

        # Misc
        "reports":      len(_REPORTS),
        "hash_db_size": len(KNOWN_PHISHING_HASHES),

        # External feed / whitelist status
        "feed_status": _phishing_feed_meta,
        "whitelist": {
            "tranco":       _tranco_meta,
            "static_count": len(_STATIC_DOMAINS),
        },
    }

@app.post("/admin/clear-history")
async def clear_scan_history():
    """Clear all scan history (for testing/evaluation)."""
    with _SCAN_HISTORY_LOCK:
        _SCAN_HISTORY.clear()
    return {"cleared": True, "message": "Scan history cleared"}