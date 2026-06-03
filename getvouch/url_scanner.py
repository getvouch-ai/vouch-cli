"""
GetVouch URL Scanner v1.6.3 — live URL security checks.
Read-only, ethical, no fuzzing, no payload injection.
"""
import re
import ssl
import socket
import base64
import json as _json
import datetime
import time
import secrets
import threading
import concurrent.futures
from urllib.parse import urlparse, urljoin

import httpx

from getvouch.scanner import SECRET_PATTERNS

USER_AGENT = "GetVouch-Scanner/1.5.0 (https://getvouch.net)"
_HEADERS    = {"User-Agent": USER_AGENT}

# ── Static lists ──────────────────────────────────────────────────────
_SECURITY_HEADERS = {
    "content-security-policy":   "Content-Security-Policy",
    "x-frame-options":           "X-Frame-Options",
    "strict-transport-security": "Strict-Transport-Security (HSTS)",
    "x-content-type-options":    "X-Content-Type-Options",
    "referrer-policy":           "Referrer-Policy",
    "permissions-policy":        "Permissions-Policy",
}

_SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.staging",
    "/.git/config", "/.git/HEAD",
    "/wp-config.php", "/wp-config.php.bak",
    "/.DS_Store", "/backup.sql", "/database.sql",
    "/config.php", "/config.json", "/secrets.json",
    "/.htpasswd", "/.npmrc",
]

_ADMIN_PATHS = [
    "/admin", "/administrator", "/admin.php",
    "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma",
    "/actuator", "/actuator/env",
    "/swagger-ui.html", "/swagger-ui", "/api-docs", "/openapi.json",
    "/console", "/debug", "/graphiql",
]

_SUPABASE_TABLES = [
    "users", "profiles", "accounts", "posts", "products",
    "orders", "comments", "reviews", "sessions", "messages",
    "todos", "tasks", "projects", "items", "customers",
]

_AUTH_ENDPOINTS = [
    "/login", "/signin", "/api/login", "/api/auth/login",
    "/api/signup", "/signup", "/register", "/api/register",
    "/auth/login", "/auth/signup", "/api/v1/auth/login",
]

_CDN_ORIGINS = frozenset({
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "cdn.skypack.dev", "esm.sh",
})

_INFRA_HOSTS = frozenset({
    "googletagmanager.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "www.google-analytics.com", "google-analytics.com", "connect.facebook.net",
    "cloudflareinsights.com", "vercel.live", "vercel-scripts.com",
    "plausible.io", "cdn.affonso.io", "snap.licdn.com",
    "analytics.tiktok.com", "js.stripe.com",
})

_CAT_SEVERITY = {
    "secrets":         "CRITICAL",
    "supabase":        "CRITICAL",
    "supply_chain":    "CRITICAL",
    "exposed_files":   "HIGH",
    "ssl":             "HIGH",
    "open_redirect":   "HIGH",
    "cors":            "HIGH",
    "admin_paths":     "HIGH",
    "auth":            "HIGH",
    "sql":             "HIGH",
    "idor":            "HIGH",
    "env":             "HIGH",
    "websocket":       "MEDIUM",
    "headers":         "MEDIUM",
    "rate_limit":      "MEDIUM",
    "mixed_content":   "MEDIUM",
    "validation":      "MEDIUM",
    "info_disclosure": "LOW",
    "sri":             "LOW",
    "dependencies":    "LOW",
}

_WS_THIRD_PARTY = frozenset({
    "pusher.com", "ably.io", "ably.com", "liveblocks.io", "getstream.io",
})

_REDIRECT_PARAMS = [
    "redirect", "return", "returnTo", "url", "next", "dest",
    "destination", "continue", "goto", "redirect_uri", "target", "link",
]

# ── Regex ─────────────────────────────────────────────────────────────
# M1: direct project URL
_SUPABASE_URL_RE     = re.compile(r'https://([a-z0-9]{20,})\.supabase\.(co|in)', re.I)
# M2: quoted/minified patterns
_SUPABASE_QUOTED_RE  = re.compile(
    r"""["'`](https://[a-z0-9-]{15,}\.supabase\.(co|in))["'`/]""", re.I)
_SUPABASE_ENV_RE     = re.compile(
    r"""(?:VITE_SUPABASE_URL|NEXT_PUBLIC_SUPABASE_URL|supabaseUrl)\s*[:=]\s*["'`](https://[^"'`]+)""",
    re.I)
_SUPABASE_CLIENT_RE  = re.compile(
    r"""createClient\s*\(\s*["'`](https://[^"'`]+)""", re.I)
# Full 3-segment JWT (more reliable than bare eyJ...)
_SUPABASE_JWT_RE     = re.compile(
    r"""["'`](eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+)["'`]""")
# Bare JWT fallback (existing pattern)
_SUPABASE_KEY_RE     = re.compile(r'eyJ[a-zA-Z0-9_\-]{50,}')
# Sent on every Supabase request so operators can identify scanner traffic
_SB_USER_AGENT = ("GetVouch-Scanner/1.5.9 (https://getvouch.net/security)"
                  " - ethical RLS audit")
_SCRIPT_SRC_RE   = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_API_PATH_RE     = re.compile(r'["\'](/api/[^"\'?\s]{1,60})["\']')
_VERSION_RE      = re.compile(r'\d+\.\d+\.?\d*')
_TEMPLATE_LIT_RE = re.compile(r'\$\{[^}]+\}')
_PROC_ENV_RE     = re.compile(r'^process\.env\.\w+$')
_SECRET_VAR_RE   = re.compile(
    r'(?:key|secret|token|password|passwd|pwd|api[_\-]?key|auth[_\-]?key|private[_\-]?key)',
    re.I
)
_JS_MINIFIED_RE  = re.compile(
    r'(?:function\s*\w*\s*\(|=>\s*\{|\.prototype\b|\.length\b|parseInt|parseFloat|\.push\()',
    re.I
)

# SPA catch-all fingerprints — modern SPAs return HTTP 200 for every unknown path
_SPA_FINGERPRINTS = [
    b'id="root"', b"id='root'",
    b'id="app"',  b"id='app'",
    b'id="__next"',
    b'/_next/',
    b'__nuxt',
    b'data-reactroot',
    b'ng-version=',
    b'<script type="module"',
]

_HTTP_ASSET_RE = re.compile(
    r'<(?:script|link|img|iframe|video|audio|source)[^>]*(?:src|href)=["\']'
    r'(http://[^"\']+)["\']',
    re.I
)
_WS_URL_RE = re.compile(r'[\'\"](wss?://[^\'\"<>\s]+)[\'\"]', re.I)
_REDIRECT_PARAM_RE = re.compile(
    r'(?:href|action)=["\']([^"\']*?[?&](?:'
    + '|'.join(["redirect", "return", "returnTo", "url", "next", "dest",
                 "destination", "continue", "goto", "redirect_uri", "target", "link"])
    + r')=[^"\'&\s]+)["\']',
    re.I
)


# ── Helpers ───────────────────────────────────────────────────────────
def safe_fetch(url: str, timeout: float = 10,
               extra_headers: dict = None) -> tuple:
    """Return (httpx.Response, None) or (None, exception). Never raises."""
    try:
        h = {**_HEADERS, **(extra_headers or {})}
        resp = httpx.get(url, headers=h, timeout=timeout,
                         follow_redirects=True)
        return resp, None
    except Exception as exc:
        return None, exc


def _f(type_: str, file_: str, snippet: str) -> dict:
    """Build a finding dict in the standard shape."""
    return {"type": type_, "file": file_, "line": "-",
            "snippet": snippet[:120]}


def is_spa_fallback(resp) -> bool:
    """True if the response looks like a SPA catch-all 200, not a real file."""
    if resp is None:
        return False
    ct = resp.headers.get("content-type", "")
    if "text/html" not in ct:
        return False
    body = resp.content[:4000]
    return any(fp in body for fp in _SPA_FINGERPRINTS)


def _is_false_positive_secret(label: str, line: str) -> bool:
    """True if this Generic Secret match is a false positive (template, env var, or minified JS)."""
    if label != "Generic Secret":
        return False
    m = re.search(r'[=:]\s*[\'"]([^\'"]*)[\'"]', line)
    if not m:
        return False
    val = m.group(1)
    if len(val) < 20:
        return True
    if _TEMPLATE_LIT_RE.search(val) or "${" in val:
        return True
    if _PROC_ENV_RE.match(val.strip()):
        return True
    # Only flag if the variable name looks like a secret holder
    prefix = line[max(0, m.start() - 60):m.start()]
    if not _SECRET_VAR_RE.search(prefix):
        return True
    # Skip if JS syntax tokens appear near the match (minified code)
    context = line[max(0, m.start() - 30):min(len(line), m.end() + 30)]
    if _JS_MINIFIED_RE.search(context):
        return True
    return False


def _registrable_domain(host: str) -> str:
    """Strip www. prefix and port for same-origin comparison."""
    h = host.lower().split(":")[0]
    return h[4:] if h.startswith("www.") else h


def _is_login_page(resp) -> bool:
    """True if the response is a login/auth page, not an exposed admin panel."""
    final_url = str(resp.url).lower()
    if any(s in final_url for s in _LOGIN_URL_SIGNALS):
        return True
    body = resp.content[:8000].lower()
    if any(m in body for m in _LOGIN_BODY_MARKERS):
        return True
    soft_hits = sum(1 for s in _LOGIN_BODY_SOFT if s in body)
    return soft_hits >= 2


# ── Check 1: Security Headers ─────────────────────────────────────────
def check_security_headers(url: str, resp) -> list:
    """Flag each missing recommended security response header."""
    if resp is None:
        return []
    present = {k.lower() for k in resp.headers}
    return [
        _f(f"Missing {name}", url,
           f"{name} header absent — browsers receive no {name} directive")
        for key, name in _SECURITY_HEADERS.items()
        if key not in present
    ]


# ── Check 2: Information Disclosure ──────────────────────────────────
def check_info_disclosure(url: str, resp) -> list:
    """Detect server/framework version strings leaked in HTTP headers."""
    if resp is None:
        return []
    findings = []
    for h in ("server", "x-powered-by", "x-aspnet-version",
               "x-aspnetmvc-version", "x-generator"):
        val = resp.headers.get(h, "")
        if val and _VERSION_RE.search(val):
            findings.append(_f("Version in HTTP Header", url,
                               f"{h}: {val}"))
    return findings


# ── Check 3: SSL / TLS ────────────────────────────────────────────────
def normalize_and_test_https(submitted_url: str) -> tuple:
    """
    Always probe https:// first regardless of submitted scheme.
    Returns (canonical_url, no_https_finding_or_None).
    Prevents false positives when users paste http:// links to HTTPS sites.
    """
    parsed = urlparse(submitted_url)
    host = parsed.netloc or parsed.path.split("/")[0]

    https_url = f"https://{host}"
    http_url  = f"http://{host}"

    https_resp, _ = safe_fetch(https_url, timeout=10)
    if https_resp is not None and https_resp.status_code < 500:
        return https_url, None   # HTTPS works — no finding, use https:// canonically

    http_resp, _ = safe_fetch(http_url, timeout=10)
    if http_resp is not None and http_resp.status_code < 500:
        return http_url, _f(
            "No HTTPS", http_url,
            f"Site at {host} only accessible over HTTP — HTTPS is not available"
        )

    return https_url, None   # unreachable; other checks handle None resp gracefully


def check_ssl(url: str) -> list:
    """Check TLS certificate validity and expiry (canonical https:// URL assumed)."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return []
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        )
        days = (not_after - datetime.datetime.utcnow()).days
        if days < 7:
            return [_f("SSL Certificate Expiring Soon", url,
                       f"Certificate expires in {days} day(s): {cert['notAfter']}")]
    except ssl.SSLCertVerificationError as exc:
        return [_f("SSL Certificate Error", url, str(exc)[:80])]
    except Exception:
        pass
    return []


# ── Check 4: Exposed Sensitive Files ─────────────────────────────────
def check_exposed_files(url: str) -> list:
    """Probe common sensitive paths; flag any that return HTTP 200 with real content."""
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    findings = []
    for path in _SENSITIVE_PATHS:
        resp, _ = safe_fetch(origin + path, timeout=4)
        if resp is None or resp.status_code != 200 or not resp.content:
            continue
        if is_spa_fallback(resp):
            continue
        # Content-validate so minified-JS false positives are rejected
        body = resp.text[:2000]
        if ".env" in path and not re.search(r'^\w+=', body, re.MULTILINE):
            continue
        if ".git" in path and not re.search(r'\[core\]|ref:|[0-9a-f]{40}', body):
            continue
        if path.endswith(".sql") and not re.search(
                r'(?i)(CREATE TABLE|INSERT INTO|DROP TABLE)', body):
            continue
        findings.append(_f("Exposed Sensitive File", origin + path,
                           f"HTTP 200 — {path} is publicly accessible"))
    return findings


# ── Check 5: Secrets in Page Source / JS Bundles ─────────────────────
def check_secrets_in_source(url: str, resp) -> list:
    """Run all 25 secret patterns against the page and linked JS bundles."""
    if resp is None:
        return []
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    sources = [(url, resp.text)]
    for m in list(_SCRIPT_SRC_RE.finditer(resp.text))[:6]:
        src = m.group(1)
        js_url = src if src.startswith("http") else urljoin(origin, src)
        js_resp, _ = safe_fetch(js_url, timeout=5)
        if js_resp and js_resp.status_code == 200:
            sources.append((js_url, js_resp.text))
    findings = []
    for source_url, content in sources:
        for label, pattern in SECRET_PATTERNS.items():
            for ln in content.splitlines():
                if re.search(pattern, ln) and not _is_false_positive_secret(label, ln):
                    findings.append(_f(label, source_url, ln.strip()[:80]))
                    break  # one finding per label per source
    return findings


# ── Check 6: Supabase RLS Deep Test (v1.5.8) ─────────────────────────
def _audit_ev(phase, action, result, detail=""):
    """Build an audit log event dict."""
    return {"phase": phase, "action": action, "result": result, "detail": detail}


def _decode_jwt_payload(token):
    """Return decoded JWT payload dict, or None on failure."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        seg = parts[1]
        # Pad to 4-byte boundary
        seg += "==" * ((4 - len(seg) % 4) % 4)
        return _json.loads(base64.b64decode(seg))
    except Exception:
        return None


def _find_keys(combined):
    """Return (anon_key, service_role_key) found in combined text. Either may be None."""
    anon_key = None
    svc_key = None
    best = None

    def _classify(candidate):
        nonlocal anon_key, svc_key, best
        payload = _decode_jwt_payload(candidate)
        if payload:
            role = payload.get("role", "")
            if role == "anon" and anon_key is None:
                anon_key = candidate
                return
            if role == "service_role" and svc_key is None:
                svc_key = candidate
                return
        if best is None:
            best = candidate

    for m in _SUPABASE_JWT_RE.finditer(combined):
        _classify(m.group(1))
    for m in _SUPABASE_KEY_RE.finditer(combined):
        _classify(m.group(0))

    if anon_key is None and svc_key is None:
        anon_key = best
    return anon_key, svc_key


def _collect_entry_assets(html_text, origin, cap=25):
    """Collect entry-level JS asset URLs (script src, modulepreload, preload as=script)."""
    seen = set()
    urls = []

    def _add(src):
        if not src:
            return
        src = src.strip()
        if src.startswith(("data:", "javascript:")):
            return
        full = src if src.startswith("http") else urljoin(origin, src)
        if full not in seen:
            seen.add(full)
            urls.append(full)

    for m in _SCRIPT_SRC_RE.finditer(html_text):
        _add(m.group(1))
    for tag_m in re.finditer(r'<link\b[^>]+>', html_text, re.I | re.S):
        tag = tag_m.group(0)
        rel_m = re.search(r'\brel=["\']([^"\']+)["\']', tag, re.I)
        if not rel_m:
            continue
        rel = rel_m.group(1).lower()
        href_m = re.search(r'\bhref=["\']([^"\']+)["\']', tag, re.I)
        if not href_m:
            continue
        if rel == "modulepreload":
            _add(href_m.group(1))
        elif rel == "preload":
            as_m = re.search(r'\bas=["\']([^"\']+)["\']', tag, re.I)
            if as_m and as_m.group(1).lower() == "script":
                _add(href_m.group(1))

    return urls[:cap]


def _fetch_assets_parallel(urls, budget=15.0):
    """Fetch URLs in parallel (4 workers, 5s each, `budget`s total). Never raises."""
    if not urls:
        return []
    deadline = time.time() + budget
    texts = {}

    def _one(u):
        try:
            r = httpx.get(u, headers=_HEADERS, timeout=5, follow_redirects=True)
            if r and r.status_code == 200:
                return u, r.text
        except Exception:
            pass
        return u, ""

    remaining = max(0.5, deadline - time.time())
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            fmap = {executor.submit(_one, u): u for u in urls}
            for fut in concurrent.futures.as_completed(fmap, timeout=remaining):
                try:
                    u, text = fut.result()
                    if text:
                        texts[u] = text
                except Exception:
                    pass
                if time.time() > deadline:
                    break
    except concurrent.futures.TimeoutError:
        pass
    except Exception:
        pass

    return list(texts.values())


def check_supabase_rls(url, resp):
    """
    Returns (findings: list, audit_log: list, status: str).
    status: 'no_response' | 'not_detected' | 'key_missing' | 'tested'

    Scans page HTML + up to 25 entry-level assets (script src, modulepreload,
    preload as=script). Service role key in client bundle → CRITICAL finding.
    Parallel RLS testing: 4 workers, 100ms gap, 30s budget, 429 abort.
    """
    audit = []

    if resp is None:
        audit.append(_audit_ev("supabase_detection", "Scanning for Supabase usage",
                               "skipped", "No response received"))
        return [], audit, "no_response"

    p = urlparse(url)
    origin = f"{p.scheme}://{p.netloc}"
    page_html = resp.text

    # ── Phase 1: Collect + fetch entry-level assets ───────────────────
    asset_urls = _collect_entry_assets(page_html, origin, cap=25)
    asset_texts = _fetch_assets_parallel(asset_urls, budget=15.0)
    combined = page_html + "\n" + "\n".join(asset_texts)

    n_assets = len(asset_urls)
    audit.append(_audit_ev(
        "supabase_detection", "Fetched entry-level JS bundles",
        "found" if n_assets > 0 else "skipped",
        f"Scanned {n_assets} entry-level assets (script tags + modulepreload links)"
    ))

    # ── Phase 2: 4-method Supabase URL detection ──────────────────────
    sb_base = None

    # M1: direct URL pattern
    m1 = _SUPABASE_URL_RE.search(combined)
    if m1:
        sb_base = f"https://{m1.group(1)}.supabase.co"

    # M2: minified-JS-aware patterns
    if not sb_base:
        for pat in (_SUPABASE_QUOTED_RE, _SUPABASE_ENV_RE, _SUPABASE_CLIENT_RE):
            m2 = pat.search(combined)
            if m2:
                raw = m2.group(1).strip().rstrip("/")
                if ".supabase." in raw.lower() and raw.startswith("https://"):
                    sb_base = raw
                    break

    # M3: response headers
    if not sb_base:
        for hname, hval in resp.headers.items():
            if hname.lower().startswith("x-supabase-"):
                m3 = _SUPABASE_URL_RE.search(hval + " " + url)
                if m3:
                    sb_base = f"https://{m3.group(1)}.supabase.co"
                break
        if not sb_base and "postgrest" in resp.headers.get("x-powered-by", "").lower():
            m3b = _SUPABASE_URL_RE.search(url)
            if m3b:
                sb_base = f"https://{m3b.group(1)}.supabase.co"

    # M4: linked resource analysis
    if not sb_base:
        for m4 in re.finditer(
            r'(?:src|href)=["\']([^"\']*supabase\.(?:co|in)[^"\']*)["\']',
            combined, re.I
        ):
            m4u = _SUPABASE_URL_RE.search(m4.group(1))
            if m4u:
                sb_base = f"https://{m4u.group(1)}.supabase.co"
                break

    if not sb_base:
        audit.append(_audit_ev(
            "supabase_detection", "Searching for Supabase project URL", "blocked",
            "No Supabase URLs found in entry-level bundles. "
            "NOTE: This scan does not perform recursive chunk analysis. "
            "If your app uses Vite or similar bundlers with dynamic imports, "
            "Supabase may be in a nested chunk we did not scan."
        ))
        return [], audit, "not_detected"

    project_id = sb_base.split("//")[1].split(".")[0]

    # ── Phase 3: Key extraction ───────────────────────────────────────
    anon_key, svc_key = _find_keys(combined)
    findings = []

    if svc_key:
        audit.append(_audit_ev(
            "supabase_detection", "Inspecting JWT role claim", "bypassed",
            "Detected service_role JWT in client bundle — CRITICAL exposure"
        ))
        findings.append(_f(
            "Supabase Service Role Key Exposed", sb_base,
            "service_role JWT found in client-side bundle — bypasses ALL RLS policies"
        ))

    if not anon_key:
        audit.append(_audit_ev(
            "supabase_detection", "Searching for Supabase anon key", "blocked",
            "Supabase project URL found, but no anon key visible in entry-level bundles. "
            "The key may be in a nested chunk — RLS testing cannot proceed without it."
        ))
        if not svc_key:
            findings.append(_f(
                "Supabase Detected — Key Not Visible", sb_base,
                f"Supabase project {project_id} found; anon key not extracted "
                "— RLS cannot be tested remotely"
            ))
        return findings, audit, "key_missing"

    audit.append(_audit_ev(
        "supabase_detection", "Located Supabase project and anon key", "found",
        f"Project: {project_id}, anon key extracted"
    ))

    sb_hdrs = {
        "apikey":        anon_key,
        "Authorization": f"Bearer {anon_key}",
        "User-Agent":    _SB_USER_AGENT,
    }

    # ── Phase 4: Table discovery via OpenAPI ──────────────────────────
    tables = []
    try:
        disc, _ = safe_fetch(f"{sb_base}/rest/v1/", timeout=10, extra_headers=sb_hdrs)
        if disc and disc.status_code == 200:
            spec = disc.json()
            schemas = (spec.get("definitions")
                       or spec.get("components", {}).get("schemas")
                       or {})
            tables = [t for t in schemas if not t.startswith("_")][:20]
            audit.append(_audit_ev("table_discovery",
                                   "Requesting OpenAPI schema from /rest/v1/",
                                   "found", f"Discovered {len(tables)} tables"))
        else:
            code = disc.status_code if disc else "no response"
            audit.append(_audit_ev("table_discovery",
                                   "Requesting OpenAPI schema from /rest/v1/",
                                   "skipped",
                                   f"OpenAPI returned {code} — using common-name fallback"))
    except Exception as exc:
        audit.append(_audit_ev("table_discovery",
                               "Requesting OpenAPI schema from /rest/v1/",
                               "error", str(exc)[:80]))

    if not tables:
        tables = list(_SUPABASE_TABLES)
        audit.append(_audit_ev("table_discovery",
                               "Falling back to common table name probing",
                               "found", f"Testing {len(tables)} common table names"))

    tables = tables[:20]

    # ── Phase 5: Parallel RLS testing (4 workers, 100ms gap, 30s budget) ─
    deadline = datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
    sem = threading.Semaphore(4)
    launch_lock = threading.Lock()
    last_launch = [0.0]
    stop_flag = threading.Event()

    def _test_one(table):
        with sem:
            if stop_flag.is_set() or datetime.datetime.utcnow() > deadline:
                return table, None, "timeout"
            with launch_lock:
                now = time.time()
                gap = now - last_launch[0]
                if gap < 0.1:
                    time.sleep(0.1 - gap)
                last_launch[0] = time.time()
            try:
                r = httpx.get(
                    f"{sb_base}/rest/v1/{table}?select=*",
                    headers={**sb_hdrs, "Range": "0-2"},
                    timeout=5,
                    follow_redirects=True,
                )
                return table, r, None
            except Exception as exc:
                return table, None, str(exc)[:60]

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        fmap = {executor.submit(_test_one, t): t for t in tables}
        for fut in concurrent.futures.as_completed(fmap, timeout=32):
            try:
                table, r, err = fut.result()
            except Exception:
                continue
            if err == "timeout" or r is None:
                continue
            if r.status_code == 429:
                stop_flag.set()
                audit.append(_audit_ev("rls_test", f"Rate limit hit on {table}",
                                       "error", "HTTP 429 — stopping Supabase phase"))
                break
            if r.status_code == 404:
                continue
            if r.status_code != 200:
                audit.append(_audit_ev("rls_test",
                                       f"Testing unauthenticated SELECT on {table} table",
                                       "blocked",
                                       f"RLS active — HTTP {r.status_code}"))
                continue
            try:
                rows = r.json()
            except Exception:
                continue
            if not isinstance(rows, list) or not rows:
                audit.append(_audit_ev("rls_test",
                                       f"Testing unauthenticated SELECT on {table} table",
                                       "blocked", "Empty result — RLS active or table empty"))
                continue
            cols = ", ".join(list(rows[0].keys())[:10])
            audit.append(_audit_ev("rls_test",
                                   f"Testing unauthenticated SELECT on {table} table",
                                   "found",
                                   f"RLS BYPASSED — {len(rows)} row(s) — columns: {cols}"))
            findings.append(_f(
                "Supabase RLS Disabled",
                f"{sb_base}/rest/v1/{table}",
                f"Unauthenticated read of '{table}' returned {len(rows)} row(s) "
                f"— columns: {cols}",
            ))

    return findings, audit, "tested"


# ── Check 7: CORS Misconfiguration ────────────────────────────────────
def check_cors(url: str, resp) -> list:
    """Find /api/* paths in page source and test with a hostile Origin."""
    if resp is None:
        return []
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    findings = []
    seen: set = set()
    for m in _API_PATH_RE.finditer(resp.text):
        path = m.group(1)
        if path in seen or len(seen) >= 5:
            continue
        seen.add(path)
        test_url = urljoin(origin, path)
        r, _ = safe_fetch(test_url, timeout=5, extra_headers={
            "Origin": "https://evil.example.com",
        })
        if r is not None:
            acao = r.headers.get("access-control-allow-origin", "")
            if acao in ("*", "https://evil.example.com"):
                findings.append(_f(
                    "CORS Wildcard or Origin Reflection", test_url,
                    f"Access-Control-Allow-Origin: {acao}",
                ))
    return findings


_LOGIN_URL_SIGNALS  = ("/login", "/signin", "/sign-in", "/auth")
_LOGIN_BODY_MARKERS = [b'type="password"', b"type='password'"]
_LOGIN_BODY_SOFT    = [b"forgot password", b"sign in", b"log in", b"username", b"email address"]

# ── Admin-path content markers — only flag if body contains these ─────
_ADMIN_BODY_MARKERS = [
    b"phpmyadmin", b"wp-login", b"wordpress", b"swagger-ui", b"swagger ui",
    b"actuator", b"graphiql", b"joomla", b"spring boot", b"admin login",
    b"login required", b'name="password"', b"name='password'",
]
_ADMIN_JSON_MARKERS = [
    b"status", b"swagger", b"openapi", b"_links",
    b"managementPort", b"activeProfiles",
]


def check_admin_paths(url: str, audit_log: list = None) -> list:
    """
    Probe common admin and debug endpoints using baseline-probe comparison
    to eliminate SPA-fallback false positives (Vite/React/Lovable apps).
    """
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    findings = []

    # ── 1. Baseline probe against a guaranteed-nonexistent path ──────
    probe_path = f"/__getvouch_probe_{secrets.token_hex(8)}"
    baseline_resp, _ = safe_fetch(origin + probe_path, timeout=5)

    if baseline_resp is not None:
        bl_status  = baseline_resp.status_code
        bl_ct      = baseline_resp.headers.get("content-type", "").lower()
        bl_body    = baseline_resp.content[:8000]
        bl_len     = len(baseline_resp.content)
        bl_head200 = bl_body[:200]

        # Detect SPA fallback site: baseline returns 200 HTML with SPA markers
        is_spa_fallback_site = (
            bl_status == 200
            and "html" in bl_ct
            and any(fp in bl_body for fp in _SPA_FINGERPRINTS)
        )
        detail = (
            f"Baseline probe: {bl_status} {bl_ct or 'unknown'} "
            f"{bl_len} bytes"
            + (" — SPA fallback detected, using content validation" if is_spa_fallback_site else "")
        )
    else:
        bl_status  = None
        bl_ct      = ""
        bl_body    = b""
        bl_len     = 0
        bl_head200 = b""
        is_spa_fallback_site = False
        detail = "Baseline probe: unreachable"

    if audit_log is not None:
        audit_log.append({
            "phase": "admin_paths",
            "action": "Baseline probe for SPA-fallback detection",
            "result": "found",
            "detail": detail,
        })

    # ── 2. Probe each admin path ──────────────────────────────────────
    for path in _ADMIN_PATHS:
        resp, _ = safe_fetch(origin + path, timeout=4)
        if resp is None or resp.status_code != 200:
            continue

        body = resp.content[:8000]
        body_lower = body.lower()
        ct   = resp.headers.get("content-type", "").lower()
        resp_len  = len(resp.content)
        resp_head = body[:200]

        # ── Skip conditions (in order) ─────────────────────────────

        # a) Matches baseline by status + length (±10%) + first 200 chars
        if bl_status == 200:
            len_ok = bl_len == 0 or abs(resp_len - bl_len) / max(bl_len, 1) <= 0.10
            if len_ok and resp_head == bl_head200:
                continue

        # b) Definitive Vite SPA marker in the response itself
        if (
            (b'id="root"' in body or b"id='root'" in body or
             b'id="app"'  in body or b"id='app'"  in body)
            and b'<script type="module" src="/assets/' in body
        ):
            continue

        # c) Site is a known SPA fallback + this response is HTML 200
        if is_spa_fallback_site and "html" in ct and resp.status_code == 200:
            continue

        # d) Generic SPA fingerprint check (existing helper)
        if is_spa_fallback(resp):
            continue

        # e) Login/auth redirect — expected to require credentials, not an exposed panel
        if _is_login_page(resp):
            continue

        # ── Flag conditions ────────────────────────────────────────

        # JSON paths (actuator, api-docs, openapi) — require JSON content-type
        # and expected structural markers
        if any(p in path for p in ("/actuator", "/api-docs", "/openapi")):
            if "json" not in ct:
                continue
            if not any(m in body_lower for m in _ADMIN_JSON_MARKERS):
                continue
        else:
            # HTML/other paths — require at least one admin-panel body marker
            if not any(m in body_lower for m in _ADMIN_BODY_MARKERS):
                continue

        findings.append(_f(
            "Exposed Admin or Debug Path", origin + path,
            f"HTTP 200 — {path} accessible without authentication",
        ))

    return findings


# ── Check 9: Subresource Integrity ────────────────────────────────────
def check_sri(url: str, resp) -> list:
    """Flag external scripts/styles loaded without an integrity= hash."""
    if resp is None:
        return []
    p = urlparse(url)
    page_reg = _registrable_domain(p.netloc)
    findings = []
    seen: set = set()
    for tag_m in re.finditer(r'<(script|link)\s[^>]*>', resp.text, re.I | re.S):
        tag = tag_m.group(0)
        tag_type = tag_m.group(1).lower()
        attr_m = (re.search(r'\bsrc=["\']([^"\']+)["\']', tag, re.I) if tag_type == 'script'
                  else re.search(r'\bhref=["\']([^"\']+)["\']', tag, re.I))
        if not attr_m:
            continue
        res_url = attr_m.group(1)
        if res_url.startswith(('data:', 'javascript:')):
            continue
        if res_url.startswith('//'):
            res_url = f"{p.scheme}:{res_url}"
        if not res_url.startswith('http'):
            continue
        rp = urlparse(res_url)
        if _registrable_domain(rp.netloc) == page_reg or any(t in rp.netloc for t in _INFRA_HOSTS):
            continue
        if res_url in seen or re.search(r'\bintegrity=', tag, re.I):
            continue
        seen.add(res_url)
        if rp.netloc in _CDN_ORIGINS:
            findings.append(_f("Missing Subresource Integrity (CDN)", res_url,
                               "CDN resource loaded without integrity= hash — supply chain risk"))
        else:
            findings.append(_f("Missing Subresource Integrity (Third-party)", res_url,
                               f"Third-party resource at {rp.netloc} loaded without integrity= hash"))
    return findings[:8]


# ── Check 10: Mixed Content ────────────────────────────────────────────
def check_mixed_content(url: str, resp) -> list:
    """Flag HTTP resources loaded on an HTTPS page."""
    if resp is None or urlparse(url).scheme != "https":
        return []
    findings = []
    for m in _HTTP_ASSET_RE.finditer(resp.text):
        findings.append(_f("Mixed Content", url,
                           f"HTTPS page loads HTTP resource: {m.group(1)[:80]}"))
    return findings[:5]


# ── Check 11: Open Redirect ────────────────────────────────────────────
def check_open_redirect(url: str, resp) -> list:
    """Test redirect parameters found in page HTML for open redirect."""
    if resp is None:
        return []
    p = urlparse(url)
    origin = f"{p.scheme}://{p.netloc}"
    test_dest = "https://example.com/getvouch-open-redirect-test"
    findings = []
    seen: set = set()
    for m in _REDIRECT_PARAM_RE.finditer(resp.text):
        raw_url = m.group(1)
        if not raw_url.startswith('http'):
            raw_url = urljoin(origin, raw_url)
        rp = urlparse(raw_url)
        if rp.netloc and rp.netloc != p.netloc:
            continue
        key = rp.path + "?" + rp.query
        if key in seen:
            continue
        seen.add(key)
        param_m = re.search(
            r'([?&])(' + '|'.join(_REDIRECT_PARAMS) + r')=([^&]+)', rp.query, re.I
        )
        if not param_m:
            continue
        test_url = raw_url.replace(param_m.group(3), test_dest, 1)
        r, _ = safe_fetch(test_url, timeout=5)
        if r is not None and r.history:
            loc = r.history[-1].headers.get("location", "")
            if "getvouch-open-redirect-test" in loc:
                findings.append(_f(
                    "Open Redirect", origin + rp.path,
                    f"?{param_m.group(2)}= redirects to attacker-controlled URL"
                ))
                break
    return findings


# ── Check 12: Rate Limit on Auth Endpoints ────────────────────────────
def check_rate_limit(url: str) -> list:
    """Send 10 rapid POSTs to auth endpoints; flag if no 429 is returned."""
    p = urlparse(url)
    origin = f"{p.scheme}://{p.netloc}"
    findings = []
    dummy = b'{"email":"test@example.com","password":"test123"}'
    hdrs = {**_HEADERS,
            "Content-Type": "application/json",
            "User-Agent": "GetVouch-Scanner/1.5.6-RateLimitProbe (https://getvouch.net)"}
    deadline = datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
    for path in _AUTH_ENDPOINTS:
        if datetime.datetime.utcnow() > deadline:
            break
        endpoint = origin + path
        try:
            r0 = httpx.post(endpoint, content=dummy, headers=hdrs,
                            timeout=5, follow_redirects=False)
        except Exception:
            continue
        # Only test endpoints that actually process auth requests
        # 200+content, 400/401/422 (processing errors) → real endpoint
        # 404/405/403/4xx others → not an auth endpoint, skip
        if r0.status_code in (404, 405, 403, 410):
            continue
        if is_spa_fallback(r0):
            continue
        if r0.status_code == 200:
            body_lower = r0.text[:3000].lower()
            _AUTH_SIGNALS = ("password", "email", "username", "sign in",
                             "credentials", "token", "bearer", '"error"', '"message"')
            if not any(s in body_lower for s in _AUTH_SIGNALS):
                continue
            if "captcha" in body_lower or "recaptcha" in body_lower:
                continue
        elif r0.status_code not in (400, 401, 422, 429, 503):
            continue  # unexpected status — not a real auth endpoint
        statuses = [r0.status_code]
        rate_limited = r0.status_code in (429, 503)
        for _ in range(9):
            if rate_limited:
                break
            time.sleep(0.1)
            try:
                r = httpx.post(endpoint, content=dummy, headers=hdrs,
                               timeout=5, follow_redirects=False)
                statuses.append(r.status_code)
                if r.status_code in (429, 503):
                    rate_limited = True
            except Exception:
                break
        if not rate_limited and len(statuses) >= 5:
            findings.append(_f(
                "No Rate Limiting on Auth Endpoint", endpoint,
                f"{len(statuses)} rapid requests returned {statuses[0]} — no 429 received"
            ))
            break
    return findings


# ── Check 13: WebSocket Security ──────────────────────────────────────
def _try_ws_handshake(ws_url: str, extra_headers: dict = None) -> bool:
    """Attempt raw HTTP→WS upgrade; returns True if server sends 101."""
    try:
        import base64, os as _os
        p = urlparse(ws_url)
        host = p.hostname
        port = p.port or (443 if ws_url.startswith("wss") else 80)
        path = (p.path or "/") + (f"?{p.query}" if p.query else "")
        key = base64.b64encode(_os.urandom(16)).decode()
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        for k, v in (extra_headers or {}).items():
            lines.append(f"{k}: {v}")
        lines += ["", ""]
        req = "\r\n".join(lines).encode()
        if ws_url.startswith("wss"):
            raw = socket.create_connection((host, port), timeout=5)
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(raw, server_hostname=host)
        else:
            conn = socket.create_connection((host, port), timeout=5)
        conn.sendall(req)
        resp_data = conn.recv(512).decode("utf-8", errors="ignore")
        conn.close()
        return "101 Switching Protocols" in resp_data
    except Exception:
        return False


def check_websocket(url: str, resp) -> list:
    """Find WebSocket URLs in page/JS and test for missing auth/origin checks."""
    if resp is None:
        return []
    p = urlparse(url)
    origin = f"{p.scheme}://{p.netloc}"
    ws_urls: set = set()
    sources = [resp.text]
    for m in list(_SCRIPT_SRC_RE.finditer(resp.text))[:4]:
        src = m.group(1)
        js_url = src if src.startswith("http") else urljoin(origin, src)
        js_resp, _ = safe_fetch(js_url, timeout=5)
        if js_resp and js_resp.status_code == 200:
            sources.append(js_resp.text)
    for source in sources:
        for m in _WS_URL_RE.finditer(source):
            ws_urls.add(m.group(1))
    findings = []
    for ws_url in list(ws_urls)[:5]:
        if any(t in ws_url for t in _WS_THIRD_PARTY):
            continue
        if _try_ws_handshake(ws_url):
            findings.append(_f(
                "WebSocket Accepts Unauthenticated Connections", ws_url,
                "WebSocket 101 upgrade succeeded without authentication credentials"
            ))
            if _try_ws_handshake(ws_url, {"Origin": "https://evil.example.com"}):
                findings.append(_f(
                    "WebSocket Accepts Arbitrary Origins", ws_url,
                    "WebSocket accepts connections from evil.example.com — no origin check"
                ))
    return findings


# ── Orchestrator ──────────────────────────────────────────────────────
def normalize_input_url(submitted: str) -> str:
    """Prepend https:// to bare domains so the scanner always gets a valid URL."""
    url = submitted.strip()
    if url.startswith('github.com/'):
        return 'https://' + url
    if not (url.startswith('http://') or url.startswith('https://')):
        return 'https://' + url
    return url


def scan_url(target_url: str) -> dict:
    """
    Run all 8 URL security checks against target_url.
    Returns the same shape as scan_directory().
    """
    findings: dict[str, list] = {
        "headers": [], "info_disclosure": [], "ssl": [],
        "secrets": [], "supabase": [], "cors": [],
        "exposed_files": [], "admin_paths": [],
        "sri": [], "mixed_content": [], "open_redirect": [],
        "websocket": [], "rate_limit": [],
    }

    target_url = normalize_input_url(target_url)
    # Normalize scheme: always test https:// first to avoid false "No HTTPS" findings
    canonical_url, no_https_finding = normalize_and_test_https(target_url)
    if no_https_finding:
        findings["ssl"].append(no_https_finding)
    findings["ssl"].extend(check_ssl(canonical_url))

    resp, _ = safe_fetch(canonical_url)

    findings["headers"]         = check_security_headers(canonical_url, resp)
    findings["info_disclosure"] = check_info_disclosure(canonical_url, resp)
    findings["secrets"]         = check_secrets_in_source(canonical_url, resp)
    sb_findings, audit_log, supabase_scan_status = check_supabase_rls(canonical_url, resp)
    findings["supabase"]        = sb_findings
    findings["cors"]            = check_cors(canonical_url, resp)
    findings["exposed_files"]   = check_exposed_files(canonical_url)
    findings["admin_paths"]     = check_admin_paths(canonical_url, audit_log=audit_log)
    findings["sri"]             = check_sri(canonical_url, resp)
    findings["mixed_content"]   = check_mixed_content(canonical_url, resp)
    findings["open_redirect"]   = check_open_redirect(canonical_url, resp)
    findings["websocket"]       = check_websocket(canonical_url, resp)
    findings["rate_limit"]      = check_rate_limit(canonical_url)

    urls_checked = (1 + len(_SENSITIVE_PATHS) + len(_ADMIN_PATHS)
                    + len(_AUTH_ENDPOINTS) + len(findings["cors"]))

    _weights = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 4, "LOW": 1}
    score = max(0, 100 - sum(
        len(v) * _weights.get(_CAT_SEVERITY.get(k, "LOW"), 1)
        for k, v in findings.items()
    ))

    crit_count = sum(len(v) for k, v in findings.items() if _CAT_SEVERITY.get(k) == "CRITICAL")
    high_count = sum(len(v) for k, v in findings.items() if _CAT_SEVERITY.get(k) == "HIGH")
    med_count  = sum(len(v) for k, v in findings.items() if _CAT_SEVERITY.get(k) == "MEDIUM")
    low_count  = sum(len(v) for k, v in findings.items() if _CAT_SEVERITY.get(k) == "LOW")

    if crit_count >= 1:
        risk_level, rating = "CRITICAL", "CRITICAL — Do not ship"
    elif high_count >= 3:
        risk_level, rating = "HIGH",     "HIGH RISK — Fix before shipping"
    elif high_count >= 1 or med_count >= 8:
        risk_level, rating = "MODERATE", "MODERATE RISK — Remediation recommended"
    elif med_count >= 1 or low_count >= 1:
        risk_level, rating = "LOW",      "LOW RISK — Minor issues to address"
    else:
        risk_level, rating = "LOW",      "CLEAN — No issues detected"

    totals = {k: len(v) for k, v in findings.items()}
    totals["total"] = sum(totals.values())

    try:
        from getvouch.fix_prompts import generate_fix_prompt
        for category, finding_list in findings.items():
            for finding in finding_list:
                finding["fix_prompt"] = generate_fix_prompt(finding, category)
    except Exception:
        pass

    return {
        "findings":      findings,
        "score":         score,
        "risk_level":    risk_level,
        "rating":        rating,
        "files_scanned": urls_checked,
        "totals":        totals,
        "repo_url":             canonical_url,
        "supabase_scan_status": supabase_scan_status,
        "audit_log":            audit_log,
    }
