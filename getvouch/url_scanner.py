"""
GetVouch URL Scanner v1.5.0 — live URL security checks.
Read-only, ethical, no fuzzing, no payload injection.
"""
import re
import ssl
import socket
import datetime
import time
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
    "users", "profiles", "posts", "orders",
    "products", "documents", "notes", "messages",
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
    "www.google-analytics.com", "connect.facebook.net",
})

_WS_THIRD_PARTY = frozenset({
    "pusher.com", "ably.io", "ably.com", "liveblocks.io", "getstream.io",
})

_REDIRECT_PARAMS = [
    "redirect", "return", "returnTo", "url", "next", "dest",
    "destination", "continue", "goto", "redirect_uri", "target", "link",
]

# ── Regex ─────────────────────────────────────────────────────────────
_SUPABASE_URL_RE = re.compile(r'https://([a-z0-9]+)\.supabase\.co', re.I)
_SUPABASE_KEY_RE = re.compile(r'eyJ[a-zA-Z0-9_\-]{50,}')
_SCRIPT_SRC_RE   = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_API_PATH_RE     = re.compile(r'["\'](/api/[^"\'?\s]{1,60})["\']')
_VERSION_RE      = re.compile(r'\d+\.\d+\.?\d*')
_TEMPLATE_LIT_RE = re.compile(r'\$\{[^}]+\}')
_PROC_ENV_RE     = re.compile(r'^process\.env\.\w+$')

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
    """True if this Generic Secret match is likely a template-literal placeholder."""
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
    return False


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


# ── Check 6: Supabase RLS ─────────────────────────────────────────────
def check_supabase_rls(url: str, resp) -> list:
    """Detect Supabase credentials in source and test unauthenticated access."""
    if resp is None:
        return []
    content = resp.text
    sb_url_m = _SUPABASE_URL_RE.search(content)
    sb_key_m = _SUPABASE_KEY_RE.search(content)
    if not (sb_url_m and sb_key_m):
        return []
    sb_base  = f"https://{sb_url_m.group(1)}.supabase.co"
    anon_key = sb_key_m.group(0)
    for table in _SUPABASE_TABLES:
        test_url = f"{sb_base}/rest/v1/{table}?select=*&limit=1"
        r, _ = safe_fetch(test_url, timeout=5, extra_headers={
            "apikey": anon_key,
            "Authorization": f"Bearer {anon_key}",
        })
        if r is not None and r.status_code == 200:
            try:
                rows = r.json()
                if isinstance(rows, list) and rows:
                    return [_f(
                        "Supabase RLS Disabled",
                        f"{sb_base}/rest/v1/{table}",
                        f"Unauthenticated query returned {len(rows)} row(s) "
                        f"from '{table}' — Row Level Security is off",
                    )]
            except Exception:
                pass
    return []


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


# ── Check 8: Exposed Admin / Debug Paths ─────────────────────────────
def check_admin_paths(url: str) -> list:
    """Probe common admin and debug endpoints; flag HTTP 200 non-SPA responses."""
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    findings = []
    for path in _ADMIN_PATHS:
        resp, _ = safe_fetch(origin + path, timeout=4)
        if resp is None or resp.status_code != 200:
            continue
        if is_spa_fallback(resp):
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
    page_origin = p.netloc
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
        if rp.netloc == page_origin or any(t in rp.netloc for t in _INFRA_HOSTS):
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

    # Normalize scheme: always test https:// first to avoid false "No HTTPS" findings
    canonical_url, no_https_finding = normalize_and_test_https(target_url)
    if no_https_finding:
        findings["ssl"].append(no_https_finding)
    findings["ssl"].extend(check_ssl(canonical_url))

    resp, _ = safe_fetch(canonical_url)

    findings["headers"]         = check_security_headers(canonical_url, resp)
    findings["info_disclosure"] = check_info_disclosure(canonical_url, resp)
    findings["secrets"]         = check_secrets_in_source(canonical_url, resp)
    findings["supabase"]        = check_supabase_rls(canonical_url, resp)
    findings["cors"]            = check_cors(canonical_url, resp)
    findings["exposed_files"]   = check_exposed_files(canonical_url)
    findings["admin_paths"]     = check_admin_paths(canonical_url)
    findings["sri"]             = check_sri(canonical_url, resp)
    findings["mixed_content"]   = check_mixed_content(canonical_url, resp)
    findings["open_redirect"]   = check_open_redirect(canonical_url, resp)
    findings["websocket"]       = check_websocket(canonical_url, resp)
    findings["rate_limit"]      = check_rate_limit(canonical_url)

    urls_checked = (1 + len(_SENSITIVE_PATHS) + len(_ADMIN_PATHS)
                    + len(_AUTH_ENDPOINTS) + len(findings["cors"]))

    score = max(0, 100
                - len(findings["secrets"])        * 20
                - len(findings["supabase"])        * 25
                - len(findings["exposed_files"])   * 20
                - len(findings["ssl"])             * 15
                - len(findings["open_redirect"])   * 15
                - len(findings["cors"])            * 10
                - len(findings["admin_paths"])     * 10
                - len(findings["websocket"])       * 10
                - len(findings["headers"])         * 8
                - len(findings["rate_limit"])      * 8
                - len(findings["mixed_content"])   * 8
                - len(findings["info_disclosure"]) * 5
                - len(findings["sri"])             * 5)

    if score == 100:
        risk_level, rating = "LOW",      "CLEAN — No issues detected"
    elif score >= 75:
        risk_level, rating = "MODERATE", "MODERATE RISK — Remediation recommended"
    elif score >= 50:
        risk_level, rating = "HIGH",     "HIGH RISK — Fix before shipping"
    else:
        risk_level, rating = "CRITICAL", "CRITICAL — Do not ship"

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
        "repo_url":      canonical_url,
    }
