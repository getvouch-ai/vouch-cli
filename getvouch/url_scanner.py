"""
GetVouch URL Scanner v1.5.0 — live URL security checks.
Read-only, ethical, no fuzzing, no payload injection.
"""
import re
import ssl
import socket
import datetime
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

    urls_checked = (1 + len(_SENSITIVE_PATHS) + len(_ADMIN_PATHS)
                    + len(findings["cors"]))

    score = max(0, 100
                - len(findings["secrets"])        * 20
                - len(findings["supabase"])        * 25
                - len(findings["exposed_files"])   * 20
                - len(findings["ssl"])             * 15
                - len(findings["cors"])            * 10
                - len(findings["admin_paths"])     * 10
                - len(findings["headers"])         * 8
                - len(findings["info_disclosure"]) * 5)

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
