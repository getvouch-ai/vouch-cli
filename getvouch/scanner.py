"""
Core scanning logic — pure function, no I/O side effects.
Used by both the CLI (main.py) and the web API (app.py).
"""
import os
import re
import json

SECRET_PATTERNS = {
    "OpenAI API Key":            r"sk-[a-zA-Z0-9]{32,}",
    "Anthropic API Key":         r"sk-ant-[a-zA-Z0-9\-]{32,}",
    "Google API Key":            r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase API Key":          r"AIzaSy[0-9A-Za-z\-_]{33}",
    "Firebase Service Account":  r'"type":\s*"service_account"',
    "Stripe Secret Key":         r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Key":           r"sk_test_[0-9a-zA-Z]{24,}",
    "Stripe Publishable Key":    r"pk_live_[0-9a-zA-Z]{24,}",
    "AWS Access Key":            r"AKIA[0-9A-Z]{16}",
    "AWS Secret":                r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "GitHub Token":              r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth":              r"gho_[a-zA-Z0-9]{36}",
    "SendGrid API Key":          r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
    "Mailgun API Key":           r"key-[0-9a-zA-Z]{32}",
    "Twilio Auth Token":         r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]",
    "Twilio API Key":            r"SK[0-9a-fA-F]{32}",
    "Shopify Secret Key":        r"shpss_[a-fA-F0-9]{32}",
    "PayPal Client Secret":      r"(?i)paypal.{0,20}secret.{0,20}['\"][A-Za-z0-9\-_]{20,}['\"]",
    "MongoDB Connection String": r"mongodb(\+srv)?://[^:]+:[^@]+@",
    "PostgreSQL Connection":     r"postgres(ql)?://[^:]+:[^@]+@",
    "JWT Secret":                r"(?i)(jwt.secret|jwt_secret|JWT_SECRET)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "Generic Secret":            r"(?i)(secret|password|passwd|api_key|apikey|access_token)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "Slack Token":               r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    "Slack Webhook":             r"https://hooks\.slack\.com/services/[A-Z0-9/]+",
    "Private Key Block":         r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
}

AUTH_PATTERNS = {
    "Client-side admin check":   r"(?i)(isAdmin|is_admin|isOwner)\s*===?\s*(true|false)",
    "Client-side role check":    r"(?i)(role|userRole|user_role)\s*===?\s*['\"]?(admin|owner|superuser)['\"]?",
    "Client-side payment check": r"(?i)(isPaid|is_paid|hasPaid|has_paid|isSubscribed)\s*===?\s*(true|false)",
    "Client-side auth bypass":   r"(?i)if\s*\(\s*!(isAuth|is_auth|isLoggedIn|authenticated)\s*\)",
    "localStorage auth token":   r"localStorage\.(getItem|setItem)\s*\(\s*['\"]?(token|auth|jwt|session)['\"]?",
}

SQL_PATTERNS = {
    "SQL Injection risk": r"(?i)(SELECT|INSERT|UPDATE|DELETE).{0,60}[\+\$\{]",
}

CORS_PATTERNS = {
    "CORS wildcard":         r"origin\s*:\s*['\"]?\*['\"]?",
    "CORS misconfiguration": r"Access-Control-Allow-Origin['\"]?\s*:\s*['\"]?\*",
}

VALIDATION_PATTERNS = {
    "Missing input validation": r"(?i)(req\.body\.|request\.form\[|request\.args\[).{0,60}(?!.*(validate|sanitize|escape|strip|clean|zod|joi|yup))",
}

IDOR_PATTERNS = {
    "Direct object reference": r"(?i)(findById|find_by_id|getById|get_by_id|params\.id|params\[.id.\]|req\.params\.id).{0,100}(?!.*(auth|permission|owner|role|admin))",
}

LOCALHOST_PATTERNS = {
    "Localhost URL in code": r"(?i)(http://localhost|http://127\.0\.0\.1):[0-9]+",
}

SCAN_EXTENSIONS = (
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".env", ".txt", ".json", ".yaml", ".yml",
    ".php", ".rb", ".go", ".java", ".cs",
    ".env.local", ".env.production",
    ".env.development", ".env.staging",
    ".config.js", ".config.ts",
)

FRONTEND_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx")
BACKEND_EXTENSIONS  = (".py", ".php", ".rb", ".go", ".java", ".cs")
JS_TS_EXTENSIONS    = (".js", ".ts", ".jsx", ".tsx", ".config.js", ".config.ts")

SKIP_FOLDERS = {
    ".git", "node_modules", "__pycache__",
    ".venv", "venv", "build", "dist",
    ".next", ".nuxt", "coverage", ".pytest_cache",
}

SKIP_FILES = {"main.py", "setup.py", "getvouch-report.html"}

KNOWN_OLD_DEPS = {
    "express": "4.17",
    "lodash":  "4.17.20",
    "axios":   "0.21",
    "moment":  "2.29",
    "jquery":  "3.6",
}


def _rel(path, base):
    """Return path relative to base, using forward slashes."""
    try:
        return os.path.relpath(path, base).replace("\\", "/")
    except ValueError:
        return path


def scan_directory(target_dir: str) -> dict:
    """
    Scan *target_dir* for security issues.

    Returns a dict with keys:
        findings   – categorised finding lists (file paths are relative)
        score      – int 0-100
        risk_level – "LOW" | "MODERATE" | "HIGH" | "CRITICAL"
        rating     – human-readable verdict string
        files_scanned – int
        totals     – per-category counts
    """
    target_dir = os.path.abspath(target_dir)

    findings: dict[str, list] = {
        "secrets": [], "auth": [], "sql": [], "cors": [],
        "env": [], "dependencies": [], "validation": [], "idor": [],
    }
    files_scanned = 0

    # ── .gitignore / env file checks ─────────────────────────────────
    gitignore_path = os.path.join(target_dir, ".gitignore")
    gitignore_content = ""

    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as gf:
            gitignore_content = gf.read()
        for env_file in (".env", ".env.local", ".env.production", ".env.development"):
            if os.path.exists(os.path.join(target_dir, env_file)):
                if env_file not in gitignore_content:
                    findings["env"].append({
                        "type": f"{env_file} not in .gitignore",
                        "file": ".gitignore",
                        "line": "-",
                        "snippet": f"{env_file} missing from .gitignore",
                    })
    else:
        if any(os.path.exists(os.path.join(target_dir, e))
               for e in (".env", ".env.local", ".env.production")):
            findings["env"].append({
                "type": "Missing .gitignore",
                "file": "project root",
                "line": "-",
                "snippet": "No .gitignore file found",
            })

    # ── package.json dependency check ────────────────────────────────
    pkg_path = os.path.join(target_dir, "package.json")
    if os.path.exists(pkg_path):
        try:
            with open(pkg_path, "r", encoding="utf-8") as pf:
                pkg = json.load(pf)
            all_deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            for pkg_name, min_ver in KNOWN_OLD_DEPS.items():
                if pkg_name in all_deps:
                    ver = all_deps[pkg_name].lstrip("^~>=")
                    if ver < min_ver:
                        findings["dependencies"].append({
                            "type": "Outdated dependency",
                            "file": "package.json",
                            "line": "-",
                            "snippet": f"{pkg_name}@{ver} — update to latest",
                        })
        except Exception:
            pass

    # ── File walk ─────────────────────────────────────────────────────
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS]
        for file in files:
            if file in SKIP_FILES:
                continue
            if not any(file.endswith(ext) for ext in SCAN_EXTENSIONS):
                continue

            abs_path = os.path.join(root, file)
            rel_path = _rel(abs_path, target_dir)
            files_scanned += 1

            is_frontend = file.endswith(FRONTEND_EXTENSIONS)
            is_backend  = file.endswith(BACKEND_EXTENSIONS)
            is_js_ts    = file.endswith(JS_TS_EXTENSIONS)

            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line_num, line in enumerate(fh, 1):

                        for label, pat in SECRET_PATTERNS.items():
                            if re.search(pat, line):
                                findings["secrets"].append({
                                    "type": label, "file": rel_path,
                                    "line": line_num, "snippet": line.strip()[:80],
                                })

                        if is_frontend:
                            for label, pat in AUTH_PATTERNS.items():
                                if re.search(pat, line):
                                    findings["auth"].append({
                                        "type": label, "file": rel_path,
                                        "line": line_num, "snippet": line.strip()[:80],
                                    })

                        if is_js_ts and not file.endswith(".py"):
                            for label, pat in SQL_PATTERNS.items():
                                if re.search(pat, line):
                                    findings["sql"].append({
                                        "type": label, "file": rel_path,
                                        "line": line_num, "snippet": line.strip()[:80],
                                    })

                        for label, pat in CORS_PATTERNS.items():
                            if re.search(pat, line):
                                findings["cors"].append({
                                    "type": label, "file": rel_path,
                                    "line": line_num, "snippet": line.strip()[:80],
                                })

                        if is_js_ts or is_backend:
                            for label, pat in VALIDATION_PATTERNS.items():
                                if re.search(pat, line):
                                    findings["validation"].append({
                                        "type": label, "file": rel_path,
                                        "line": line_num, "snippet": line.strip()[:80],
                                    })

                        if is_js_ts or is_backend:
                            for label, pat in IDOR_PATTERNS.items():
                                if re.search(pat, line):
                                    findings["idor"].append({
                                        "type": label, "file": rel_path,
                                        "line": line_num, "snippet": line.strip()[:80],
                                    })

                        for label, pat in LOCALHOST_PATTERNS.items():
                            if re.search(pat, line):
                                findings["dependencies"].append({
                                    "type": label, "file": rel_path,
                                    "line": line_num, "snippet": line.strip()[:80],
                                })
            except Exception:
                pass

    # ── Score ─────────────────────────────────────────────────────────
    score = max(0, 100
                - len(findings["secrets"])      * 20
                - len(findings["auth"])         * 20
                - len(findings["sql"])          * 15
                - len(findings["cors"])         * 10
                - len(findings["env"])          * 20
                - len(findings["dependencies"]) * 5
                - len(findings["validation"])   * 10
                - len(findings["idor"])         * 15)

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

    return {
        "findings":     findings,
        "score":        score,
        "risk_level":   risk_level,
        "rating":       rating,
        "files_scanned": files_scanned,
        "totals":       totals,
    }
