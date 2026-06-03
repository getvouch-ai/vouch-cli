"""
Core scanning logic — pure function, no I/O side effects.
Used by both the CLI (main.py) and the web API (app.py).
"""
import os
import re
import json

SECRET_PATTERNS = {
    "OpenAI API Key":            r"sk-proj-[a-zA-Z0-9_-]{16,}|sk-svcacct-[a-zA-Z0-9_-]{16,}|sk-[a-zA-Z0-9]{32,}",
    "Anthropic API Key":         r"sk-ant-[a-zA-Z0-9_-]{20,}",
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


def check_supply_chain_attacks(repo_files: dict) -> list:
    """
    Scans package.json, package-lock.json, and yarn.lock for known-compromised
    package versions from major 2025-2026 npm supply chain attacks.
    """
    from .supply_chain_iocs import is_compromised, THREAT_INTEL_SOURCES

    findings = []

    # 1. package.json (direct dependencies)
    package_json = repo_files.get("package.json")
    if package_json:
        try:
            data = json.loads(package_json)
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                deps = data.get(section, {})
                for pkg_name, version_spec in deps.items():
                    clean_version = re.sub(r"^[\^~>=<\s]+", "", str(version_spec))
                    ioc = is_compromised(pkg_name, clean_version)
                    if ioc:
                        findings.append({
                            "type": f"Known-compromised package: {pkg_name}@{clean_version}",
                            "file": f"package.json → {section}",
                            "line": "-",
                            "snippet": f"campaign: {ioc['campaign']} | safe: {ioc['safe_version']}",
                            "fix_prompt": _supply_chain_fix_prompt(pkg_name, clean_version, ioc, THREAT_INTEL_SOURCES),
                        })
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    # 2. package-lock.json (transitive deps — more thorough)
    lock_file = repo_files.get("package-lock.json")
    if lock_file:
        try:
            data = json.loads(lock_file)
            packages = data.get("packages") or data.get("dependencies") or {}
            for pkg_path, pkg_data in packages.items():
                if pkg_path == "":
                    continue
                name = pkg_path.split("node_modules/")[-1]
                version = pkg_data.get("version", "")
                if not version:
                    continue
                ioc = is_compromised(name, version)
                if ioc:
                    findings.append({
                        "type": f"Known-compromised package in lockfile: {name}@{version}",
                        "file": "package-lock.json",
                        "line": "-",
                        "snippet": f"campaign: {ioc['campaign']} | safe: {ioc['safe_version']}",
                        "fix_prompt": _supply_chain_fix_prompt(name, version, ioc, THREAT_INTEL_SOURCES),
                    })
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    # 3. yarn.lock
    yarn_lock = repo_files.get("yarn.lock")
    if yarn_lock:
        yarn_entries = re.findall(
            r'^([^@\s"]+)@[^\n]+:\n\s+version "([^"]+)"',
            yarn_lock,
            re.MULTILINE,
        )
        for name, version in yarn_entries:
            ioc = is_compromised(name, version)
            if ioc:
                findings.append({
                    "type": f"Known-compromised package in yarn.lock: {name}@{version}",
                    "file": "yarn.lock",
                    "line": "-",
                    "snippet": f"campaign: {ioc['campaign']} | safe: {ioc['safe_version']}",
                    "fix_prompt": _supply_chain_fix_prompt(name, version, ioc, THREAT_INTEL_SOURCES),
                })

    # Deduplicate (same pkg+version across multiple files)
    seen = set()
    unique = []
    for f in findings:
        key = (f["type"],)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _supply_chain_fix_prompt(pkg_name: str, version: str, ioc: dict, sources: list) -> str:
    sources_text = "\n".join(sources)
    return (
        f"CRITICAL SECURITY FIX NEEDED — Your project uses {pkg_name}@{version}, "
        f"which was compromised in the {ioc['campaign']} supply chain attack.\n\n"
        f"What this means: {ioc['description']}\n\n"
        f"If you have already run npm install with this version present, treat your "
        f"environment as potentially compromised.\n\n"
        f"Immediate actions:\n\n"
        f"1. STOP — do not deploy any code that includes this dependency.\n\n"
        f"2. Update the package:\n"
        f"   npm install {pkg_name}@latest\n"
        f"   (Safe version guidance: {ioc['safe_version']})\n\n"
        f"3. Delete and regenerate your lockfile:\n"
        f"   rm -rf package-lock.json node_modules && npm install\n"
        f"   (For yarn: rm -rf yarn.lock node_modules && yarn install)\n\n"
        f"4. If you ran npm install with this version at any point, ROTATE immediately:\n"
        f"   - npm tokens: https://www.npmjs.com/settings/~/tokens\n"
        f"   - GitHub Personal Access Tokens: https://github.com/settings/tokens\n"
        f"   - AWS IAM access keys\n"
        f"   - GCP service account keys\n"
        f"   - All .env API keys\n"
        f"   - SSH keys used for git operations\n\n"
        f"5. Audit git history for suspicious commits or repos you don't recognise.\n\n"
        f"6. Check CI/CD logs for unexpected outbound network traffic.\n\n"
        f"Reference sources:\n{sources_text}\n\n"
        f"After remediation: re-run GetVouch to confirm the compromised version is gone. "
        f"For real-time supply chain monitoring, consider Socket or Snyk Open Source."
    )


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
        "supply_chain": [],
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

    # ── package.json dependency check + supply chain IOC scan ────────
    pkg_path      = os.path.join(target_dir, "package.json")
    lock_path     = os.path.join(target_dir, "package-lock.json")
    yarn_lock_path = os.path.join(target_dir, "yarn.lock")

    repo_files: dict[str, str] = {}
    if os.path.exists(pkg_path):
        try:
            with open(pkg_path, "r", encoding="utf-8") as pf:
                raw = pf.read()
            repo_files["package.json"] = raw
            pkg = json.loads(raw)
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

    if os.path.exists(lock_path):
        try:
            with open(lock_path, "r", encoding="utf-8") as lf:
                repo_files["package-lock.json"] = lf.read()
        except Exception:
            pass

    if os.path.exists(yarn_lock_path):
        try:
            with open(yarn_lock_path, "r", encoding="utf-8") as yf:
                repo_files["yarn.lock"] = yf.read()
        except Exception:
            pass

    from .supply_chain_iocs import LAST_UPDATED
    supply_chain_audit: list = []

    if not repo_files:
        supply_chain_audit.append({
            "phase": "supply_chain",
            "action": "Scanning for package management files",
            "result": "skipped",
            "detail": "No package.json, package-lock.json, or yarn.lock found — skipping supply chain check",
        })
    else:
        supply_chain_audit.append({
            "phase": "supply_chain",
            "action": "Scanning dependencies against known-compromised package IOCs",
            "result": "found",
            "detail": "Checking against 5 active campaigns: qix_phish_2025, shai_hulud_2025, s1ngularity_2025, mini_shai_hulud_2026, and individual compromises",
        })
        sc_findings = check_supply_chain_attacks(repo_files)
        findings["supply_chain"] = sc_findings
        if sc_findings:
            supply_chain_audit.append({
                "phase": "supply_chain",
                "action": "Detected compromised packages",
                "result": "bypassed",
                "detail": f"Found {len(sc_findings)} package(s) matching known compromise campaigns",
            })
        else:
            supply_chain_audit.append({
                "phase": "supply_chain",
                "action": "Verified dependencies against known compromise list",
                "result": "blocked",
                "detail": f"No matches found. Note: this is a static check against published IOCs (last updated {LAST_UPDATED}). For real-time supply chain monitoring, use Socket or Snyk.",
            })

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
    _SC_SEVERITY = {
        "secrets":      "CRITICAL",
        "supply_chain": "CRITICAL",
        "auth":         "HIGH",
        "sql":          "HIGH",
        "cors":         "HIGH",
        "idor":         "HIGH",
        "env":          "HIGH",
        "validation":   "MEDIUM",
        "dependencies": "LOW",
    }
    _weights = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 4, "LOW": 1}
    score = max(0, 100 - sum(
        len(v) * _weights.get(_SC_SEVERITY.get(k, "LOW"), 1)
        for k, v in findings.items()
    ))

    crit_count = sum(len(v) for k, v in findings.items() if _SC_SEVERITY.get(k) == "CRITICAL")
    high_count = sum(len(v) for k, v in findings.items() if _SC_SEVERITY.get(k) == "HIGH")
    med_count  = sum(len(v) for k, v in findings.items() if _SC_SEVERITY.get(k) == "MEDIUM")
    low_count  = sum(len(v) for k, v in findings.items() if _SC_SEVERITY.get(k) == "LOW")

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

    # Attach AI fix prompts to every finding (supply_chain already has custom prompts)
    try:
        from getvouch.fix_prompts import generate_fix_prompt
        for category, finding_list in findings.items():
            if category == "supply_chain":
                continue
            for finding in finding_list:
                finding["fix_prompt"] = generate_fix_prompt(finding, category)
    except Exception:
        pass

    return {
        "findings":      findings,
        "score":         score,
        "risk_level":    risk_level,
        "rating":        rating,
        "files_scanned": files_scanned,
        "totals":        totals,
        "audit_log":     supply_chain_audit,
    }
