import os
import re

def run_vouch():
    print("")
    print("🛡️  GetVouch v0.2.0 — The Integrity Layer for AI-Native Software")
    print("🕵️  Hunting Ghosts in your codebase...")
    print("─" * 60)

    secret_patterns = {
        "OpenAI API Key":      r"sk-[a-zA-Z0-9]{32,}",
        "Anthropic API Key":   r"sk-ant-[a-zA-Z0-9\-]{32,}",
        "Google API Key":      r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe Secret Key":   r"sk_live_[0-9a-zA-Z]{24,}",
        "Stripe Test Key":     r"sk_test_[0-9a-zA-Z]{24,}",
        "AWS Access Key":      r"AKIA[0-9A-Z]{16}",
        "GitHub Token":        r"ghp_[a-zA-Z0-9]{36}",
        "Slack Token":         r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
        "Twilio API Key":      r"SK[0-9a-fA-F]{32}",
        "Generic Secret":      r"(?i)(secret|password|passwd|api_key)\s*=\s*['\"][^'\"]{8,}['\"]",
    }

    auth_patterns = {
        "Client-side admin check":   r"(?i)(isAdmin|is_admin|isOwner)\s*===?\s*(true|false)",
        "Client-side role check":    r"(?i)(role|userRole|user_role)\s*===?\s*['\"]?(admin|owner|superuser)['\"]?",
        "Client-side payment check": r"(?i)(isPaid|is_paid|hasPaid|has_paid|isSubscribed)\s*===?\s*(true|false)",
        "Client-side auth bypass":   r"(?i)if\s*\(\s*!(isAuth|is_auth|isLoggedIn|authenticated)\s*\)",
        "localStorage auth token":   r"localStorage\.(getItem|setItem)\s*\(\s*['\"]?(token|auth|jwt|session)['\"]?",
    }

    sql_patterns = {
        "SQL Injection risk": r"(?i)(SELECT|INSERT|UPDATE|DELETE).{0,40}[\+\$\{]",
    }

    scan_extensions = (
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".env", ".txt", ".json", ".yaml", ".yml",
        ".php", ".rb", ".go", ".java", ".cs"
    )

    frontend_extensions = (".js", ".jsx", ".ts", ".tsx")

    skip_folders = {
        ".git", "node_modules", "__pycache__",
        ".venv", "venv", "build", "dist"
    }

    secret_findings = []
    auth_findings = []
    sql_findings = []
    files_scanned = 0

    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in skip_folders]

        for file in files:
            if not file.endswith(scan_extensions):
                continue

            file_path = os.path.join(root, file)
            files_scanned += 1
            is_frontend = file.endswith(frontend_extensions)

            try:
                with open(file_path, "r", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):

                        for label, pattern in secret_patterns.items():
                            if re.search(pattern, line):
                                secret_findings.append({
                                    "type": label,
                                    "file": file_path,
                                    "line": line_num,
                                    "snippet": line.strip()[:80]
                                })

                        if is_frontend:
                            for label, pattern in auth_patterns.items():
                                if re.search(pattern, line):
                                    auth_findings.append({
                                        "type": label,
                                        "file": file_path,
                                        "line": line_num,
                                        "snippet": line.strip()[:80]
                                    })

                        for label, pattern in sql_patterns.items():
                            if re.search(pattern, line):
                                sql_findings.append({
                                    "type": label,
                                    "file": file_path,
                                    "line": line_num,
                                    "snippet": line.strip()[:80]
                                })

            except Exception:
                pass

    print(f"📂 Files scanned: {files_scanned}")
    print("")

    total_findings = len(secret_findings) + len(auth_findings) + len(sql_findings)

    if secret_findings:
        print(f"🚨 SECRETS EXPOSED — {len(secret_findings)} found:\n")
        for i, f in enumerate(secret_findings, 1):
            print(f"  [{i}] {f['type']}")
            print(f"      File    : {f['file']}")
            print(f"      Line    : {f['line']}")
            print(f"      Code    : {f['snippet']}")
            print("")
    else:
        print("✅ SECRETS — Clean. No exposed keys found.")
        print("")

    if auth_findings:
        print(f"⚠️  CLIENT-SIDE AUTH — {len(auth_findings)} risk(s) found:\n")
        for i, f in enumerate(auth_findings, 1):
            print(f"  [{i}] {f['type']}")
            print(f"      File    : {f['file']}")
            print(f"      Line    : {f['line']}")
            print(f"      Code    : {f['snippet']}")
            print(f"      Risk    : Auth logic in the browser can be bypassed")
            print(f"                by any user with DevTools. Move to server.")
            print("")
    else:
        print("✅ AUTH LOGIC — Clean. No client-side auth patterns found.")
        print("")

    if sql_findings:
        print(f"💉 SQL INJECTION — {len(sql_findings)} risk(s) found:\n")
        for i, f in enumerate(sql_findings, 1):
            print(f"  [{i}] {f['type']}")
            print(f"      File    : {f['file']}")
            print(f"      Line    : {f['line']}")
            print(f"      Code    : {f['snippet']}")
            print(f"      Risk    : User input in SQL queries.")
            print(f"                Use parameterized queries instead.")
            print("")
    else:
        print("✅ SQL — Clean. No injection patterns found.")
        print("")

    print("─" * 60)

    score = max(0, 100 - (len(secret_findings) * 20) - 
                (len(auth_findings) * 15) - (len(sql_findings) * 10))

    if score == 100:
        rating = "🟢 CLEAN — Safe to ship"
    elif score >= 80:
        rating = "🟡 LOW RISK — Minor issues"
    elif score >= 50:
        rating = "🔴 HIGH RISK — Fix before shipping"
    else:
        rating = "💀 CRITICAL — Do not ship"

    print(f"Your Vibe Score: {score}/100 — {rating}")
    print("")

    if total_findings > 0:
        print("Fix these before you ship.")
        print("Need help understanding the fixes? → getvouch.ai")

    print("")
    print("─" * 60)
    print("Powered by GetVouch v0.2.0 — Security for the AI Era")
    print("")

if __name__ == "__main__":
    run_vouch()
```
