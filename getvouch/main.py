import os
import re

def run_vouch():
    print("")
    print("🛡️  GetVouch v0.1.0 — The Integrity Layer for AI-Native Software")
    print("🕵️  Hunting Ghosts in your codebase...")
    print("─" * 60)

    patterns = {
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

    scan_extensions = (
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".env", ".txt", ".json", ".yaml", ".yml",
        ".php", ".rb", ".go", ".java", ".cs"
    )

    skip_folders = {
        ".git", "node_modules", "__pycache__",
        ".venv", "venv", "build", "dist"
    }

    findings = []
    files_scanned = 0

    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in skip_folders]

        for file in files:
            if not file.endswith(scan_extensions):
                continue

            file_path = os.path.join(root, file)
            files_scanned += 1

            try:
                with open(file_path, "r", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        for label, pattern in patterns.items():
                            if re.search(pattern, line):
                                findings.append({
                                    "type":  label,
                                    "file":  file_path,
                                    "line":  line_num,
                                    "snippet": line.strip()[:80]
                                })
            except Exception:
                pass

    print(f"📂 Files scanned: {files_scanned}")
    print("")

    if not findings:
        print("✅ CLEAN — No exposed secrets detected.")
        print("")
        print("Your Vibe Score: 100/100 🟢")
    else:
        critical = len(findings)
        print(f"🚨 ALERT — {critical} potential secret(s) exposed:\n")

        for i, f in enumerate(findings, 1):
            print(f"  [{i}] {f['type']}")
            print(f"      File : {f['file']}")
            print(f"      Line : {f['line']}")
            print(f"      Code : {f['snippet']}")
            print("")

        score = max(0, 100 - (critical * 15))
        if score >= 80:
            rating = "🟡 MODERATE RISK"
        elif score >= 50:
            rating = "🔴 HIGH RISK"
        else:
            rating = "💀 CRITICAL — DO NOT SHIP"

        print("─" * 60)
        print(f"Your Vibe Score: {score}/100 — {rating}")
        print("")
        print("Fix these before you ship.")
        print("Need help? → getvouch.ai")

    print("")
    print("─" * 60)
    print("Powered by GetVouch — Security for the AI Era")
    print("")

if __name__ == "__main__":
    run_vouch()
```

