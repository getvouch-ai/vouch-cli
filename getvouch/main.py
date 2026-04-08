import os
import re
import datetime

def generate_html_report(secret_findings, auth_findings, 
                          sql_findings, files_scanned, score, rating):
    
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(secret_findings) + len(auth_findings) + len(sql_findings)

    if score == 100:
        score_color = "#22c55e"
    elif score >= 80:
        score_color = "#eab308"
    elif score >= 50:
        score_color = "#ef4444"
    else:
        score_color = "#7f1d1d"

    def build_rows(findings, category_color):
        if not findings:
            return f"""
            <tr>
              <td colspan='4' style='text-align:center;
              color:#22c55e;padding:16px;'>
                No issues found
              </td>
            </tr>"""
        rows = ""
        for f in findings:
            rows += f"""
            <tr>
              <td><span style='background:{category_color};
                color:white;padding:3px 10px;border-radius:20px;
                font-size:12px;font-weight:600;'>
                {f['type']}</span></td>
              <td style='font-family:monospace;font-size:12px;
                color:#6b7280;'>{f['file']}</td>
              <td style='text-align:center;color:#6b7280;'>
                {f['line']}</td>
              <td style='font-family:monospace;font-size:11px;
                background:#f9fafb;padding:4px 8px;border-radius:4px;
                max-width:300px;overflow:hidden;text-overflow:ellipsis;
                white-space:nowrap;'>{f['snippet']}</td>
            </tr>"""
        return rows

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='UTF-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1.0'>
  <title>GetVouch Security Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 
      'Segoe UI', sans-serif; background: #f8fafc; 
      color: #1e293b; padding: 40px 20px; }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    .header {{ background: #0f172a; color: white; 
      border-radius: 12px; padding: 32px; 
      margin-bottom: 24px; }}
    .header h1 {{ font-size: 24px; margin-bottom: 6px; }}
    .header p {{ color: #94a3b8; font-size: 14px; }}
    .score-box {{ background: white; border-radius: 12px; 
      padding: 32px; margin-bottom: 24px; 
      border: 1px solid #e2e8f0; text-align: center; }}
    .score-number {{ font-size: 72px; font-weight: 700; 
      color: {score_color}; line-height: 1; }}
    .score-label {{ font-size: 18px; color: #64748b; 
      margin-top: 8px; }}
    .score-rating {{ font-size: 20px; font-weight: 600; 
      color: {score_color}; margin-top: 12px; }}
    .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); 
      gap: 16px; margin-bottom: 24px; }}
    .stat {{ background: white; border-radius: 12px; 
      padding: 20px; border: 1px solid #e2e8f0; 
      text-align: center; }}
    .stat-num {{ font-size: 32px; font-weight: 700; }}
    .stat-label {{ font-size: 13px; color: #64748b; 
      margin-top: 4px; }}
    .section {{ background: white; border-radius: 12px; 
      padding: 24px; margin-bottom: 20px; 
      border: 1px solid #e2e8f0; }}
    .section h2 {{ font-size: 16px; font-weight: 600; 
      margin-bottom: 16px; display: flex; 
      align-items: center; gap: 8px; }}
    table {{ width: 100%; border-collapse: collapse; 
      font-size: 13px; }}
    th {{ text-align: left; padding: 10px 12px; 
      background: #f8fafc; color: #64748b; 
      font-weight: 600; font-size: 12px; 
      text-transform: uppercase; letter-spacing: 0.05em; 
      border-bottom: 1px solid #e2e8f0; }}
    td {{ padding: 12px; border-bottom: 1px solid #f1f5f9; 
      vertical-align: middle; }}
    tr:last-child td {{ border-bottom: none; }}
    .footer {{ text-align: center; color: #94a3b8; 
      font-size: 13px; margin-top: 32px; }}
    .footer a {{ color: #3b82f6; text-decoration: none; }}
    .badge {{ display: inline-block; padding: 4px 12px; 
      border-radius: 20px; font-size: 12px; 
      font-weight: 600; }}
  </style>
</head>
<body>
  <div class='container'>
    <div class='header'>
      <h1>🛡️ GetVouch Security Report</h1>
      <p>Generated: {now} &nbsp;|&nbsp; 
         Files scanned: {files_scanned} &nbsp;|&nbsp; 
         Version: v0.3.0</p>
    </div>

    <div class='score-box'>
      <div class='score-number'>{score}</div>
      <div class='score-label'>Vibe Score / 100</div>
      <div class='score-rating'>{rating}</div>
    </div>

    <div class='stats'>
      <div class='stat'>
        <div class='stat-num' style='color:#ef4444;'>
          {len(secret_findings)}</div>
        <div class='stat-label'>Exposed Secrets</div>
      </div>
      <div class='stat'>
        <div class='stat-num' style='color:#f97316;'>
          {len(auth_findings)}</div>
        <div class='stat-label'>Auth Risks</div>
      </div>
      <div class='stat'>
        <div class='stat-num' style='color:#eab308;'>
          {len(sql_findings)}</div>
        <div class='stat-label'>SQL Risks</div>
      </div>
    </div>

    <div class='section'>
      <h2>🔑 Exposed Secrets</h2>
      <table>
        <tr>
          <th>Type</th><th>File</th>
          <th>Line</th><th>Code</th>
        </tr>
        {build_rows(secret_findings, '#ef4444')}
      </table>
    </div>

    <div class='section'>
      <h2>🔐 Client-Side Auth Risks</h2>
      <table>
        <tr>
          <th>Type</th><th>File</th>
          <th>Line</th><th>Code</th>
        </tr>
        {build_rows(auth_findings, '#f97316')}
      </table>
    </div>

    <div class='section'>
      <h2>💉 SQL Injection Risks</h2>
      <table>
        <tr>
          <th>Type</th><th>File</th>
          <th>Line</th><th>Code</th>
        </tr>
        {build_rows(sql_findings, '#eab308')}
      </table>
    </div>

    <div class='footer'>
      <p>Powered by <a href='https://getvouch.ai'>GetVouch</a> 
      — Security for the AI Era</p>
      <p style='margin-top:8px;'>Want a human to review 
      these results? Open an Issue on GitHub for a free audit.</p>
    </div>
  </div>
</body>
</html>"""
    return html


def run_vouch():
    print("")
    print("🛡️  GetVouch v0.3.0 — The Integrity Layer")
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
                                    "type": label, "file": file_path,
                                    "line": line_num,
                                    "snippet": line.strip()[:80]
                                })
                        if is_frontend:
                            for label, pattern in auth_patterns.items():
                                if re.search(pattern, line):
                                    auth_findings.append({
                                        "type": label, "file": file_path,
                                        "line": line_num,
                                        "snippet": line.strip()[:80]
                                    })
                        for label, pattern in sql_patterns.items():
                            if re.search(pattern, line):
                                sql_findings.append({
                                    "type": label, "file": file_path,
                                    "line": line_num,
                                    "snippet": line.strip()[:80]
                                })
            except Exception:
                pass

    total = (len(secret_findings) + 
             len(auth_findings) + len(sql_findings))
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

    print(f"📂 Files scanned: {files_scanned}")
    print(f"🔑 Secrets found: {len(secret_findings)}")
    print(f"🔐 Auth risks: {len(auth_findings)}")
    print(f"💉 SQL risks: {len(sql_findings)}")
    print("")
    print(f"Your Vibe Score: {score}/100 — {rating}")
    print("")
    print("📄 Generating your HTML report...")

    report_html = generate_html_report(
        secret_findings, auth_findings,
        sql_findings, files_scanned, score, rating
    )

    report_path = "getvouch-report.html"
    with open(report_path, "w") as f:
        f.write(report_html)

    print(f"✅ Report saved: {report_path}")
    print("   Open it in your browser to see your full results.")
    print("")
    print("─" * 60)
    print("Powered by GetVouch v0.3.0 — Security for the AI Era")
    print("")


if __name__ == "__main__":
    run_vouch()
