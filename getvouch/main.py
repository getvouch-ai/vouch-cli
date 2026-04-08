import os
import re
import datetime

def generate_html_report(secret_findings, auth_findings,
                          sql_findings, files_scanned, score, rating):

    now = datetime.datetime.now().strftime("%B %d, %Y at %H:%M")
    date_short = datetime.datetime.now().strftime("%B %d, %Y")
    total = (len(secret_findings) +
             len(auth_findings) + len(sql_findings))

    if score == 100:
        score_color = "#16a34a"
        risk_level = "LOW"
        risk_bg = "#f0fdf4"
        risk_border = "#16a34a"
        exec_summary = (
            "No critical security vulnerabilities were detected "
            "in this codebase. The application demonstrates "
            "adequate security hygiene for its current stage. "
            "Continued monitoring is recommended as the "
            "codebase evolves."
        )
    elif score >= 80:
        score_color = "#ca8a04"
        risk_level = "MODERATE"
        risk_bg = "#fefce8"
        risk_border = "#ca8a04"
        exec_summary = (
            "Minor security concerns were identified that "
            "require attention before production deployment. "
            "No critical vulnerabilities were found, however "
            "the issues identified represent potential entry "
            "points that should be remediated promptly."
        )
    elif score >= 50:
        score_color = "#dc2626"
        risk_level = "HIGH"
        risk_bg = "#fef2f2"
        risk_border = "#dc2626"
        exec_summary = (
            "Significant security vulnerabilities have been "
            "identified in this codebase. These issues present "
            "material risk to the organization including "
            "potential data exposure, unauthorized access, "
            "and financial liability. Immediate remediation "
            "is strongly recommended prior to any production "
            "deployment or user onboarding."
        )
    else:
        score_color = "#7f1d1d"
        risk_level = "CRITICAL"
        risk_bg = "#fef2f2"
        risk_border = "#7f1d1d"
        exec_summary = (
            "Critical security vulnerabilities have been "
            "identified that pose an immediate and severe risk "
            "to the organization. Exposed credentials, "
            "authentication bypasses, or injection "
            "vulnerabilities were detected that could result "
            "in complete system compromise, data breach, or "
            "significant financial loss. This application "
            "should not be deployed or exposed to users until "
            "all critical findings are resolved."
        )

    def severity_badge(level, color, bg):
        return (
            f"<span style='background:{bg};color:{color};"
            f"padding:3px 12px;border-radius:4px;"
            f"font-size:11px;font-weight:700;"
            f"letter-spacing:0.05em;border:1px solid {color};'>"
            f"{level}</span>"
        )

    def build_findings_table(findings, category, severity,
                              sev_color, sev_bg, description):
        if not findings:
            return f"""
        <div style='margin-bottom:32px;'>
          <h3 style='font-size:14px;font-weight:600;
            color:#374151;margin-bottom:12px;
            padding-bottom:8px;
            border-bottom:1px solid #e5e7eb;'>
            {category}
          </h3>
          <div style='background:#f9fafb;border-radius:6px;
            padding:16px;text-align:center;
            color:#6b7280;font-size:13px;'>
            No issues detected in this category.
          </div>
        </div>"""

        rows = ""
        for i, f in enumerate(findings, 1):
            rows += f"""
              <tr style='border-bottom:1px solid #f3f4f6;'>
                <td style='padding:12px 16px;font-size:13px;
                  color:#111827;font-weight:500;
                  vertical-align:top;'>{i}</td>
                <td style='padding:12px 16px;vertical-align:top;'>
                  {severity_badge(severity, sev_color, sev_bg)}
                </td>
                <td style='padding:12px 16px;font-size:13px;
                  color:#374151;vertical-align:top;'>
                  {f['type']}
                </td>
                <td style='padding:12px 16px;font-size:12px;
                  color:#6b7280;font-family:monospace;
                  vertical-align:top;'>{f['file']}</td>
                <td style='padding:12px 16px;font-size:12px;
                  color:#374151;text-align:center;
                  vertical-align:top;'>{f['line']}</td>
              </tr>"""

        return f"""
        <div style='margin-bottom:32px;'>
          <h3 style='font-size:14px;font-weight:600;
            color:#374151;margin-bottom:4px;
            padding-bottom:8px;
            border-bottom:1px solid #e5e7eb;'>
            {category}
          </h3>
          <p style='font-size:12px;color:#6b7280;
            margin-bottom:12px;'>{description}</p>
          <table style='width:100%;border-collapse:collapse;
            font-size:13px;'>
            <thead>
              <tr style='background:#f9fafb;'>
                <th style='padding:10px 16px;text-align:left;
                  font-size:11px;font-weight:600;color:#6b7280;
                  text-transform:uppercase;
                  letter-spacing:0.05em;width:40px;'>#</th>
                <th style='padding:10px 16px;text-align:left;
                  font-size:11px;font-weight:600;color:#6b7280;
                  text-transform:uppercase;
                  letter-spacing:0.05em;'>Severity</th>
                <th style='padding:10px 16px;text-align:left;
                  font-size:11px;font-weight:600;color:#6b7280;
                  text-transform:uppercase;
                  letter-spacing:0.05em;'>Finding</th>
                <th style='padding:10px 16px;text-align:left;
                  font-size:11px;font-weight:600;color:#6b7280;
                  text-transform:uppercase;
                  letter-spacing:0.05em;'>File</th>
                <th style='padding:10px 16px;text-align:center;
                  font-size:11px;font-weight:600;color:#6b7280;
                  text-transform:uppercase;
                  letter-spacing:0.05em;'>Line</th>
              </tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
        </div>"""

    remediation_rows = ""
    all_findings = (
        [("CRITICAL", f) for f in secret_findings] +
        [("HIGH", f) for f in auth_findings] +
        [("MEDIUM", f) for f in sql_findings]
    )

    remediation_map = {
        "OpenAI API Key": (
            "Move this key to an environment variable immediately. "
            "Revoke the exposed key in your OpenAI dashboard "
            "and generate a new one."
        ),
        "Anthropic API Key": (
            "Revoke this key immediately in your Anthropic console. "
            "Store replacement keys in environment variables only."
        ),
        "Stripe Secret Key": (
            "Revoke this key in your Stripe dashboard immediately. "
            "This key has billing privileges and must never appear "
            "in source code."
        ),
        "Stripe Test Key": (
            "Move to environment variables. Even test keys expose "
            "your integration architecture to attackers."
        ),
        "AWS Access Key": (
            "Deactivate this key in AWS IAM immediately. "
            "AWS keys exposed publicly are exploited within minutes "
            "by automated scanners."
        ),
        "GitHub Token": (
            "Revoke this token in GitHub Settings immediately. "
            "Replace with a scoped token stored as an "
            "environment secret."
        ),
        "Google API Key": (
            "Restrict or revoke this key in Google Cloud Console. "
            "Apply API restrictions to limit its scope."
        ),
        "Client-side admin check": (
            "Move all authorization checks to the server side. "
            "Never trust client-sent role or permission values. "
            "Verify on every API request."
        ),
        "Client-side payment check": (
            "Payment verification must occur server-side on "
            "every request. Client-side checks can be bypassed "
            "with browser developer tools in seconds."
        ),
        "localStorage auth token": (
            "Avoid storing sensitive tokens in localStorage. "
            "Use httpOnly cookies which are inaccessible "
            "to JavaScript."
        ),
        "SQL Injection risk": (
            "Replace string concatenation in SQL queries with "
            "parameterized statements or a trusted ORM. "
            "This is the most exploited vulnerability class "
            "on the web."
        ),
        "Generic Secret": (
            "Remove hardcoded credentials from source code. "
            "Use environment variables or a secrets manager "
            "such as Doppler or AWS Secrets Manager."
        ),
    }

    for sev, f in all_findings:
        remedy = remediation_map.get(
            f['type'],
            "Review this finding and apply appropriate "
            "security controls."
        )
        if sev == "CRITICAL":
            sev_color = "#dc2626"
            sev_bg = "#fef2f2"
        elif sev == "HIGH":
            sev_color = "#ea580c"
            sev_bg = "#fff7ed"
        else:
            sev_color = "#ca8a04"
            sev_bg = "#fefce8"

        remediation_rows += f"""
          <tr style='border-bottom:1px solid #f3f4f6;'>
            <td style='padding:14px 16px;vertical-align:top;'>
              {severity_badge(sev, sev_color, sev_bg)}
            </td>
            <td style='padding:14px 16px;font-size:13px;
              color:#111827;font-weight:500;
              vertical-align:top;'>{f['type']}</td>
            <td style='padding:14px 16px;font-size:13px;
              color:#374151;vertical-align:top;
              line-height:1.6;'>{remedy}</td>
          </tr>"""

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='UTF-8'>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>GetVouch Security Assessment — {date_short}</title>
  <style>
    * {{ box-sizing:border-box;margin:0;padding:0; }}
    body {{
      font-family:-apple-system,BlinkMacSystemFont,
        'Segoe UI',Arial,sans-serif;
      background:#f3f4f6;
      color:#111827;
      font-size:14px;
      line-height:1.6;
    }}
    .page {{
      max-width:960px;
      margin:40px auto;
      background:white;
      border-radius:8px;
      overflow:hidden;
      border:1px solid #e5e7eb;
    }}
    .cover {{
      background:#0f172a;
      padding:48px;
      color:white;
    }}
    .cover-top {{
      display:flex;
      justify-content:space-between;
      align-items:flex-start;
      margin-bottom:48px;
    }}
    .logo {{
      font-size:18px;
      font-weight:700;
      color:white;
      letter-spacing:-0.02em;
    }}
    .logo span {{ color:#60a5fa; }}
    .confidential {{
      font-size:11px;
      color:#94a3b8;
      letter-spacing:0.1em;
      text-transform:uppercase;
      border:1px solid #334155;
      padding:4px 12px;
      border-radius:4px;
    }}
    .cover h1 {{
      font-size:32px;
      font-weight:700;
      color:white;
      margin-bottom:8px;
      line-height:1.2;
    }}
    .cover-sub {{
      font-size:16px;
      color:#94a3b8;
      margin-bottom:32px;
    }}
    .cover-meta {{
      display:grid;
      grid-template-columns:repeat(3,1fr);
      gap:24px;
      border-top:1px solid #1e293b;
      padding-top:32px;
    }}
    .meta-item label {{
      font-size:11px;
      color:#64748b;
      text-transform:uppercase;
      letter-spacing:0.08em;
      display:block;
      margin-bottom:4px;
    }}
    .meta-item value {{
      font-size:14px;
      color:#e2e8f0;
      font-weight:500;
    }}
    .body {{ padding:48px; }}
    .section {{ margin-bottom:48px; }}
    .section-label {{
      font-size:11px;
      font-weight:700;
      color:#6b7280;
      text-transform:uppercase;
      letter-spacing:0.1em;
      margin-bottom:16px;
      padding-bottom:8px;
      border-bottom:2px solid #f3f4f6;
    }}
    .exec-box {{
      background:{risk_bg};
      border:1px solid {risk_border};
      border-left:4px solid {risk_border};
      border-radius:6px;
      padding:20px 24px;
      margin-bottom:24px;
    }}
    .exec-box p {{
      font-size:14px;
      color:#374151;
      line-height:1.7;
    }}
    .score-grid {{
      display:grid;
      grid-template-columns:1fr 3fr;
      gap:24px;
      margin-bottom:32px;
    }}
    .score-card {{
      background:#0f172a;
      border-radius:8px;
      padding:24px;
      text-align:center;
    }}
    .score-number {{
      font-size:56px;
      font-weight:700;
      color:{score_color};
      line-height:1;
    }}
    .score-denom {{
      font-size:18px;
      color:#475569;
    }}
    .score-label {{
      font-size:11px;
      color:#64748b;
      text-transform:uppercase;
      letter-spacing:0.08em;
      margin-top:8px;
    }}
    .metrics-grid {{
      display:grid;
      grid-template-columns:repeat(3,1fr);
      gap:12px;
    }}
    .metric {{
      border:1px solid #e5e7eb;
      border-radius:6px;
      padding:16px;
      text-align:center;
    }}
    .metric-num {{
      font-size:28px;
      font-weight:700;
    }}
    .metric-label {{
      font-size:11px;
      color:#6b7280;
      margin-top:4px;
      text-transform:uppercase;
      letter-spacing:0.05em;
    }}
    .risk-banner {{
      background:{risk_bg};
      border:1px solid {risk_border};
      border-radius:6px;
      padding:12px 20px;
      display:flex;
      align-items:center;
      justify-content:space-between;
      margin-top:12px;
    }}
    .risk-label {{
      font-size:12px;
      color:#6b7280;
      text-transform:uppercase;
      letter-spacing:0.08em;
    }}
    .risk-value {{
      font-size:16px;
      font-weight:700;
      color:{risk_border};
    }}
    .footer {{
      background:#f9fafb;
      border-top:1px solid #e5e7eb;
      padding:24px 48px;
      display:flex;
      justify-content:space-between;
      align-items:center;
    }}
    .footer-brand {{
      font-size:13px;
      color:#6b7280;
    }}
    .footer-brand strong {{
      color:#111827;
    }}
    .footer-note {{
      font-size:11px;
      color:#9ca3af;
      text-align:right;
    }}
    .print-btn {{
      display:block;
      text-align:center;
      margin:32px auto 0;
    }}
    .print-btn button {{
      background:#0f172a;
      color:white;
      border:none;
      padding:14px 40px;
      border-radius:6px;
      font-size:14px;
      font-weight:600;
      cursor:pointer;
      font-family:inherit;
      letter-spacing:0.02em;
    }}
    .print-btn p {{
      font-size:11px;
      color:#9ca3af;
      margin-top:8px;
    }}
    @media print {{
      body {{ background:white; }}
      .page {{
        margin:0;
        border:none;
        border-radius:0;
      }}
      .print-btn {{ display:none; }}
    }}
  </style>
</head>
<body>
  <div class='page'>

    <div class='cover'>
      <div class='cover-top'>
        <div class='logo'>Get<span>Vouch</span></div>
        <div class='confidential'>Confidential</div>
      </div>
      <h1>Security Assessment Report</h1>
      <div class='cover-sub'>
        AI-Generated Code Security Analysis
      </div>
      <div class='cover-meta'>
        <div class='meta-item'>
          <label>Report Date</label>
          <value>{date_short}</value>
        </div>
        <div class='meta-item'>
          <label>Assessment Type</label>
          <value>Automated Static Analysis</value>
        </div>
        <div class='meta-item'>
          <label>Prepared By</label>
          <value>GetVouch Security</value>
        </div>
        <div class='meta-item'>
          <label>Files Analyzed</label>
          <value>{files_scanned}</value>
        </div>
        <div class='meta-item'>
          <label>Total Findings</label>
          <value>{total}</value>
        </div>
        <div class='meta-item'>
          <label>Overall Risk</label>
          <value style='color:{score_color};'>{risk_level}</value>
        </div>
      </div>
    </div>

    <div class='body'>

      <div class='section'>
        <div class='section-label'>
          01 — Executive Summary
        </div>
        <div class='exec-box'>
          <p>{exec_summary}</p>
        </div>
        <p style='font-size:13px;color:#6b7280;line-height:1.7;'>
          This assessment was performed using GetVouch automated
          static analysis, scanning {files_scanned} files for
          exposed credentials, authentication vulnerabilities,
          and injection risks. All findings represent real
          patterns identified in the submitted codebase and
          should be reviewed by a qualified developer prior
          to remediation.
        </p>
      </div>

      <div class='section'>
        <div class='section-label'>
          02 — Risk Score
        </div>
        <div class='score-grid'>
          <div class='score-card'>
            <div class='score-number'>{score}</div>
            <div class='score-denom'>/100</div>
            <div class='score-label'>Security Score</div>
          </div>
          <div>
            <div class='metrics-grid'>
              <div class='metric'>
                <div class='metric-num'
                  style='color:#dc2626;'>
                  {len(secret_findings)}
                </div>
                <div class='metric-label'>
                  Exposed Secrets
                </div>
              </div>
              <div class='metric'>
                <div class='metric-num'
                  style='color:#ea580c;'>
                  {len(auth_findings)}
                </div>
                <div class='metric-label'>
                  Auth Vulnerabilities
                </div>
              </div>
              <div class='metric'>
                <div class='metric-num'
                  style='color:#ca8a04;'>
                  {len(sql_findings)}
                </div>
                <div class='metric-label'>
                  Injection Risks
                </div>
              </div>
            </div>
            <div class='risk-banner'>
              <span class='risk-label'>Overall Risk Level</span>
              <span class='risk-value'>{risk_level} RISK</span>
            </div>
          </div>
        </div>
      </div>

      <div class='section'>
        <div class='section-label'>
          03 — Detailed Findings
        </div>
        {build_findings_table(
            secret_findings,
            "Exposed Credentials and API Keys",
            "CRITICAL", "#dc2626", "#fef2f2",
            "Hardcoded credentials discovered in source files. "
            "These must be rotated and removed immediately as "
            "they grant unauthorized access to third-party "
            "services and infrastructure."
        )}
        {build_findings_table(
            auth_findings,
            "Client-Side Authentication Vulnerabilities",
            "HIGH", "#ea580c", "#fff7ed",
            "Authorization logic detected in client-side code. "
            "Authentication checks performed in the browser "
            "can be bypassed by any user with developer tools, "
            "enabling unauthorized access to protected features."
        )}
        {build_findings_table(
            sql_findings,
            "SQL Injection Vulnerabilities",
            "MEDIUM", "#ca8a04", "#fefce8",
            "User-controlled input detected in database queries. "
            "This pattern enables attackers to manipulate "
            "database operations, potentially leading to "
            "data theft or destruction."
        )}
      </div>

      <div class='section'>
        <div class='section-label'>
          04 — Remediation Guidance
        </div>
        <p style='font-size:13px;color:#6b7280;
          margin-bottom:16px;line-height:1.7;'>
          The following remediation steps are recommended
          in order of priority. Critical findings should be
          addressed before any production deployment.
        </p>
        <table style='width:100%;border-collapse:collapse;'>
          <thead>
            <tr style='background:#f9fafb;'>
              <th style='padding:10px 16px;text-align:left;
                font-size:11px;font-weight:600;color:#6b7280;
                text-transform:uppercase;
                letter-spacing:0.05em;width:100px;'>
                Priority
              </th>
              <th style='padding:10px 16px;text-align:left;
                font-size:11px;font-weight:600;color:#6b7280;
                text-transform:uppercase;
                letter-spacing:0.05em;width:200px;'>
                Finding
              </th>
              <th style='padding:10px 16px;text-align:left;
                font-size:11px;font-weight:600;color:#6b7280;
                text-transform:uppercase;
                letter-spacing:0.05em;'>
                Recommended Action
              </th>
            </tr>
          </thead>
          <tbody>
            {remediation_rows if remediation_rows else
             "<tr><td colspan='3' style='padding:16px;text-align:center;color:#16a34a;'>No remediation required — codebase is clean.</td></tr>"}
          </tbody>
        </table>
      </div>

      <div class='section'
        style='background:#f9fafb;border-radius:8px;
        padding:24px;border:1px solid #e5e7eb;'>
        <div class='section-label'>
          05 — Disclaimer
        </div>
        <p style='font-size:12px;color:#6b7280;line-height:1.8;'>
          This report was generated by GetVouch automated
          static analysis tools. It represents findings
          detected through pattern matching and heuristic
          analysis of source code files. This report does
          not constitute a comprehensive penetration test
          or security audit. GetVouch recommends that all
          findings be reviewed by a qualified security
          professional prior to remediation. False positives
          may occur. GetVouch is not liable for decisions
          made based solely on this report.
        </p>
      </div>

      <div class='print-btn'>
        <button onclick='window.print()'>
          Download as PDF
        </button>
        <p>
          In the print dialog — select "Save as PDF"
        </p>
      </div>

    </div>

    <div class='footer'>
      <div class='footer-brand'>
        Prepared by <strong>GetVouch Security</strong>
        &nbsp;|&nbsp; getvouch.ai
      </div>
      <div class='footer-note'>
        GetVouch v0.3.1 &nbsp;|&nbsp;
        Generated {now}<br>
        This document is confidential
      </div>
    </div>

  </div>
</body>
</html>"""
    return html


def run_vouch():
    print("")
    print("  GetVouch v0.3.1 — Security Assessment")
    print("  Scanning codebase for vulnerabilities...")
    print("  " + "-" * 50)

    secret_patterns = {
        "OpenAI API Key":    r"sk-[a-zA-Z0-9]{32,}",
        "Anthropic API Key": r"sk-ant-[a-zA-Z0-9\-]{32,}",
        "Google API Key":    r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24,}",
        "Stripe Test Key":   r"sk_test_[0-9a-zA-Z]{24,}",
        "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
        "GitHub Token":      r"ghp_[a-zA-Z0-9]{36}",
        "Slack Token":       r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
        "Twilio API Key":    r"SK[0-9a-fA-F]{32}",
        "Generic Secret":    r"(?i)(secret|password|passwd|api_key)\s*=\s*['\"][^'\"]{8,}['\"]",
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
    ".venv", "venv", "build", "dist",
    "getvouch-report.html"
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
                with open(file_path, "r",
                          encoding="utf-8",
                          errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        for label, pattern in (
                                secret_patterns.items()):
                            if re.search(pattern, line):
                                secret_findings.append({
                                    "type": label,
                                    "file": file_path,
                                    "line": line_num,
                                    "snippet": line.strip()[:80]
                                })
                        if is_frontend:
                            for label, pattern in (
                                    auth_patterns.items()):
                                if re.search(pattern, line):
                                    auth_findings.append({
                                        "type": label,
                                        "file": file_path,
                                        "line": line_num,
                                        "snippet": line.strip()[:80]
                                    })
                         if not file.endswith(".py"):
          for label, pattern in (
                  sql_patterns.items()):
              if re.search(pattern, line):
                                sql_findings.append({
                                    "type": label,
                                    "file": file_path,
                                    "line": line_num,
                                    "snippet": line.strip()[:80]
                                })
            except Exception:
                pass

    total = (len(secret_findings) +
             len(auth_findings) + len(sql_findings))
    score = max(0, 100 -
                (len(secret_findings) * 20) -
                (len(auth_findings) * 15) -
                (len(sql_findings) * 10))

    if score == 100:
        rating = "CLEAN - No issues detected"
    elif score >= 80:
        rating = "LOW RISK - Minor issues found"
    elif score >= 50:
        rating = "HIGH RISK - Fix before shipping"
    else:
        rating = "CRITICAL - Do not ship"

    print(f"  Files scanned    : {files_scanned}")
    print(f"  Secrets found    : {len(secret_findings)}")
    print(f"  Auth risks       : {len(auth_findings)}")
    print(f"  SQL risks        : {len(sql_findings)}")
    print(f"  Security Score   : {score}/100")
    print(f"  Assessment       : {rating}")
    print("")
    print("  Generating executive report...")

    report_html = generate_html_report(
        secret_findings, auth_findings,
        sql_findings, files_scanned, score, rating
    )

    report_path = "getvouch-report.html"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_html)

    print(f"  Report saved     : {report_path}")
    print("  Open in browser to view and download as PDF.")
    print("")
    print("  " + "-" * 50)
    print("  GetVouch v0.3.1 — getvouch.ai")
    print("")


if __name__ == "__main__":
    run_vouch()

