import os
import re
import sys
import datetime
import json


def generate_html_report(findings_data, files_scanned,
                         score, rating, risk_level):

    now = datetime.datetime.now().strftime("%B %d, %Y at %H:%M")
    date_short = datetime.datetime.now().strftime("%B %d, %Y")

    secret_findings = findings_data["secrets"]
    auth_findings = findings_data["auth"]
    sql_findings = findings_data["sql"]
    cors_findings = findings_data["cors"]
    env_findings = findings_data["env"]
    dep_findings = findings_data["dependencies"]
    val_findings = findings_data["validation"]
    idor_findings = findings_data["idor"]

    total = sum(len(v) for v in findings_data.values())

    color_map = {
        "LOW": ("#16a34a", "#f0fdf4", "#16a34a"),
        "MODERATE": ("#ca8a04", "#fefce8", "#ca8a04"),
        "HIGH": ("#dc2626", "#fef2f2", "#dc2626"),
        "CRITICAL": ("#7f1d1d", "#fef2f2", "#991b1b"),
    }
    score_color, risk_bg, risk_border = color_map.get(
        risk_level, color_map["HIGH"])

    summary_map = {
        "LOW": (
            "No critical security vulnerabilities were detected. "
            "The application demonstrates adequate security hygiene. "
            "Continued monitoring is recommended as the codebase evolves."
        ),
        "MODERATE": (
            "Minor security concerns were identified requiring attention "
            "before production deployment. No critical vulnerabilities "
            "were found, however the issues identified represent "
            "potential entry points that should be remediated promptly."
        ),
        "HIGH": (
            "Significant security vulnerabilities have been identified. "
            "These issues present material risk including potential data "
            "exposure, unauthorized access, and financial liability. "
            "Immediate remediation is strongly recommended prior to "
            "any production deployment or user onboarding."
        ),
        "CRITICAL": (
            "Critical security vulnerabilities pose an immediate and "
            "severe risk to the organization. Exposed credentials, "
            "authentication bypasses, or injection vulnerabilities "
            "were detected that could result in complete system "
            "compromise, data breach, or significant financial loss. "
            "This application must not be deployed until all critical "
            "findings are resolved."
        ),
    }
    exec_summary = summary_map.get(risk_level, summary_map["HIGH"])

    def badge(level, color, bg):
        return (
            f"<span style='background:{bg};color:{color};"
            f"padding:3px 10px;border-radius:4px;font-size:11px;"
            f"font-weight:700;letter-spacing:0.05em;"
            f"border:1px solid {color};'>{level}</span>"
        )

    def build_table(findings, title, sev, sc, sb, desc):
        if not findings:
            return (
                f"<div style='margin-bottom:28px;'>"
                f"<h3 style='font-size:14px;font-weight:600;"
                f"color:#374151;margin-bottom:8px;padding-bottom:8px;"
                f"border-bottom:1px solid #e5e7eb;'>{title}</h3>"
                f"<div style='background:#f9fafb;border-radius:6px;"
                f"padding:14px;text-align:center;color:#16a34a;"
                f"font-size:13px;font-weight:500;'>"
                f"No issues detected.</div></div>"
            )
        rows = ""
        for i, f in enumerate(findings, 1):
            snippet = f.get("snippet", "")
            rows += (
                f"<tr style='border-bottom:1px solid #f3f4f6;'>"
                f"<td style='padding:10px 14px;font-size:13px;"
                f"color:#6b7280;vertical-align:top;'>{i}</td>"
                f"<td style='padding:10px 14px;vertical-align:top;'>"
                f"{badge(sev, sc, sb)}</td>"
                f"<td style='padding:10px 14px;font-size:13px;"
                f"color:#111827;font-weight:500;vertical-align:top;'>"
                f"{f['type']}</td>"
                f"<td style='padding:10px 14px;font-size:11px;"
                f"color:#6b7280;font-family:monospace;"
                f"vertical-align:top;max-width:200px;"
                f"word-break:break-all;'>{f['file']}</td>"
                f"<td style='padding:10px 14px;font-size:12px;"
                f"color:#374151;text-align:center;"
                f"vertical-align:top;'>{f.get('line', '-')}</td>"
                f"<td style='padding:10px 14px;font-size:11px;"
                f"color:#6b7280;font-family:monospace;"
                f"vertical-align:top;max-width:220px;"
                f"overflow:hidden;text-overflow:ellipsis;"
                f"white-space:nowrap;'>{snippet}</td>"
                f"</tr>"
            )
        return (
            f"<div style='margin-bottom:28px;'>"
            f"<h3 style='font-size:14px;font-weight:600;"
            f"color:#374151;margin-bottom:4px;padding-bottom:8px;"
            f"border-bottom:1px solid #e5e7eb;'>{title}</h3>"
            f"<p style='font-size:12px;color:#6b7280;"
            f"margin-bottom:10px;line-height:1.6;'>{desc}</p>"
            f"<div style='overflow-x:auto;'>"
            f"<table style='width:100%;border-collapse:collapse;"
            f"font-size:13px;min-width:600px;'>"
            f"<thead><tr style='background:#f9fafb;'>"
            f"<th style='padding:8px 14px;text-align:left;"
            f"font-size:11px;font-weight:600;color:#6b7280;"
            f"text-transform:uppercase;letter-spacing:0.05em;"
            f"width:30px;'>#</th>"
            f"<th style='padding:8px 14px;text-align:left;"
            f"font-size:11px;font-weight:600;color:#6b7280;"
            f"text-transform:uppercase;letter-spacing:0.05em;"
            f"width:80px;'>Severity</th>"
            f"<th style='padding:8px 14px;text-align:left;"
            f"font-size:11px;font-weight:600;color:#6b7280;"
            f"text-transform:uppercase;letter-spacing:0.05em;'>"
            f"Finding</th>"
            f"<th style='padding:8px 14px;text-align:left;"
            f"font-size:11px;font-weight:600;color:#6b7280;"
            f"text-transform:uppercase;letter-spacing:0.05em;'>"
            f"File</th>"
            f"<th style='padding:8px 14px;text-align:center;"
            f"font-size:11px;font-weight:600;color:#6b7280;"
            f"text-transform:uppercase;letter-spacing:0.05em;"
            f"width:50px;'>Line</th>"
            f"<th style='padding:8px 14px;text-align:left;"
            f"font-size:11px;font-weight:600;color:#6b7280;"
            f"text-transform:uppercase;letter-spacing:0.05em;'>"
            f"Code</th>"
            f"</tr></thead>"
            f"<tbody>{rows}</tbody>"
            f"</table></div></div>"
        )

    remediation_map = {
        "OpenAI API Key": (
            "CRITICAL",
            "Revoke this key immediately in your OpenAI dashboard. "
            "Move to environment variables using process.env.OPENAI_KEY."
        ),
        "Anthropic API Key": (
            "CRITICAL",
            "Revoke in Anthropic console immediately. "
            "Use environment variables only."
        ),
        "Stripe Secret Key": (
            "CRITICAL",
            "Revoke in Stripe dashboard immediately. "
            "This key controls billing and must never appear in code."
        ),
        "Stripe Test Key": (
            "HIGH",
            "Move to environment variables. "
            "Test keys still expose your integration architecture."
        ),
        "Stripe Publishable Key": (
            "MEDIUM",
            "Publishable keys are less sensitive but should still "
            "be stored in environment variables as best practice."
        ),
        "AWS Access Key": (
            "CRITICAL",
            "Deactivate in AWS IAM immediately. "
            "AWS keys are exploited within minutes by automated scanners."
        ),
        "GitHub Token": (
            "CRITICAL",
            "Revoke in GitHub Settings immediately. "
            "Replace with a scoped token stored as a secret."
        ),
        "Google API Key": (
            "HIGH",
            "Restrict or revoke in Google Cloud Console. "
            "Apply API restrictions to limit its scope."
        ),
        "Firebase API Key": (
            "HIGH",
            "Firebase keys are semi-public but should be restricted "
            "in Firebase console to your domain only."
        ),
        "Firebase Service Account": (
            "CRITICAL",
            "Revoke this service account key in Firebase console. "
            "Service account keys grant admin access to your database."
        ),
        "SendGrid API Key": (
            "HIGH",
            "Revoke in SendGrid dashboard. "
            "Exposed email keys enable spam and phishing attacks."
        ),
        "Mailgun API Key": (
            "HIGH",
            "Revoke in Mailgun dashboard immediately. "
            "Store in environment variables."
        ),
        "Twilio Auth Token": (
            "CRITICAL",
            "Revoke in Twilio console. "
            "Auth tokens control your entire Twilio account."
        ),
        "Twilio API Key": (
            "HIGH",
            "Revoke in Twilio console and regenerate. "
            "Store in environment variables."
        ),
        "Shopify Secret Key": (
            "CRITICAL",
            "Revoke in Shopify Partner dashboard. "
            "This key controls your store integrations."
        ),
        "PayPal Client Secret": (
            "CRITICAL",
            "Revoke in PayPal Developer dashboard. "
            "This key controls payment processing."
        ),
        "MongoDB Connection String": (
            "CRITICAL",
            "Rotate your MongoDB credentials immediately. "
            "Move the full connection string to environment variables."
        ),
        "PostgreSQL Connection String": (
            "CRITICAL",
            "Rotate database credentials immediately. "
            "Never hardcode connection strings."
        ),
        "JWT Secret": (
            "CRITICAL",
            "Generate a new JWT secret immediately. "
            "Anyone with this secret can forge authentication tokens."
        ),
        "Generic Secret": (
            "HIGH",
            "Remove hardcoded credentials. "
            "Use environment variables or a secrets manager like Doppler."
        ),
        "Client-side admin check": (
            "CRITICAL",
            "Move all authorization checks to the server. "
            "Client-side checks can be disabled in DevTools instantly."
        ),
        "Client-side role check": (
            "CRITICAL",
            "Role verification must happen on the server on every request. "
            "Never trust client-sent role values."
        ),
        "Client-side payment check": (
            "CRITICAL",
            "Payment verification must be server-side on every request. "
            "This exact pattern shut down a SaaS in 72 hours."
        ),
        "Client-side auth bypass": (
            "CRITICAL",
            "Authentication checks in JavaScript can be bypassed. "
            "Verify authentication server-side on every protected endpoint."
        ),
        "localStorage auth token": (
            "HIGH",
            "localStorage is accessible to all JavaScript including "
            "injected scripts. Use httpOnly cookies for auth tokens."
        ),
        "SQL Injection risk": (
            "HIGH",
            "Replace string concatenation with parameterized queries "
            "or a trusted ORM. This is the most exploited "
            "web vulnerability class."
        ),
        "CORS wildcard": (
            "HIGH",
            "Replace origin:'*' with your specific allowed domains. "
            "Wildcard CORS allows any website to make authenticated "
            "requests to your API."
        ),
        "CORS misconfiguration": (
            "MEDIUM",
            "Review CORS configuration and restrict to known origins only."
        ),
        "Missing .gitignore": (
            "CRITICAL",
            "Create a .gitignore file immediately and add .env to it. "
            "Without this, your secret keys will be uploaded to GitHub."
        ),
        ".env not in .gitignore": (
            "CRITICAL",
            "Add .env to your .gitignore file immediately. "
            "Your environment file containing secrets will be "
            "committed to version control on your next git push."
        ),
        ".env.local not in .gitignore": (
            "HIGH",
            "Add .env.local to your .gitignore file."
        ),
        ".env.production not in .gitignore": (
            "CRITICAL",
            "Add .env.production to your .gitignore immediately. "
            "Production secrets must never reach version control."
        ),
        "Outdated dependency": (
            "MEDIUM",
            "Update this package to the latest version. "
            "Outdated dependencies are a common attack vector."
        ),
        "Missing input validation": (
            "HIGH",
            "Validate and sanitize all user input before processing. "
            "Install a validation library like joi, zod, or express-validator."
        ),
        "Direct object reference": (
            "HIGH",
            "Verify authorization on every request that accesses "
            "user data by ID. Never assume the requesting user "
            "owns the resource they are requesting."
        ),
        "Localhost URL in code": (
            "MEDIUM",
            "Replace hardcoded localhost URLs with environment variables. "
            "These will fail silently in production."
        ),
        "Twilio API Key": (
            "HIGH",
            "Revoke in Twilio console. Store in environment variables."
        ),
    }

    all_findings_for_remediation = (
        [("CRITICAL", "#dc2626", "#fef2f2", f)
         for f in secret_findings] +
        [("CRITICAL", "#dc2626", "#fef2f2", f)
         for f in auth_findings] +
        [("HIGH", "#ea580c", "#fff7ed", f)
         for f in sql_findings] +
        [("HIGH", "#ea580c", "#fff7ed", f)
         for f in cors_findings] +
        [("CRITICAL", "#dc2626", "#fef2f2", f)
         for f in env_findings] +
        [("MEDIUM", "#ca8a04", "#fefce8", f)
         for f in dep_findings] +
        [("HIGH", "#ea580c", "#fff7ed", f)
         for f in val_findings] +
        [("HIGH", "#ea580c", "#fff7ed", f)
         for f in idor_findings]
    )

    remediation_rows = ""
    for sev, sc, sb, f in all_findings_for_remediation:
        info = remediation_map.get(f["type"], None)
        if info:
            actual_sev, remedy = info
            sev_colors = {
                "CRITICAL": ("#dc2626", "#fef2f2"),
                "HIGH": ("#ea580c", "#fff7ed"),
                "MEDIUM": ("#ca8a04", "#fefce8"),
            }
            fc, fb = sev_colors.get(actual_sev,
                                    ("#6b7280", "#f9fafb"))
        else:
            actual_sev = sev
            fc, fb = sc, sb
            remedy = ("Review this finding and apply "
                      "appropriate security controls.")
        remediation_rows += (
            f"<tr style='border-bottom:1px solid #f3f4f6;'>"
            f"<td style='padding:12px 14px;vertical-align:top;'>"
            f"{badge(actual_sev, fc, fb)}</td>"
            f"<td style='padding:12px 14px;font-size:13px;"
            f"color:#111827;font-weight:500;"
            f"vertical-align:top;'>{f['type']}</td>"
            f"<td style='padding:12px 14px;font-size:13px;"
            f"color:#374151;vertical-align:top;"
            f"line-height:1.6;'>{remedy}</td>"
            f"</tr>"
        )

    no_remedy = (
        "<tr><td colspan='3' style='padding:16px;"
        "text-align:center;color:#16a34a;font-weight:500;'>"
        "No remediation required — codebase is clean.</td></tr>"
    )

    coverage_items = [
        ("Exposed API Keys and Secrets", "20+ secret types",
         "#16a34a"),
        ("Client-Side Auth Vulnerabilities", "5 patterns",
         "#16a34a"),
        ("SQL Injection", "Pattern analysis", "#16a34a"),
        ("CORS Misconfiguration", "Wildcard detection",
         "#16a34a"),
        (".gitignore Safety", "Env file protection", "#16a34a"),
        ("Input Validation", "Missing sanitization", "#16a34a"),
        ("Insecure Direct Object Reference", "IDOR patterns",
         "#16a34a"),
        ("Dependency Check", "package.json analysis", "#16a34a"),
        ("Localhost URLs", "Production config check", "#16a34a"),
        ("MongoDB/PostgreSQL Strings", "Connection security",
         "#16a34a"),
    ]

    coverage_html = ""
    for item, detail, color in coverage_items:
        coverage_html += (
            f"<div style='display:flex;align-items:center;"
            f"gap:10px;padding:8px 0;"
            f"border-bottom:1px solid #f3f4f6;'>"
            f"<div style='width:8px;height:8px;border-radius:50%;"
            f"background:{color};flex-shrink:0;'></div>"
            f"<div style='flex:1;font-size:13px;color:#374151;'>"
            f"{item}</div>"
            f"<div style='font-size:12px;color:#6b7280;'>"
            f"{detail}</div>"
            f"</div>"
        )

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>GetVouch Security Assessment v1.0 — {date_short}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',
Arial,sans-serif;background:#f3f4f6;color:#111827;
font-size:14px;line-height:1.6;}}
.page{{max-width:1000px;margin:40px auto;background:white;
border-radius:8px;overflow:hidden;border:1px solid #e5e7eb;}}
.cover{{background:#0f172a;padding:48px;color:white;}}
.cover-top{{display:flex;justify-content:space-between;
align-items:flex-start;margin-bottom:48px;}}
.logo{{font-size:20px;font-weight:700;color:white;
letter-spacing:-0.02em;}}
.logo span{{color:#60a5fa;}}
.version{{font-size:11px;color:#64748b;margin-top:2px;
letter-spacing:0.05em;}}
.confidential{{font-size:11px;color:#94a3b8;
letter-spacing:0.1em;text-transform:uppercase;
border:1px solid #334155;padding:4px 12px;border-radius:4px;}}
.cover h1{{font-size:30px;font-weight:700;color:white;
margin-bottom:6px;line-height:1.2;}}
.cover-sub{{font-size:15px;color:#94a3b8;margin-bottom:32px;}}
.cover-meta{{display:grid;grid-template-columns:repeat(3,1fr);
gap:24px;border-top:1px solid #1e293b;padding-top:32px;}}
.meta-label{{font-size:10px;color:#64748b;text-transform:uppercase;
letter-spacing:0.08em;display:block;margin-bottom:4px;}}
.meta-value{{font-size:14px;color:#e2e8f0;font-weight:500;}}
.body{{padding:48px;}}
.section{{margin-bottom:44px;}}
.section-label{{font-size:10px;font-weight:700;color:#6b7280;
text-transform:uppercase;letter-spacing:0.12em;margin-bottom:14px;
padding-bottom:8px;border-bottom:2px solid #f3f4f6;}}
.exec-box{{background:{risk_bg};border:1px solid {risk_border};
border-left:4px solid {risk_border};border-radius:6px;
padding:18px 22px;margin-bottom:20px;}}
.score-grid{{display:grid;grid-template-columns:180px 1fr;
gap:20px;margin-bottom:28px;}}
.score-card{{background:#0f172a;border-radius:8px;
padding:24px 16px;text-align:center;}}
.score-number{{font-size:60px;font-weight:700;
color:{score_color};line-height:1;}}
.score-denom{{font-size:16px;color:#475569;}}
.score-lbl{{font-size:10px;color:#64748b;text-transform:uppercase;
letter-spacing:0.08em;margin-top:6px;}}
.metrics-grid{{display:grid;grid-template-columns:repeat(4,1fr);
gap:10px;margin-bottom:12px;}}
.metric{{border:1px solid #e5e7eb;border-radius:6px;
padding:14px 10px;text-align:center;}}
.metric-num{{font-size:24px;font-weight:700;}}
.metric-lbl{{font-size:10px;color:#6b7280;margin-top:3px;
text-transform:uppercase;letter-spacing:0.04em;line-height:1.3;}}
.risk-banner{{background:{risk_bg};border:1px solid {risk_border};
border-radius:6px;padding:10px 18px;display:flex;
align-items:center;justify-content:space-between;}}
.footer{{background:#f9fafb;border-top:1px solid #e5e7eb;
padding:20px 48px;display:flex;justify-content:space-between;
align-items:center;}}
.footer-brand{{font-size:13px;color:#6b7280;}}
.footer-note{{font-size:11px;color:#9ca3af;text-align:right;}}
.print-btn{{display:block;text-align:center;
margin:28px auto 0;}}
.print-btn button{{background:#0f172a;color:white;border:none;
padding:13px 36px;border-radius:6px;font-size:14px;
font-weight:600;cursor:pointer;font-family:inherit;
letter-spacing:0.02em;}}
.print-btn p{{font-size:11px;color:#9ca3af;margin-top:6px;}}
@media print{{
body{{background:white;}}
.page{{margin:0;border:none;border-radius:0;}}
.print-btn{{display:none;}}
}}
</style>
</head>
<body>
<div class='page'>
<div class='cover'>
<div class='cover-top'>
<div>
<div class='logo'>Get<span>Vouch</span></div>
<div class='version'>v1.0.0 — Enterprise Edition</div>
</div>
<div class='confidential'>Confidential</div>
</div>
<h1>Security Assessment Report</h1>
<div class='cover-sub'>
AI-Generated Code Security Analysis — Full Spectrum Scan
</div>
<div class='cover-meta'>
<div><span class='meta-label'>Report Date</span>
<span class='meta-value'>{date_short}</span></div>
<div><span class='meta-label'>Assessment Type</span>
<span class='meta-value'>Automated Static Analysis</span></div>
<div><span class='meta-label'>Prepared By</span>
<span class='meta-value'>GetVouch Security</span></div>
<div><span class='meta-label'>Files Analyzed</span>
<span class='meta-value'>{files_scanned}</span></div>
<div><span class='meta-label'>Total Findings</span>
<span class='meta-value'>{total}</span></div>
<div><span class='meta-label'>Overall Risk</span>
<span class='meta-value'
style='color:{score_color};'>{risk_level}</span></div>
</div>
</div>

<div class='body'>

<div class='section'>
<div class='section-label'>01 — Executive Summary</div>
<div class='exec-box'>
<p style='font-size:14px;color:#374151;line-height:1.7;'>
{exec_summary}</p>
</div>
<p style='font-size:13px;color:#6b7280;line-height:1.7;'>
This assessment was performed using GetVouch v1.0.0 automated
static analysis, scanning {files_scanned} files across 9 security
domains including credential exposure, authentication
vulnerabilities, injection risks, CORS misconfiguration,
environment safety, dependency analysis, input validation,
and insecure object references.
</p>
</div>

<div class='section'>
<div class='section-label'>02 — Risk Score</div>
<div class='score-grid'>
<div class='score-card'>
<div class='score-number'>{score}</div>
<div class='score-denom'>/100</div>
<div class='score-lbl'>Security Score</div>
</div>
<div>
<div class='metrics-grid'>
<div class='metric'>
<div class='metric-num' style='color:#dc2626;'>
{len(secret_findings)}</div>
<div class='metric-lbl'>Exposed Secrets</div>
</div>
<div class='metric'>
<div class='metric-num' style='color:#dc2626;'>
{len(auth_findings)}</div>
<div class='metric-lbl'>Auth Risks</div>
</div>
<div class='metric'>
<div class='metric-num' style='color:#ea580c;'>
{len(sql_findings) + len(cors_findings) + len(idor_findings)}</div>
<div class='metric-lbl'>Injection and Access</div>
</div>
<div class='metric'>
<div class='metric-num' style='color:#ca8a04;'>
{len(env_findings) + len(dep_findings) + len(val_findings)}</div>
<div class='metric-lbl'>Config and Hygiene</div>
</div>
</div>
<div class='risk-banner'>
<span style='font-size:12px;color:#6b7280;
text-transform:uppercase;letter-spacing:0.08em;'>
Overall Risk Level</span>
<span style='font-size:16px;font-weight:700;
color:{risk_border};'>{risk_level} RISK</span>
</div>
</div>
</div>
</div>

<div class='section'>
<div class='section-label'>03 — Scan Coverage</div>
<p style='font-size:13px;color:#6b7280;margin-bottom:14px;'>
GetVouch v1.0.0 scans across 9 security domains.
All categories below were included in this assessment.
</p>
{coverage_html}
</div>

<div class='section'>
<div class='section-label'>04 — Detailed Findings</div>
{build_table(
    secret_findings,
    "Exposed Credentials and API Keys",
    "CRITICAL", "#dc2626", "#fef2f2",
    "Hardcoded credentials found in source files. "
    "These must be rotated and removed immediately."
)}
{build_table(
    auth_findings,
    "Client-Side Authentication Vulnerabilities",
    "CRITICAL", "#dc2626", "#fef2f2",
    "Authorization logic in client-side code can be bypassed "
    "by any user using browser developer tools."
)}
{build_table(
    sql_findings,
    "SQL Injection Vulnerabilities",
    "HIGH", "#ea580c", "#fff7ed",
    "User-controlled input in database queries enables "
    "attackers to manipulate or destroy database contents."
)}
{build_table(
    cors_findings,
    "CORS Misconfiguration",
    "HIGH", "#ea580c", "#fff7ed",
    "Overly permissive CORS configuration allows any website "
    "to make authenticated requests to your API."
)}
{build_table(
    env_findings,
    "Environment File Safety",
    "CRITICAL", "#dc2626", "#fef2f2",
    "Environment files containing secrets are not protected "
    "from being committed to version control."
)}
{build_table(
    val_findings,
    "Missing Input Validation",
    "HIGH", "#ea580c", "#fff7ed",
    "User input is processed without validation or sanitization, "
    "enabling injection and manipulation attacks."
)}
{build_table(
    idor_findings,
    "Insecure Direct Object Reference",
    "HIGH", "#ea580c", "#fff7ed",
    "User-controlled IDs used to access resources without "
    "authorization checks allow users to access others data."
)}
{build_table(
    dep_findings,
    "Dependency and Configuration Issues",
    "MEDIUM", "#ca8a04", "#fefce8",
    "Configuration issues and localhost references that "
    "may cause failures or expose information in production."
)}
</div>

<div class='section'>
<div class='section-label'>05 — Remediation Guidance</div>
<p style='font-size:13px;color:#6b7280;margin-bottom:14px;
line-height:1.7;'>
Remediation steps listed in order of priority.
Critical findings must be addressed before any production
deployment or user onboarding.
</p>
<table style='width:100%;border-collapse:collapse;'>
<thead><tr style='background:#f9fafb;'>
<th style='padding:10px 14px;text-align:left;font-size:11px;
font-weight:600;color:#6b7280;text-transform:uppercase;
letter-spacing:0.05em;width:90px;'>Priority</th>
<th style='padding:10px 14px;text-align:left;font-size:11px;
font-weight:600;color:#6b7280;text-transform:uppercase;
letter-spacing:0.05em;width:200px;'>Finding</th>
<th style='padding:10px 14px;text-align:left;font-size:11px;
font-weight:600;color:#6b7280;text-transform:uppercase;
letter-spacing:0.05em;'>Recommended Action</th>
</tr></thead>
<tbody>
{remediation_rows if remediation_rows else no_remedy}
</tbody>
</table>
</div>

<div class='section'
style='background:#f9fafb;border-radius:8px;
padding:22px;border:1px solid #e5e7eb;'>
<div class='section-label'>06 — Disclaimer</div>
<p style='font-size:12px;color:#6b7280;line-height:1.8;'>
This report was generated by GetVouch v1.0.0 automated static
analysis. It represents findings detected through pattern matching
and heuristic analysis of source code files. This report does not
constitute a comprehensive penetration test or security audit.
GetVouch recommends all findings be reviewed by a qualified
security professional prior to remediation. False positives may
occur. GetVouch is not liable for decisions made based solely on
this report. Runtime vulnerabilities, business logic flaws, and
infrastructure misconfigurations may not be detected by static
analysis and require additional testing.
</p>
</div>

<div class='print-btn'>
<button onclick='window.print()'>Download Report as PDF</button>
<p>In the print dialog — select Save as PDF</p>
</div>

</div>

<div class='footer'>
<div class='footer-brand'>
Prepared by <strong>GetVouch Security</strong>
&nbsp;|&nbsp; getvouch.ai
</div>
<div class='footer-note'>
GetVouch v1.0.0 &nbsp;|&nbsp; Generated {now}<br>
This document is confidential
</div>
</div>
</div>
</body>
</html>"""
    return html


def run_vouch(target_dir="."):
    target_dir = os.path.abspath(target_dir)
    print("")
    print("  GetVouch v1.0.0 — Full Spectrum Security Assessment")
    print("  " + "=" * 52)
    print(f"  Scanning           : {target_dir}")

    secret_patterns = {
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

    auth_patterns = {
        "Client-side admin check":   r"(?i)(isAdmin|is_admin|isOwner)\s*===?\s*(true|false)",
        "Client-side role check":    r"(?i)(role|userRole|user_role)\s*===?\s*['\"]?(admin|owner|superuser)['\"]?",
        "Client-side payment check": r"(?i)(isPaid|is_paid|hasPaid|has_paid|isSubscribed)\s*===?\s*(true|false)",
        "Client-side auth bypass":   r"(?i)if\s*\(\s*!(isAuth|is_auth|isLoggedIn|authenticated)\s*\)",
        "localStorage auth token":   r"localStorage\.(getItem|setItem)\s*\(\s*['\"]?(token|auth|jwt|session)['\"]?",
    }

    sql_patterns = {
        "SQL Injection risk": r"(?i)(SELECT|INSERT|UPDATE|DELETE).{0,60}[\+\$\{]",
    }

    cors_patterns = {
        "CORS wildcard":         r"origin\s*:\s*['\"]?\*['\"]?",
        "CORS misconfiguration": r"Access-Control-Allow-Origin['\"]?\s*:\s*['\"]?\*",
    }

    validation_patterns = {
        "Missing input validation": r"(?i)(req\.body\.|request\.form\[|request\.args\[).{0,60}(?!.*(validate|sanitize|escape|strip|clean|zod|joi|yup))",
    }

    idor_patterns = {
        "Direct object reference": r"(?i)(findById|find_by_id|getById|get_by_id|params\.id|params\[.id.\]|req\.params\.id).{0,100}(?!.*(auth|permission|owner|role|admin))",
    }

    localhost_patterns = {
        "Localhost URL in code": r"(?i)(http://localhost|http://127\.0\.0\.1):[0-9]+",
    }

    scan_extensions = (
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".env", ".txt", ".json", ".yaml", ".yml",
        ".php", ".rb", ".go", ".java", ".cs",
        ".env.local", ".env.production",
        ".env.development", ".env.staging",
        ".config.js", ".config.ts"
    )

    frontend_extensions = (".js", ".jsx", ".ts", ".tsx")
    backend_extensions = (
        ".py", ".php", ".rb", ".go", ".java", ".cs"
    )

    skip_folders = {
        ".git", "node_modules", "__pycache__",
        ".venv", "venv", "build", "dist",
        ".next", ".nuxt", "coverage", ".pytest_cache"
    }

    skip_files = {
        "main.py", "setup.py", "getvouch-report.html"
    }

    findings_data = {
        "secrets": [],
        "auth": [],
        "sql": [],
        "cors": [],
        "env": [],
        "dependencies": [],
        "validation": [],
        "idor": [],
    }

    files_scanned = 0

    gitignore_path = os.path.join(target_dir, ".gitignore")
    gitignore_content = ""
    has_gitignore = os.path.exists(gitignore_path)

    if has_gitignore:
        with open(gitignore_path, "r",
                  encoding="utf-8", errors="ignore") as gf:
            gitignore_content = gf.read()

        env_files_to_check = [
            ".env", ".env.local",
            ".env.production", ".env.development"
        ]
        for env_file in env_files_to_check:
            if os.path.exists(os.path.join(target_dir, env_file)):
                if env_file not in gitignore_content:
                    findings_data["env"].append({
                        "type": f"{env_file} not in .gitignore",
                        "file": ".gitignore",
                        "line": "-",
                        "snippet": f"{env_file} missing from .gitignore"
                    })
    else:
        if any(os.path.exists(os.path.join(target_dir, e))
               for e in [".env", ".env.local", ".env.production"]):
            findings_data["env"].append({
                "type": "Missing .gitignore",
                "file": "project root",
                "line": "-",
                "snippet": "No .gitignore file found"
            })

    package_json_path = os.path.join(target_dir, "package.json")
    if os.path.exists(package_json_path):
        try:
            with open(package_json_path, "r",
                      encoding="utf-8") as pf:
                pkg = json.load(pf)
                all_deps = {}
                all_deps.update(pkg.get("dependencies", {}))
                all_deps.update(pkg.get("devDependencies", {}))

                known_old = {
                    "express": "4.17",
                    "lodash": "4.17.20",
                    "axios": "0.21",
                    "moment": "2.29",
                    "jquery": "3.6",
                }
                for pkg_name, min_ver in known_old.items():
                    if pkg_name in all_deps:
                        ver = all_deps[pkg_name].lstrip(
                            "^~>=")
                        if ver < min_ver:
                            findings_data[
                                "dependencies"].append({
                                "type": "Outdated dependency",
                                "file": "package.json",
                                "line": "-",
                                "snippet": (
                                    f"{pkg_name}@{ver} "
                                    f"— update to latest"
                                )
                            })
        except Exception:
            pass

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs
                   if d not in skip_folders]
        for file in files:
            if file in skip_files:
                continue

            has_scan_ext = any(
                file.endswith(ext)
                for ext in scan_extensions
            )
            if not has_scan_ext:
                continue

            file_path = os.path.join(root, file)
            files_scanned += 1
            is_frontend = file.endswith(frontend_extensions)
            is_backend = file.endswith(backend_extensions)
            is_js_ts = file.endswith(
                (".js", ".ts", ".jsx", ".tsx",
                 ".config.js", ".config.ts")
            )

            try:
                with open(file_path, "r",
                          encoding="utf-8",
                          errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):

                        for label, pattern in (
                                secret_patterns.items()):
                            if re.search(pattern, line):
                                findings_data[
                                    "secrets"].append({
                                    "type": label,
                                    "file": file_path,
                                    "line": line_num,
                                    "snippet": line.strip()[:80]
                                })

                        if is_frontend:
                            for label, pattern in (
                                    auth_patterns.items()):
                                if re.search(pattern, line):
                                    findings_data[
                                        "auth"].append({
                                        "type": label,
                                        "file": file_path,
                                        "line": line_num,
                                        "snippet": line.strip()[:80]
                                    })

                        if is_js_ts and not file.endswith(
                                ".py"):
                            for label, pattern in (
                                    sql_patterns.items()):
                                if re.search(pattern, line):
                                    findings_data[
                                        "sql"].append({
                                        "type": label,
                                        "file": file_path,
                                        "line": line_num,
                                        "snippet": line.strip()[:80]
                                    })

                        for label, pattern in (
                                cors_patterns.items()):
                            if re.search(pattern, line):
                                findings_data[
                                    "cors"].append({
                                    "type": label,
                                    "file": file_path,
                                    "line": line_num,
                                    "snippet": line.strip()[:80]
                                })

                        if is_js_ts or is_backend:
                            for label, pattern in (
                                    validation_patterns.items()):
                                if re.search(pattern, line):
                                    findings_data[
                                        "validation"].append({
                                        "type": label,
                                        "file": file_path,
                                        "line": line_num,
                                        "snippet": line.strip()[:80]
                                    })

                        if is_js_ts or is_backend:
                            for label, pattern in (
                                    idor_patterns.items()):
                                if re.search(pattern, line):
                                    findings_data[
                                        "idor"].append({
                                        "type": label,
                                        "file": file_path,
                                        "line": line_num,
                                        "snippet": line.strip()[:80]
                                    })

                        for label, pattern in (
                                localhost_patterns.items()):
                            if re.search(pattern, line):
                                findings_data[
                                    "dependencies"].append({
                                    "type": label,
                                    "file": file_path,
                                    "line": line_num,
                                    "snippet": line.strip()[:80]
                                })

            except Exception:
                pass

    total = sum(len(v) for v in findings_data.values())
    secrets = len(findings_data["secrets"])
    auth = len(findings_data["auth"])
    sql = len(findings_data["sql"])
    cors = len(findings_data["cors"])
    env = len(findings_data["env"])
    deps = len(findings_data["dependencies"])
    val = len(findings_data["validation"])
    idor = len(findings_data["idor"])

    score = max(0, 100
                - (secrets * 20)
                - (auth * 20)
                - (sql * 15)
                - (cors * 10)
                - (env * 20)
                - (deps * 5)
                - (val * 10)
                - (idor * 15))

    if score == 100:
        risk_level = "LOW"
        rating = "CLEAN — No issues detected"
    elif score >= 75:
        risk_level = "MODERATE"
        rating = "MODERATE RISK — Remediation recommended"
    elif score >= 50:
        risk_level = "HIGH"
        rating = "HIGH RISK — Fix before shipping"
    else:
        risk_level = "CRITICAL"
        rating = "CRITICAL — Do not ship"

    print(f"  Secrets found      : {secrets}")
    print(f"  Auth risks         : {auth}")
    print(f"  SQL risks          : {sql}")
    print(f"  CORS issues        : {cors}")
    print(f"  Env file safety    : {env}")
    print(f"  Validation gaps    : {val}")
    print(f"  IDOR risks         : {idor}")
    print(f"  Config issues      : {deps}")
    print(f"  Files scanned      : {files_scanned}")
    print(f"  Total findings     : {total}")
    print("")
    print(f"  Security Score     : {score}/100")
    print(f"  Assessment         : {rating}")
    print("")
    print("  Generating executive report...")

    report_html = generate_html_report(
        findings_data, files_scanned,
        score, rating, risk_level
    )

    report_path = "getvouch-report.html"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_html)

    print(f"  Report saved       : {report_path}")
    print("  Open in browser to view and download as PDF.")
    print("")
    print("  " + "=" * 52)
    print("  GetVouch v1.0.0 — getvouch.ai")
    print("")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    if not os.path.isdir(path):
        print(f"Error: '{path}' is not a valid directory.")
        sys.exit(1)
    run_vouch(path)
