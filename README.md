# 🛡️ GetVouch — Security for Vibe-Coded Apps

> AI builds fast. It also builds with unlocked doors.
> GetVouch finds them before your users do.

Built by a Cybersecurity analyst who spent 3 years watching these exact
vulnerabilities get exploited in enterprise breaches.
Now they're being baked into vibe-coded apps automatically.
Nobody was talking about this clearly enough. So I built this.

---

## Why this exists

Every vibe-coded app I reviewed had the same issues.
Not because the founders were careless.
Because the AI tools build them in automatically —
and they're invisible until something goes wrong.

I've seen what "something going wrong" looks like from
the inside of a security operations center. It's not pretty.
GetVouch is the check that runs before that happens.

---

## What GetVouch v1.2.0 scans for

### Secrets and credentials — 25 types
| Secret | Example pattern |
|---|---|
| OpenAI API Key | sk-... |
| Anthropic API Key | sk-ant-... |
| Stripe Live + Test Keys | sk_live_... / sk_test_... |
| AWS Access Key | AKIA... |
| Google + Firebase Keys | AIza... |
| GitHub Token | ghp_... |
| SendGrid Key | SG.... |
| Mailgun Key | key-... |
| Twilio Auth Token | detected by pattern |
| Shopify Secret | shpss_... |
| PayPal Client Secret | detected by pattern |
| MongoDB Connection String | mongodb://user:pass@... |
| PostgreSQL Connection | postgres://user:pass@... |
| JWT Secret | JWT_SECRET = "..." |
| Private Key Block | -----BEGIN PRIVATE KEY----- |
| Slack Token + Webhook | xoxb-... / hooks.slack.com |
| Generic hardcoded secrets | password = "..." |

### Authentication vulnerabilities
- Client-side admin and role checks bypassable in DevTools
- Client-side payment checks (the bug that killed a SaaS in 72hrs)
- Client-side auth bypass patterns
- Auth tokens stored in localStorage

### Injection risks
- SQL injection — user input in database queries
- Missing input validation on req.body and form data

### Infrastructure and configuration
- CORS wildcard misconfiguration (origin: '*')
- .env files not protected in .gitignore
- Missing .gitignore entirely
- Insecure direct object references (IDOR)
- Hardcoded localhost URLs left in production code
- Outdated dependencies in package.json

---

## What you get

A full executive security report — the kind you'd get
from a paid consulting firm.

- Security Score from 0 to 100
- Risk level: LOW / MODERATE / HIGH / CRITICAL
- Executive summary in plain English
- Every finding with exact file and line number
- Remediation guidance for each issue
- Download as PDF with one click

---

## Run it in 60 seconds
```bash
git clone https://github.com/getvouch-ai/vouch-cli.git
cd vouch-cli
python getvouch/main.py
```

Run it from inside your project folder.
Open `getvouch-report.html` in your browser when it finishes.

**Requirements:** Python 3.8+. No external libraries needed.
No API key. No signup. No data leaves your machine.

---

## Sample terminal output
```
  GetVouch v1.2.0 — Full Spectrum Security Assessment
  ====================================================
  Secrets found      : 2
  Auth risks         : 1
  SQL risks          : 0
  CORS issues        : 1
  Env file safety    : 1
  Validation gaps    : 3
  IDOR risks         : 0
  Config issues      : 1
  Files scanned      : 47
  Total findings     : 9

  Security Score     : 45/100
  Assessment         : CRITICAL — Do not ship

  Generating executive report...
  Report saved       : getvouch-report.html
  ====================================================
  GetVouch v1.2.0 — getvouch.ai
```

---

## Your data never leaves your machine

GetVouch runs entirely locally.
No network requests. No telemetry. No account required.
Your code stays on your computer.

This matters because you're trusting a security tool
with your codebase. You should be able to verify that.
Read the source — it's 400 lines of Python.

---

## Free audit

Run GetVouch and want a human to look at the results?

I personally review vibe-coded apps for free
while GetVouch is in early access.

SOC analyst background.
Plain English findings.
No jargon, no upsell.

→ Open an Issue titled "Free Audit Request"
→ Or find me on Reddit: u/CablePrestigious4523

---

## Roadmap

- [x] v0.1.0 — Secret scanner, 10 key types
- [x] v0.2.0 — Client-side auth detection, SQL scanner
- [x] v0.3.0 — Executive HTML report, PDF download
- [x] v1.0.0 — Full spectrum scan, 9 security domains
- [x] v1.1.0 — Scan any folder by path argument
- [x] v1.2.0 — Web interface — paste repo URL, get report
- [ ] v2.0.0 — GitHub App — auto-scan every PR

---

*Built by Sufiyan — Cybersecurity Analyst turned founder.*
*getvouch.ai | v1.2.0*
