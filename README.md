# 🛡️ GetVouch — Security for Vibe-Coded Apps

> AI builds fast. It also builds with unlocked doors.  
> GetVouch finds them before your users do.

Built by a Cybersecurity analyst who spent 3 years watching these exact 
vulnerabilities get exploited in enterprise breaches.
Now they're being baked into vibe-coded apps automatically.

---

## What GetVouch catches right now (v0.1.0)

| Secret Type | Example |
|---|---|
| OpenAI API Key | sk-... |
| Anthropic API Key | sk-ant-... |
| Stripe Live + Test Keys | sk_live_... / sk_test_... |
| AWS Access Key | AKIA... |
| Google API Key | AIza... |
| GitHub Token | ghp_... |
| Slack Token | xoxb-... |
| Twilio Key | SK... |
| Generic hardcoded secrets | password = "..." |

Every one of these gets baked into vibe-coded apps automatically.
GetVouch finds them before you ship.

---

## Run it in 60 seconds
```bash
git clone https://github.com/getvouch-ai/vouch-cli.git
cd vouch-cli
python getvouch/main.py
```

Run it from inside your project folder.
You'll get a Vibe Score from 0–100 and exact file + line numbers
for everything exposed.

---

## Sample output
```
🛡️  GetVouch v0.1.0 — The Integrity Layer for AI-Native Software
🕵️  Hunting Ghosts in your codebase...
────────────────────────────────────────────────────────────
📂 Files scanned: 42

🚨 ALERT — 2 potential secret(s) exposed:

  [1] Stripe Secret Key
      File : ./config/payments.js
      Line : 14
      Code : const stripe = require('stripe')('sk_live_abc123')

  [2] OpenAI API Key  
      File : ./utils/ai.js
      Line : 3
      Code : const openai = new OpenAI({ apiKey: 'sk-abc123' })

────────────────────────────────────────────────────────────
Your Vibe Score: 70/100 — 🔴 HIGH RISK

Fix these before you ship.
Need help? → getvouch.ai
```

---

## What GetVouch catches (v0.3.0)

| Check | What it finds |
|---|---|
| 🔑 Secrets | 10 key types — OpenAI, Stripe, AWS, GitHub and more |
| 🔐 Auth | Client-side auth logic bypassable in DevTools |
| 💉 SQL | Injection patterns in database queries |
| 📄 Report | Full HTML report with Vibe Score saved locally |

## Run it

git clone https://github.com/getvouch-ai/vouch-cli.git
cd vouch-cli
python getvouch/main.py

Open getvouch-report.html in your browser to see your results.

## Coming in v0.4.0

- .gitignore safety check
- Missing rate limiting detection
- Scan any folder path as argument

---

## Free audit

Running GetVouch and want a human to review your results?

I personally review vibe-coded apps for free right now.  
Cybersecurity analyst background. Plain English findings. No jargon.

→ Open an Issue titled "Free Audit Request"  
→ Or find me on Reddit: u/CablePrestigious4523

---

*Built by Sufiyan — Cybersecurity Analyst turned founder.*  
*getvouch.ai | v0.1.0*
