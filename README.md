# GetVouch

**The security scanner built for vibe-coded apps.**

Catches the real vulnerabilities in apps built with Lovable, Bolt, Cursor, Replit, Claude Code, v0, and Windsurf. Free, no signup, your code never leaves your machine.

🌐 Live scanner: https://getvouch.net

## What it does

- Scans GitHub repos for 9 categories of code-level vulnerabilities (exposed secrets, client-side auth, SQL injection, etc.)
- Scans deployed app URLs for 14 categories of live vulnerabilities (security headers, exposed files, Supabase RLS, SSL/TLS, etc.)
- Generates a copy-paste AI fix prompt for every finding — paste it into Lovable/Cursor/Bolt and the AI fixes it
- Produces a professional PDF report you can deliver to clients
- Shows a Technical Audit Log proving what was tested (even when defenses hold)

## Flagship feature: Supabase RLS testing

GetVouch is the only vibe-coding security scanner that tests Supabase Row Level Security directly. When your app uses Supabase, we send authorized read-only queries to confirm that your RLS policies actually block unauthenticated access. If they don't, you'll find out before an attacker does.

## Quickstart

### Scan via the web

Visit https://getvouch.net and paste either:
- A GitHub repo URL: `https://github.com/your-org/your-repo`
- A deployed app URL: `https://your-app.vercel.app`

### Scan via CLI

```bash
pip install getvouch-cli
getvouch scan https://github.com/your-org/your-repo
```

## What we scan

### GitHub repository scanning (9 checks)
1. Exposed Secrets (25 key types)
2. Client-Side Authentication
3. SQL Injection Patterns
4. CORS Misconfiguration
5. Environment File Safety
6. Input Validation
7. Insecure Direct Object References
8. Dependency Issues
9. Outdated Packages

### Live URL scanning (14 checks)
1. Security Headers (CSP, X-Frame-Options, HSTS, etc.)
2. Exposed Sensitive Files (.env, .git/config, wp-config.php, etc.)
3. Secrets in Page Source and JS Bundles
4. **Supabase Row Level Security** (flagship — the #1 Lovable vulnerability)
5. SSL/TLS Configuration
6. CORS Misconfiguration (Live)
7. Exposed Admin & Debug Paths
8. Information Disclosure in HTTP Headers
9. Subresource Integrity
10. Open Redirect Detection
11. Mixed Content
12. Rate Limit Detection on Auth Endpoints
13. WebSocket Security

## Architecture

- Frontend: Static HTML/CSS/JS on Cloudflare Pages → https://getvouch.net
- Backend: FastAPI on Railway → https://web-production-8cf38.up.railway.app
- CLI: Python package on PyPI

## Ethical scanning

GetVouch follows industry-standard ethical scanning practices:
- All HTTP requests use a transparent User-Agent identifying GetVouch
- Read-only operations — no writes, no deletes, no modifications
- Rate-limited to avoid impact on target apps
- Maximum scan time capped at 60 seconds per URL
- Never logs or displays captured data — findings show only structure and counts
- Supabase RLS testing uses OpenAPI introspection (authorized discovery) before falling back to common-name probing

## Built by

[@its_sj13](https://x.com/its_sj13) — former SOC analyst, building GetVouch full-time.

## License

MIT
