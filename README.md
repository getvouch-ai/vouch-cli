# GetVouch

**The security scanner built for vibe-coded apps.**

Catches the real vulnerabilities in apps built with Lovable, Bolt, Cursor, Replit, Claude Code, v0, and Windsurf. Free, no signup, your code never leaves your machine.

🌐 Live scanner: https://getvouch.net

## What it does

- Scans GitHub repos for 9 categories of code-level vulnerabilities (exposed secrets, client-side auth, SQL injection, etc.)
- Scans deployed app URLs for 15 categories of live vulnerabilities (security headers, exposed files, Supabase RLS, service role key exposure, SSL/TLS, etc.)
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

### GitHub repository scanning (10 checks)
1. Exposed Secrets (25 key types)
2. Client-Side Authentication
3. SQL Injection Patterns
4. CORS Misconfiguration
5. Environment File Safety
6. Input Validation
7. Insecure Direct Object References
8. Dependency Issues
9. Outdated Packages
10. **Supply Chain Attack Detection** (v1.6.1) — checks package.json, package-lock.json, and yarn.lock against a static IOC list of packages compromised in major 2025–2026 npm supply chain attacks

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
14. **Supabase Service Role Key Exposure** (CRITICAL) — Detects if the service_role JWT is present in client-side bundles. This key bypasses all RLS — finding it in a client bundle is the most severe finding GetVouch produces.

## Supply chain attack detection

GetVouch v1.6.1 adds static IOC matching against packages compromised in the major 2025–2026 npm supply chain attacks:

| Campaign | Date | Packages | Payload |
|---|---|---|---|
| qix / chalk phish | Sept 2025 | chalk, debug, and chalk-ecosystem packages | Crypto wallet hijacker |
| s1ngularity / Nx | Aug 2025 | nx, @nx/* | Credential exfiltration |
| Shai-Hulud worm | Sept 2025 | 500+ packages | Self-replicating credential theft |
| Mini Shai-Hulud | Apr 2026 | 170+ packages (npm + PyPI) | Pre-install malware, axios compromised |

**Scope:** This is a static check — we match exact versions in your dependency files against a published list of known-compromised versions. We do **not** perform real-time malware analysis or catch new attacks automatically.

**Update cadence:** The IOC list (`getvouch/supply_chain_iocs.py`) is updated weekly as new public advisories are published.

**For comprehensive real-time supply chain security,** we recommend [Socket](https://socket.dev) or [Snyk Open Source](https://snyk.io). They run continuous threat research operations and catch attacks within hours of disclosure. GetVouch is the quick free check; they're the full-time operation.

**Sources:** CISA, Unit42 (Palo Alto Networks), Socket, StepSecurity, Sonatype, Microsoft Security Blog.

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

**Honest reporting:** When our automated scanner can't fully test something (e.g., Supabase keys hidden in dynamically loaded chunks), we mark the result as Inconclusive and tell you exactly what we couldn't scan. We don't show a green check on incomplete scans.

## Built by

[@its_sj13](https://x.com/its_sj13) — former SOC analyst, building GetVouch full-time.

## License

MIT
