"""
AI Fix Prompt generator for GetVouch v1.3.0.
Returns a copy-paste prompt for every finding — paste into Lovable, Cursor,
Bolt, Replit, or Claude Code to fix the issue automatically.
"""

# ── Provider dashboards ────────────────────────────────────────────────────
PROVIDER_URLS = {
    "OpenAI API Key":            "platform.openai.com/api-keys",
    "Anthropic API Key":         "console.anthropic.com",
    "Google API Key":            "console.cloud.google.com/apis/credentials",
    "Firebase API Key":          "console.cloud.google.com/apis/credentials",
    "Firebase Service Account":  "console.firebase.google.com",
    "Stripe Secret Key":         "dashboard.stripe.com/apikeys",
    "Stripe Test Key":           "dashboard.stripe.com/apikeys",
    "Stripe Publishable Key":    "dashboard.stripe.com/apikeys",
    "AWS Access Key":            "console.aws.amazon.com/iam",
    "AWS Secret":                "console.aws.amazon.com/iam",
    "GitHub Token":              "github.com/settings/tokens",
    "GitHub OAuth":              "github.com/settings/tokens",
    "SendGrid API Key":          "app.sendgrid.com/settings/api_keys",
    "Mailgun API Key":           "app.mailgun.com/app/account/security/api_keys",
    "Twilio Auth Token":         "console.twilio.com",
    "Twilio API Key":            "console.twilio.com",
    "Shopify Secret Key":        "shopify.dev/apps/auth",
    "PayPal Client Secret":      "developer.paypal.com/dashboard",
    "MongoDB Connection String": "cloud.mongodb.com",
    "PostgreSQL Connection":     "your database provider dashboard",
    "JWT Secret":                "your auth provider dashboard",
    "Slack Token":               "api.slack.com/apps",
    "Slack Webhook":             "api.slack.com/apps",
    "Generic Secret":            "your API provider dashboard",
    "Private Key Block":         "your certificate authority dashboard",
}

# ── Default env var names per secret type ─────────────────────────────────
ENV_VAR_NAMES = {
    "OpenAI API Key":            "OPENAI_API_KEY",
    "Anthropic API Key":         "ANTHROPIC_API_KEY",
    "Google API Key":            "GOOGLE_API_KEY",
    "Firebase API Key":          "FIREBASE_API_KEY",
    "Firebase Service Account":  "FIREBASE_SERVICE_ACCOUNT_JSON",
    "Stripe Secret Key":         "STRIPE_SECRET_KEY",
    "Stripe Test Key":           "STRIPE_TEST_KEY",
    "Stripe Publishable Key":    "STRIPE_PUBLISHABLE_KEY",
    "AWS Access Key":            "AWS_ACCESS_KEY_ID",
    "AWS Secret":                "AWS_SECRET_ACCESS_KEY",
    "GitHub Token":              "GITHUB_TOKEN",
    "GitHub OAuth":              "GITHUB_OAUTH_TOKEN",
    "SendGrid API Key":          "SENDGRID_API_KEY",
    "Mailgun API Key":           "MAILGUN_API_KEY",
    "Twilio Auth Token":         "TWILIO_AUTH_TOKEN",
    "Twilio API Key":            "TWILIO_API_KEY",
    "Shopify Secret Key":        "SHOPIFY_SECRET_KEY",
    "PayPal Client Secret":      "PAYPAL_CLIENT_SECRET",
    "MongoDB Connection String": "MONGODB_URI",
    "PostgreSQL Connection":     "DATABASE_URL",
    "JWT Secret":                "JWT_SECRET",
    "Slack Token":               "SLACK_TOKEN",
    "Slack Webhook":             "SLACK_WEBHOOK_URL",
    "Generic Secret":            "SECRET_KEY",
    "Private Key Block":         "PRIVATE_KEY",
}


def generate_fix_prompt(finding: dict, category: str) -> str:
    """
    Return a full copy-paste AI fix prompt for this finding.
    Routes by category, then by type where needed.
    """
    f_type    = finding.get("type", "")
    f_file    = finding.get("file", "unknown")
    f_line    = finding.get("line", "-")
    f_snippet = finding.get("snippet", "")
    loc = (f"{f_file} line {f_line}") if str(f_line) != "-" else f_file

    if category == "secrets":
        return _prompt_secrets(f_type, f_file, f_line, f_snippet, loc)
    elif category == "auth":
        return _prompt_auth(f_type, f_file, f_line, f_snippet, loc)
    elif category == "sql":
        return _prompt_sql(f_file, f_line, f_snippet, loc)
    elif category == "cors":
        return _prompt_cors(f_file, f_line, f_snippet, loc)
    elif category == "env":
        return _prompt_env(f_type, f_file)
    elif category == "validation":
        return _prompt_validation(f_file, f_line, f_snippet, loc)
    elif category == "idor":
        return _prompt_idor(f_file, f_line, f_snippet, loc)
    elif category == "dependencies":
        return _prompt_dependencies(f_type, f_file, f_line, f_snippet, loc)
    elif category == "headers":
        return _prompt_headers(f_type, f_file)
    elif category == "info_disclosure":
        return _prompt_info_disclosure(f_snippet, f_file)
    elif category == "ssl":
        return _prompt_ssl(f_type, f_file)
    elif category == "exposed_files":
        return _prompt_exposed_files(f_file)
    elif category == "supabase":
        return _prompt_supabase(f_file, f_snippet)
    elif category == "admin_paths":
        return _prompt_admin_paths(f_file)
    elif category == "sri":
        return _prompt_sri(f_type, f_file)
    elif category == "mixed_content":
        return _prompt_mixed_content(f_snippet)
    elif category == "open_redirect":
        return _prompt_open_redirect(f_file, f_snippet)
    elif category == "rate_limit":
        return _prompt_rate_limit(f_file)
    elif category == "websocket":
        return _prompt_websocket(f_type, f_file)
    return (
        f"Review the security finding at {loc} and apply appropriate controls.\n"
        f"Finding type: {f_type}"
    )


# ── Category prompts ───────────────────────────────────────────────────────

def _prompt_secrets(f_type, f_file, f_line, f_snippet, loc):
    provider = PROVIDER_URLS.get(f_type, "your API provider dashboard")
    env_var  = ENV_VAR_NAMES.get(f_type, "SECRET_KEY")
    return (
        f"SECURITY FIX NEEDED — {f_type} found at {loc}\n"
        f"\n"
        f"IMPORTANT: If this key has ever been committed to git, it is already\n"
        f"compromised. Go to {provider} and revoke/rotate it NOW before fixing the code.\n"
        f"\n"
        f"Then fix the code:\n"
        f"\n"
        f"Step 1 — Create or open .env in your project root and add:\n"
        f"  {env_var}=your_new_key_here\n"
        f"\n"
        f"Step 2 — Make sure .env is in .gitignore (create .gitignore if missing):\n"
        f"  .env\n"
        f"  .env.local\n"
        f"  .env*.local\n"
        f"\n"
        f"Step 3 — In {f_file} line {f_line}, replace the hardcoded key with:\n"
        f"  Node.js / Next.js server:  process.env.{env_var}\n"
        f"  Python:                    os.environ['{env_var}']\n"
        f"  Vite (non-secret only):    import.meta.env.VITE_{env_var}\n"
        f"\n"
        f"Step 4 — Search the entire codebase for other hardcoded keys of this\n"
        f"type and apply the same fix.\n"
        f"\n"
        f"Verify: restart the app and confirm it connects to the service correctly."
    )


def _prompt_auth(f_type, f_file, f_line, f_snippet, loc):
    return (
        f"SECURITY FIX NEEDED — Client-side auth bypass at {loc}\n"
        f"Issue: {f_type} — this check runs in the browser and any user can bypass\n"
        f"it instantly using browser DevTools (F12 > Console).\n"
        f"\n"
        f"Fix the code at {f_file} line {f_line}:\n"
        f"\n"
        f"Step 1 — Create a protected API endpoint on your server that:\n"
        f"  - Reads the user session or JWT from a secure httpOnly cookie or Authorization header\n"
        f"  - Queries the database to check the user role / subscription status\n"
        f"  - Returns HTTP 403 Forbidden if the user does not have access\n"
        f"\n"
        f"Step 2 — Update {f_file} to call this server endpoint instead of\n"
        f"checking permissions in client-side code. Never gate features on\n"
        f"localStorage values, URL params, or client-side state.\n"
        f"\n"
        f"Step 3 — Search the entire codebase for similar patterns:\n"
        f"  isAdmin, isPaid, isSubscribed, userRole checks in .js/.jsx/.ts/.tsx\n"
        f"  localStorage.getItem('token') used to show or hide features\n"
        f"  ?admin=true or ?role=admin style URL param checks\n"
        f"\n"
        f"Verify: open DevTools > Application > Local Storage, delete or change\n"
        f"any auth-related value, and confirm the protected feature stays locked."
    )


def _prompt_sql(f_file, f_line, f_snippet, loc):
    return (
        f"SECURITY FIX NEEDED — SQL Injection vulnerability at {loc}\n"
        f"Issue: User input is concatenated directly into a SQL query.\n"
        f"Code: {f_snippet}\n"
        f"\n"
        f"Fix {f_file} line {f_line} using parameterized queries:\n"
        f"\n"
        f"  Node.js with pg (PostgreSQL):\n"
        f"    const result = await client.query(\n"
        f"      'SELECT * FROM users WHERE id = $1', [userId]\n"
        f"    )\n"
        f"\n"
        f"  Node.js with mysql2:\n"
        f"    const [rows] = await db.execute(\n"
        f"      'SELECT * FROM users WHERE id = ?', [userId]\n"
        f"    )\n"
        f"\n"
        f"  Python with psycopg2:\n"
        f"    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
        f"\n"
        f"  Prisma ORM: use .findUnique() / .findMany() with where clauses.\n"
        f"  Never pass user input into queryRaw() or executeRaw().\n"
        f"\n"
        f"  Supabase: use .eq() / .filter() chain methods — not rpc() with string interpolation.\n"
        f"\n"
        f"Search the entire codebase for SQL strings built with + concatenation\n"
        f"or template literals containing user-controlled variables.\n"
        f"\n"
        f"Verify: submit input containing: ' OR '1'='1 — the query must treat it\n"
        f"as literal data, not execute it as SQL."
    )


def _prompt_cors(f_file, f_line, f_snippet, loc):
    return (
        f"SECURITY FIX NEEDED — CORS misconfiguration at {loc}\n"
        f"Issue: Your server allows requests from any origin (*), letting any website\n"
        f"make authenticated API calls on behalf of your logged-in users.\n"
        f"\n"
        f"Fix {f_file} line {f_line} — replace the wildcard with your actual domains:\n"
        f"\n"
        f"  Express.js:\n"
        f"    app.use(cors({{\n"
        f"      origin: ['https://yourdomain.com', 'http://localhost:3000'],\n"
        f"      credentials: true\n"
        f"    }}))\n"
        f"\n"
        f"  FastAPI:\n"
        f"    app.add_middleware(CORSMiddleware,\n"
        f"      allow_origins=['https://yourdomain.com'],\n"
        f"      allow_credentials=True,\n"
        f"      allow_methods=['*'],\n"
        f"      allow_headers=['*']\n"
        f"    )\n"
        f"\n"
        f"  Note: never combine credentials=True with origin='*' — browsers block this anyway.\n"
        f"  A public API with no authentication may use '*' safely.\n"
        f"\n"
        f"Ask me what your production domain is if you are not sure what to put.\n"
        f"\n"
        f"Verify: test that requests from your domain succeed and requests from\n"
        f"an unknown origin are blocked with a CORS error."
    )


def _prompt_env(f_type, f_file):
    if f_type == "Missing .gitignore":
        return (
            f"SECURITY FIX NEEDED — No .gitignore file found\n"
            f"Issue: Without .gitignore your .env file will be committed to GitHub,\n"
            f"exposing all secrets in it.\n"
            f"\n"
            f"Step 1 — Create .gitignore in your project root containing at minimum:\n"
            f"  .env\n"
            f"  .env.local\n"
            f"  .env.*.local\n"
            f"  .env.production\n"
            f"  node_modules/\n"
            f"  .DS_Store\n"
            f"\n"
            f"Step 2 — Check if any .env file was already committed:\n"
            f"  git log --all --full-history -- .env\n"
            f"\n"
            f"If .env appears in git history, every secret inside it is compromised.\n"
            f"Rotate all of them at their respective provider dashboards.\n"
            f"\n"
            f"Verify: run 'git status' and confirm .env does not appear as a tracked file."
        )
    else:
        env_file = f_type.replace(" not in .gitignore", "").strip()
        return (
            f"SECURITY FIX NEEDED — {env_file} is not protected by .gitignore\n"
            f"Issue: {env_file} is not listed in .gitignore and may be committed\n"
            f"to version control, exposing secrets publicly.\n"
            f"\n"
            f"Step 1 — Open .gitignore and add this line:\n"
            f"  {env_file}\n"
            f"\n"
            f"Step 2 — If {env_file} was already committed to git, remove it from tracking:\n"
            f"  git rm --cached {env_file}\n"
            f"  git commit -m 'Remove {env_file} from git tracking'\n"
            f"\n"
            f"Step 3 — Check if it was ever pushed to GitHub:\n"
            f"  git log --all --full-history -- {env_file}\n"
            f"\n"
            f"If it was pushed at any point, every secret inside is compromised.\n"
            f"Rotate them all at their respective provider dashboards immediately.\n"
            f"\n"
            f"Verify: run 'git status' and confirm {env_file} does not appear."
        )


def _prompt_validation(f_file, f_line, f_snippet, loc):
    return (
        f"SECURITY FIX NEEDED — Missing input validation at {loc}\n"
        f"Issue: User-supplied input is processed without validation or sanitization.\n"
        f"Code: {f_snippet}\n"
        f"\n"
        f"Fix {f_file} line {f_line} by validating the input before using it:\n"
        f"\n"
        f"  Node.js with Zod (recommended):\n"
        f"    import {{ z }} from 'zod'\n"
        f"    const schema = z.object({{ field: z.string().min(1).max(255) }})\n"
        f"    const parsed = schema.parse(req.body)  // throws 400 if invalid\n"
        f"\n"
        f"  Node.js with Joi:\n"
        f"    const schema = Joi.object({{ field: Joi.string().required().max(255) }})\n"
        f"    const {{ error, value }} = schema.validate(req.body)\n"
        f"    if (error) return res.status(400).json({{ error: error.message }})\n"
        f"\n"
        f"  FastAPI (auto-validates via Pydantic):\n"
        f"    class RequestModel(BaseModel):\n"
        f"        field: str = Field(..., min_length=1, max_length=255)\n"
        f"\n"
        f"For this specific input validate: type, minimum and maximum length,\n"
        f"required fields present, no unexpected fields allowed, format (email/URL/etc).\n"
        f"Return HTTP 400 with a descriptive error message if validation fails.\n"
        f"\n"
        f"Verify: test with an empty string, a 10,000 character string, missing\n"
        f"required fields, and unexpected extra fields."
    )


def _prompt_idor(f_file, f_line, f_snippet, loc):
    return (
        f"SECURITY FIX NEEDED — Insecure Direct Object Reference (IDOR) at {loc}\n"
        f"Issue: A resource is fetched using a user-controlled ID with no check that\n"
        f"the requesting user is authorized to access it.\n"
        f"Code: {f_snippet}\n"
        f"\n"
        f"Fix {f_file} line {f_line} — add an ownership check after fetching:\n"
        f"\n"
        f"  // Fetch the resource\n"
        f"  const resource = await db.findById(params.id)\n"
        f"\n"
        f"  // Check existence\n"
        f"  if (!resource) return res.status(404).json({{ error: 'Not found' }})\n"
        f"\n"
        f"  // Check ownership (use 403 not 404 — 404 leaks that the resource exists)\n"
        f"  if (resource.userId !== session.user.id) {{\n"
        f"    return res.status(403).json({{ error: 'Forbidden' }})\n"
        f"  }}\n"
        f"\n"
        f"  return res.json(resource)\n"
        f"\n"
        f"Search the codebase for every endpoint that accepts an ID parameter and\n"
        f"returns data — each one needs this ownership or permission check:\n"
        f"  /api/users/[id], /api/posts/[id], /api/orders/[id], /api/files/[id]\n"
        f"\n"
        f"Verify: sign in as User A, copy the ID of User B's resource, try to access\n"
        f"it as User A — the response must be 403 Forbidden, not the resource data."
    )


def _prompt_dependencies(f_type, f_file, f_line, f_snippet, loc):
    if f_type == "Localhost URL in code":
        return (
            f"SECURITY FIX NEEDED — Hardcoded localhost URL at {loc}\n"
            f"Issue: This URL will fail silently in production.\n"
            f"Code: {f_snippet}\n"
            f"\n"
            f"Fix {f_file} line {f_line}:\n"
            f"\n"
            f"Step 1 — Add to .env.local (development):\n"
            f"  API_URL=http://localhost:3000\n"
            f"\n"
            f"Step 2 — Add to your deployment environment variables (production):\n"
            f"  API_URL=https://your-production-domain.com\n"
            f"\n"
            f"Step 3 — Replace the hardcoded URL in {f_file} with:\n"
            f"  Next.js client-side:  process.env.NEXT_PUBLIC_API_URL\n"
            f"  Vite client-side:     import.meta.env.VITE_API_URL\n"
            f"  Node.js server:       process.env.API_URL\n"
            f"\n"
            f"Make sure .env.local and .env.production are in .gitignore.\n"
            f"\n"
            f"Verify: deploy to your staging environment and confirm API calls\n"
            f"reach the correct production URL."
        )
    else:
        pkg = f_snippet.split("@")[0].strip() if "@" in f_snippet else "this package"
        return (
            f"SECURITY FIX NEEDED — Outdated dependency at {loc}\n"
            f"Issue: {f_snippet} may contain known security vulnerabilities.\n"
            f"\n"
            f"Fix steps:\n"
            f"\n"
            f"Step 1 — Check all known vulnerabilities:\n"
            f"  npm audit\n"
            f"\n"
            f"Step 2 — Auto-fix safe updates:\n"
            f"  npm audit fix\n"
            f"\n"
            f"Step 3 — Update this specific package:\n"
            f"  npm update {pkg}\n"
            f"  For a major version bump: npm install {pkg}@latest\n"
            f"\n"
            f"Step 4 — Test the app after updating. Major versions can have breaking\n"
            f"changes. Update one package at a time, test, commit, then move to the next.\n"
            f"\n"
            f"Verify: run 'npm audit' again and confirm no high or critical vulnerabilities remain."
        )


# ── URL scanner prompts ────────────────────────────────────────────────────

def _prompt_headers(f_type: str, f_file: str) -> str:
    header = f_type.replace("Missing ", "")
    recipes = {
        "Content-Security-Policy": (
            "Content-Security-Policy: default-src 'self'; script-src 'self'; "
            "object-src 'none'; base-uri 'self'"
        ),
        "X-Frame-Options": "X-Frame-Options: DENY",
        "Strict-Transport-Security (HSTS)": (
            "Strict-Transport-Security: max-age=31536000; includeSubDomains"
        ),
        "X-Content-Type-Options": "X-Content-Type-Options: nosniff",
        "Referrer-Policy": "Referrer-Policy: strict-origin-when-cross-origin",
        "Permissions-Policy": (
            "Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ),
    }
    value = recipes.get(header, f"{header}: <appropriate-value>")
    return (
        f"SECURITY FIX NEEDED — {f_type} at {f_file}\n"
        f"Risk: browsers receive no {header} directive, enabling related attacks.\n"
        f"\n"
        f"Step 1 — Add this header to every response from your server:\n"
        f"  {value}\n"
        f"\n"
        f"Step 2 — Framework-specific locations:\n"
        f"  Next.js: add to headers() in next.config.js\n"
        f"  Express: app.use(helmet()) installs all security headers at once\n"
        f"  Vercel: set in vercel.json under 'headers'\n"
        f"  Netlify: set in netlify.toml under [[headers]]\n"
        f"  Cloudflare Pages: set in _headers file at repo root\n"
        f"\n"
        f"Step 3 — Check all routes receive the header (use curl -I {f_file}).\n"
        f"\n"
        f"Verify: run curl -sI {f_file} and confirm {header} is present."
    )


def _prompt_info_disclosure(f_snippet: str, f_file: str) -> str:
    return (
        f"SECURITY FIX NEEDED — Server version leaked in HTTP headers at {f_file}\n"
        f"Issue: {f_snippet}\n"
        f"Risk: version strings let attackers look up CVEs for your exact stack.\n"
        f"\n"
        f"Step 1 — Remove or mask the header at the web server level:\n"
        f"  Nginx:   server_tokens off;\n"
        f"  Apache:  ServerTokens Prod\n"
        f"  Express: app.disable('x-powered-by') or use helmet()\n"
        f"  Next.js: add 'poweredByHeader: false' in next.config.js\n"
        f"\n"
        f"Step 2 — If behind a CDN or load balancer (Cloudflare, Vercel, Railway),\n"
        f"check their header-stripping options — most proxy layers can remove this.\n"
        f"\n"
        f"Verify: curl -sI {f_file} and confirm the version string is gone."
    )


def _prompt_ssl(f_type: str, f_file: str) -> str:
    if f_type == "No HTTPS":
        return (
            f"SECURITY FIX NEEDED — Site is served over HTTP at {f_file}\n"
            f"Risk: all traffic (including passwords and tokens) is transmitted in plaintext.\n"
            f"\n"
            f"Step 1 — Enable HTTPS on your host:\n"
            f"  Vercel / Netlify / Cloudflare Pages: HTTPS is automatic — check your domain config.\n"
            f"  Railway / Render: use the provided HTTPS domain or configure a custom domain with TLS.\n"
            f"  VPS (Nginx/Apache): run 'certbot --nginx' or 'certbot --apache' (free Let's Encrypt cert).\n"
            f"\n"
            f"Step 2 — Redirect all HTTP traffic to HTTPS:\n"
            f"  Nginx: return 301 https://$host$request_uri;\n"
            f"  Express: use the 'express-force-ssl' package or a reverse proxy rule.\n"
            f"\n"
            f"Step 3 — Add HSTS once HTTPS is confirmed working:\n"
            f"  Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
            f"\n"
            f"Verify: curl -I http://{f_file.split('//')[-1]} confirms a 301 redirect to https://."
        )
    if "Expiring" in f_type:
        return (
            f"SECURITY FIX NEEDED — SSL certificate expiring soon at {f_file}\n"
            f"Risk: browsers will show a security warning when it expires, blocking all users.\n"
            f"\n"
            f"Step 1 — Renew the certificate immediately:\n"
            f"  Let's Encrypt (certbot): certbot renew\n"
            f"  Cloudflare / Vercel / Netlify: renewal is automatic — check your domain settings.\n"
            f"  Purchased cert: contact your CA and follow their renewal process.\n"
            f"\n"
            f"Step 2 — Enable auto-renewal to prevent recurrence:\n"
            f"  certbot: add 'certbot renew' to a daily cron job\n"
            f"  crontab: 0 0 * * * certbot renew --quiet\n"
            f"\n"
            f"Verify: openssl s_client -connect {f_file.split('//')[-1].split('/')[0]}:443 "
            f"</dev/null 2>/dev/null | openssl x509 -noout -dates"
        )
    return (
        f"SECURITY FIX NEEDED — SSL certificate error at {f_file}\n"
        f"Risk: browsers will block access and users will see a security warning.\n"
        f"\n"
        f"Step 1 — Identify the error type (hostname mismatch, expired, self-signed):\n"
        f"  openssl s_client -connect {f_file.split('//')[-1].split('/')[0]}:443\n"
        f"\n"
        f"Step 2 — For hostname mismatch: ensure the certificate's CN or SAN includes\n"
        f"  your exact domain (including www. if applicable).\n"
        f"\n"
        f"Step 3 — Replace with a valid certificate. Free option:\n"
        f"  certbot certonly --standalone -d yourdomain.com\n"
        f"\n"
        f"Verify: run the openssl command again and confirm no errors appear."
    )


def _prompt_exposed_files(f_file: str) -> str:
    path = f_file.split("/", 3)[-1] if "/" in f_file else f_file
    is_env  = ".env" in path
    is_git  = ".git" in path
    is_sql  = ".sql" in path or "backup" in path
    if is_env:
        action = (
            "This file contains secret keys. Rotate ALL credentials inside it immediately\n"
            "at their respective provider dashboards before fixing the exposure."
        )
    elif is_git:
        action = (
            "Your git history (including deleted secrets) is now public. Rotate any\n"
            "credentials that ever appeared in a commit."
        )
    elif is_sql:
        action = (
            "Your database schema and possibly data is exposed. Change all DB passwords\n"
            "and review what data was in the file."
        )
    else:
        action = "Review the file contents and rotate any credentials found inside."
    return (
        f"CRITICAL — Sensitive file exposed at {f_file}\n"
        f"Risk: {action}\n"
        f"\n"
        f"Step 1 — Block access to this path immediately:\n"
        f"  Nginx:   location ~ /\\.  {{ deny all; }}\n"
        f"  Apache:  <FilesMatch \"^\\.\">\n"
        f"             Require all denied\n"
        f"           </FilesMatch>\n"
        f"  Vercel:  add to vercel.json 'routes': [{{'src': '/\\.env', 'dest': '/404'}}]\n"
        f"  Cloudflare: create a firewall rule blocking the path\n"
        f"\n"
        f"Step 2 — Confirm the block: curl -I {f_file} should return 403 or 404.\n"
        f"\n"
        f"Step 3 — Assume the file was already read. Rotate all secrets inside it."
    )


def _prompt_supabase(f_file: str, f_snippet: str) -> str:
    return (
        f"CRITICAL — Supabase Row Level Security (RLS) disabled at {f_file}\n"
        f"Issue: {f_snippet}\n"
        f"Risk: any internet user can read (and possibly write) your entire database table\n"
        f"without logging in. This is a complete data breach.\n"
        f"\n"
        f"Step 1 — Enable RLS on the exposed table immediately:\n"
        f"  In Supabase Dashboard → Table Editor → select the table\n"
        f"  → RLS tab → 'Enable RLS'\n"
        f"  Or via SQL: ALTER TABLE public.<table_name> ENABLE ROW LEVEL SECURITY;\n"
        f"\n"
        f"Step 2 — Add a policy that controls who can read:\n"
        f"  -- Allow users to read only their own rows:\n"
        f"  CREATE POLICY 'Users see own rows' ON public.<table_name>\n"
        f"    FOR SELECT USING (auth.uid() = user_id);\n"
        f"\n"
        f"Step 3 — Check ALL other tables for the same issue:\n"
        f"  SELECT schemaname, tablename, rowsecurity\n"
        f"  FROM pg_tables WHERE schemaname = 'public';\n"
        f"  Any row with rowsecurity = false is exposed.\n"
        f"\n"
        f"Step 4 — Rotate the anon key that was exposed in your source code:\n"
        f"  Supabase Dashboard → Project Settings → API → Regenerate anon key.\n"
        f"\n"
        f"Verify: retry the unauthenticated query — it must return 401 or empty rows."
    )


def _prompt_sri(f_type: str, f_file: str) -> str:
    is_cdn = "CDN" in f_type
    return (
        f"SECURITY FIX NEEDED — Missing Subresource Integrity at {f_file}\n"
        f"Risk: if {('this CDN' if is_cdn else 'this third-party host')} is compromised, "
        f"attackers can inject arbitrary JavaScript into your users' browsers.\n"
        f"\n"
        f"Step 1 — Generate the integrity hash for this resource:\n"
        f"  Visit https://www.srihash.org and paste the resource URL, OR run:\n"
        f"  curl -s {f_file} | openssl dgst -sha384 -binary | openssl base64 -A\n"
        f"\n"
        f"Step 2 — Add the integrity and crossorigin attributes to the tag:\n"
        f'  <script src="{f_file}"\n'
        f'          integrity="sha384-<hash-from-step-1>"\n'
        f'          crossorigin="anonymous"></script>\n'
        f"\n"
        f"Step 3 — Switch to self-hosted if the resource changes frequently\n"
        f"  (integrity hashes break on every update):\n"
        f"  npm install <package> and import from node_modules instead.\n"
        f"\n"
        f"Verify: open DevTools > Network, reload — the resource should load\n"
        f"without an 'integrity mismatch' console error."
    )


def _prompt_mixed_content(f_snippet: str) -> str:
    resource = f_snippet.replace("HTTPS page loads HTTP resource: ", "").strip()
    return (
        f"SECURITY FIX NEEDED — Mixed Content\n"
        f"Risk: HTTPS pages loading HTTP resources break the security model — the HTTP\n"
        f"resource can be intercepted and replaced by a network attacker.\n"
        f"\n"
        f"Affected resource: {resource}\n"
        f"\n"
        f"Step 1 — Change the resource URL to HTTPS:\n"
        f"  http://example.com/script.js  →  https://example.com/script.js\n"
        f"\n"
        f"Step 2 — If the resource is not available over HTTPS, self-host it:\n"
        f"  Download the file and serve it from your own domain.\n"
        f"\n"
        f"Step 3 — Search your codebase for all http:// asset references:\n"
        f"  grep -r 'src=\"http://' . --include='*.html' --include='*.js'\n"
        f"  grep -r 'href=\"http://' . --include='*.html'\n"
        f"\n"
        f"Verify: reload the page in Chrome DevTools > Console — no Mixed Content\n"
        f"warnings should appear."
    )


def _prompt_open_redirect(f_file: str, f_snippet: str) -> str:
    return (
        f"SECURITY FIX NEEDED — Open Redirect at {f_file}\n"
        f"Issue: {f_snippet}\n"
        f"Risk: attackers can craft a link like https://yourapp.com/login?redirect=https://evil.com\n"
        f"to phish your users after they authenticate — the trusted domain lends credibility.\n"
        f"\n"
        f"Step 1 — Validate the redirect target before redirecting:\n"
        f"  // Only allow relative paths or your own domain\n"
        f"  function safeRedirect(url) {{\n"
        f"    if (url.startsWith('/') && !url.startsWith('//')) return url\n"
        f"    const allowed = ['https://yourdomain.com', 'https://app.yourdomain.com']\n"
        f"    if (allowed.some(origin => url.startsWith(origin))) return url\n"
        f"    return '/dashboard'  // safe fallback\n"
        f"  }}\n"
        f"\n"
        f"Step 2 — Apply to every redirect parameter handler:\n"
        f"  redirect, return, returnTo, next, url, dest, goto, target\n"
        f"\n"
        f"Step 3 — For OAuth flows, validate redirect_uri against a pre-registered\n"
        f"  allowlist at your OAuth provider — never accept arbitrary URIs.\n"
        f"\n"
        f"Verify: test https://yoursite.com/login?redirect=https://evil.com — it should\n"
        f"land on /dashboard (or similar) instead of evil.com."
    )


def _prompt_rate_limit(f_file: str) -> str:
    return (
        f"SECURITY FIX NEEDED — No Rate Limiting on Auth Endpoint at {f_file}\n"
        f"Risk: attackers can run credential stuffing or brute-force attacks with\n"
        f"thousands of password attempts per minute at no cost.\n"
        f"\n"
        f"Step 1 — Add rate limiting middleware:\n"
        f"  Express / Node.js:\n"
        f"    import rateLimit from 'express-rate-limit'\n"
        f"    app.use('/login', rateLimit({{ windowMs: 15*60*1000, max: 10 }}))\n"
        f"\n"
        f"  Next.js API route (using Upstash Redis):\n"
        f"    import {{ Ratelimit }} from '@upstash/ratelimit'\n"
        f"    const ratelimit = new Ratelimit({{ limiter: Ratelimit.slidingWindow(10, '15m') }})\n"
        f"    const {{ success }} = await ratelimit.limit(ip)\n"
        f"    if (!success) return res.status(429).json({{ error: 'Too many requests' }})\n"
        f"\n"
        f"  FastAPI:\n"
        f"    Use slowapi: @limiter.limit('5/minute') on the login endpoint.\n"
        f"\n"
        f"  Lovable / Bolt / Replit (Supabase Auth):\n"
        f"    Supabase applies rate limits automatically — ensure you are using\n"
        f"    supabase.auth.signInWithPassword() not a custom endpoint.\n"
        f"\n"
        f"Step 2 — Return HTTP 429 with Retry-After header when limit is exceeded.\n"
        f"\n"
        f"Step 3 — Consider adding CAPTCHA for login after N failures:\n"
        f"  hCaptcha or Cloudflare Turnstile (both have free tiers).\n"
        f"\n"
        f"Verify: send 15 rapid POST requests — the 11th should return 429."
    )


def _prompt_websocket(f_type: str, f_file: str) -> str:
    is_origin = "Origin" in f_type
    return (
        f"SECURITY FIX NEEDED — WebSocket Security at {f_file}\n"
        f"Risk: {'any origin can connect to your WebSocket (cross-site WebSocket hijacking)' if is_origin else 'unauthenticated users can connect to your WebSocket and receive real-time data'}\n"
        f"\n"
        f"Step 1 — {'Validate the Origin header on connection:' if is_origin else 'Authenticate on connection:'}\n"
        + (
        f"  // Node.js / ws library\n"
        f"  wss.on('connection', (ws, req) => {{\n"
        f"    const origin = req.headers.origin\n"
        f"    const allowed = ['https://yourdomain.com']\n"
        f"    if (!allowed.includes(origin)) {{ ws.close(4001, 'Forbidden'); return }}\n"
        f"  }})\n"
        if is_origin else
        f"  // Verify auth token on the initial connection\n"
        f"  wss.on('connection', async (ws, req) => {{\n"
        f"    const token = new URL(req.url, 'ws://x').searchParams.get('token')\n"
        f"    const user = await verifyToken(token)\n"
        f"    if (!user) {{ ws.close(4001, 'Unauthorized'); return }}\n"
        f"  }})\n"
        ) +
        f"\n"
        f"Step 2 — Use wss:// (WebSocket over TLS) in production — never ws://.\n"
        f"\n"
        f"Step 3 — For Socket.io, enable auth in the handshake:\n"
        f"  io.use(async (socket, next) => {{\n"
        f"    const token = socket.handshake.auth.token\n"
        f"    const user = await verifyToken(token)\n"
        f"    if (!user) next(new Error('Unauthorized'))\n"
        f"    else next()\n"
        f"  }})\n"
        f"\n"
        f"Verify: attempt to connect without credentials (or from evil.example.com)\n"
        f"— the server should close the connection immediately."
    )


def _prompt_admin_paths(f_file: str) -> str:
    path = "/" + f_file.split("/", 3)[-1] if "/" in f_file else f_file
    return (
        f"SECURITY FIX NEEDED — Admin or debug endpoint exposed at {f_file}\n"
        f"Risk: unauthenticated access to admin interfaces enables account takeover,\n"
        f"data manipulation, and infrastructure enumeration.\n"
        f"\n"
        f"Step 1 — Determine if this endpoint should be public:\n"
        f"  Admin panels, Swagger UI, /actuator, /console, /debug → should require auth.\n"
        f"  If it should not exist at all in production, disable it.\n"
        f"\n"
        f"Step 2 — Add authentication if keeping it:\n"
        f"  Express:  use a middleware that checks req.session.isAdmin\n"
        f"  FastAPI:  add Depends(require_admin) to the route\n"
        f"  Spring:   configure .requestMatchers('{path}').hasRole('ADMIN') in SecurityConfig\n"
        f"\n"
        f"Step 3 — Consider IP allowlisting for internal-only tools:\n"
        f"  Nginx:   allow 10.0.0.0/8; deny all;  (inside the location block)\n"
        f"  Cloudflare: use Access policies to restrict by team email / IP\n"
        f"\n"
        f"Step 4 — Disable dev/debug endpoints in production via environment flags:\n"
        f"  Spring Boot: management.endpoints.web.exposure.include=health (actuator only)\n"
        f"  Swagger:    conditionally register only when NODE_ENV !== 'production'\n"
        f"\n"
        f"Verify: curl -I {f_file} should return 401, 403, or 404 — not 200."
    )
