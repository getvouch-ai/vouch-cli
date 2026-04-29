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
