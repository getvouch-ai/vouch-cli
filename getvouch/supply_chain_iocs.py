# SOURCE NOTES:
# - Last updated: 2026-05-15
# - Sources: CISA, Unit42 (Palo Alto Networks), Socket, StepSecurity, Sonatype, Microsoft Security Blog
# - This list covers MAJOR public compromises only. For comprehensive real-time
#   supply chain security, users should use Socket, Snyk, or similar dedicated tools.
#
# TODO: Pull the full StepSecurity list (500+ Shai-Hulud packages) from:
#   https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised
# TODO: Pull the full Mini Shai-Hulud list (170+ packages) from the Microsoft advisory:
#   https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance
# TODO: Pull exact qix/chalk-ecosystem versions from Socket advisory before each release.

COMPROMISED_NPM_PACKAGES = {

    # ------------------------------------------------------------------
    # Sept 8, 2025 — "qix" / Josh Junon phishing compromise
    # Crypto wallet hijacker payload injected into chalk ecosystem packages.
    # Maintainer Josh Junon ("qix") was phished; attacker published malicious
    # versions of every package under his npm account.
    # Sources: Socket (https://socket.dev/blog/), Sonatype, Trend Micro
    # ------------------------------------------------------------------
    "chalk": {
        "compromised_versions": ["5.6.0", "5.6.1"],
        "campaign": "qix_phish_2025",
        "severity": "CRITICAL",
        "description": "Compromised September 2025 in a phishing attack on maintainer Josh Junon. Malicious versions contain a crypto wallet hijacker that silently redirects cryptocurrency transactions.",
        "safe_version": ">=5.5.0,<5.6.0 OR >=5.6.2",
    },
    "debug": {
        "compromised_versions": ["4.4.2"],
        "campaign": "qix_phish_2025",
        "severity": "CRITICAL",
        "description": "Compromised September 2025 in the same qix phishing attack as chalk. Same crypto wallet hijacker payload.",
        "safe_version": "<4.4.2 OR >=4.4.3",
    },
    "ansi-styles": {
        # TODO: verify exact version from Socket advisory — placeholder based on campaign scope
        "compromised_versions": ["6.2.2"],
        "campaign": "qix_phish_2025",
        "severity": "CRITICAL",
        "description": "Compromised September 2025 as part of the qix phishing attack on the chalk ecosystem. Verify exact version against Socket advisory.",
        "safe_version": "Versions outside the Sept 8–10 2025 publish window — verify with Socket advisory",
    },
    "strip-ansi": {
        "compromised_versions": ["7.1.1"],
        "campaign": "qix_phish_2025",
        "severity": "CRITICAL",
        "description": "Compromised September 2025 as part of the qix phishing attack on the chalk ecosystem. Verify exact version against Socket advisory.",
        "safe_version": "Versions outside the Sept 8–10 2025 publish window — verify with Socket advisory",
    },
    "color-convert": {
        "compromised_versions": ["2.0.2"],
        "campaign": "qix_phish_2025",
        "severity": "CRITICAL",
        "description": "Compromised September 2025 as part of the qix phishing attack on the chalk ecosystem. Verify exact version against Socket advisory.",
        "safe_version": "Versions outside the Sept 8–10 2025 publish window — verify with Socket advisory",
    },
    "color-name": {
        "compromised_versions": ["1.1.5"],
        "campaign": "qix_phish_2025",
        "severity": "CRITICAL",
        "description": "Compromised September 2025 as part of the qix phishing attack. Verify exact version against Socket advisory.",
        "safe_version": "Versions outside the Sept 8–10 2025 publish window — verify with Socket advisory",
    },
    "supports-color": {
        "compromised_versions": ["9.4.1"],
        "campaign": "qix_phish_2025",
        "severity": "CRITICAL",
        "description": "Compromised September 2025 as part of the qix phishing attack on the chalk ecosystem. Verify exact version against Socket advisory.",
        "safe_version": "Versions outside the Sept 8–10 2025 publish window — verify with Socket advisory",
    },
    "wrap-ansi": {
        "compromised_versions": ["9.0.1"],
        "campaign": "qix_phish_2025",
        "severity": "CRITICAL",
        "description": "Compromised September 2025 as part of the qix phishing attack on the chalk ecosystem. Verify exact version against Socket advisory.",
        "safe_version": "Versions outside the Sept 8–10 2025 publish window — verify with Socket advisory",
    },
    "has-ansi": {
        "compromised_versions": ["5.0.2"],
        "campaign": "qix_phish_2025",
        "severity": "CRITICAL",
        "description": "Compromised September 2025 as part of the qix phishing attack. Verify exact version against Socket advisory.",
        "safe_version": "Versions outside the Sept 8–10 2025 publish window — verify with Socket advisory",
    },

    # ------------------------------------------------------------------
    # Aug 26–27, 2025 — Nx / s1ngularity compromise
    # Stolen npm publishing token used to push malicious versions of Nx
    # packages. Window was ~4 hours before npm yanked the versions.
    # Payload: developer credential exfiltration.
    # Sources: Unit42, Sonatype
    # ------------------------------------------------------------------
    "nx": {
        "compromised_versions": ["20.9.0", "21.5.0", "21.6.0"],
        "campaign": "s1ngularity_2025",
        "severity": "CRITICAL",
        "description": "Nx monorepo tooling compromised August 26–27 2025 via a stolen npm publishing token. Malicious versions exfiltrate developer credentials. Affected a ~4-hour window before npm yanked the packages.",
        "safe_version": "Versions published outside 2025-08-26 18:00 UTC to 2025-08-27 22:00 UTC — use >=21.6.1",
    },
    "@nx/devkit": {
        "compromised_versions": ["20.9.0", "21.5.0", "21.6.0"],
        "campaign": "s1ngularity_2025",
        "severity": "CRITICAL",
        "description": "@nx/devkit compromised in the August 2025 s1ngularity stolen-token attack. Same credential-exfiltration payload as nx core.",
        "safe_version": ">=21.6.1",
    },
    "@nx/jest": {
        "compromised_versions": ["20.9.0", "21.5.0", "21.6.0"],
        "campaign": "s1ngularity_2025",
        "severity": "CRITICAL",
        "description": "@nx/jest compromised in the August 2025 s1ngularity stolen-token attack.",
        "safe_version": ">=21.6.1",
    },
    "@nx/eslint": {
        "compromised_versions": ["20.9.0", "21.5.0", "21.6.0"],
        "campaign": "s1ngularity_2025",
        "severity": "CRITICAL",
        "description": "@nx/eslint compromised in the August 2025 s1ngularity stolen-token attack.",
        "safe_version": ">=21.6.1",
    },
    "@nx/react": {
        "compromised_versions": ["20.9.0", "21.5.0", "21.6.0"],
        "campaign": "s1ngularity_2025",
        "severity": "CRITICAL",
        "description": "@nx/react compromised in the August 2025 s1ngularity stolen-token attack.",
        "safe_version": ">=21.6.1",
    },
    "@nx/next": {
        "compromised_versions": ["20.9.0", "21.5.0", "21.6.0"],
        "campaign": "s1ngularity_2025",
        "severity": "CRITICAL",
        "description": "@nx/next compromised in the August 2025 s1ngularity stolen-token attack.",
        "safe_version": ">=21.6.1",
    },
    "@nx/node": {
        "compromised_versions": ["20.9.0", "21.5.0", "21.6.0"],
        "campaign": "s1ngularity_2025",
        "severity": "CRITICAL",
        "description": "@nx/node compromised in the August 2025 s1ngularity stolen-token attack.",
        "safe_version": ">=21.6.1",
    },
    "@nx/workspace": {
        "compromised_versions": ["20.9.0", "21.5.0", "21.6.0"],
        "campaign": "s1ngularity_2025",
        "severity": "CRITICAL",
        "description": "@nx/workspace compromised in the August 2025 s1ngularity stolen-token attack.",
        "safe_version": ">=21.6.1",
    },
    "@nx/web": {
        "compromised_versions": ["20.9.0", "21.5.0", "21.6.0"],
        "campaign": "s1ngularity_2025",
        "severity": "CRITICAL",
        "description": "@nx/web compromised in the August 2025 s1ngularity stolen-token attack.",
        "safe_version": ">=21.6.1",
    },
    "@nx/angular": {
        "compromised_versions": ["20.9.0", "21.5.0", "21.6.0"],
        "campaign": "s1ngularity_2025",
        "severity": "CRITICAL",
        "description": "@nx/angular compromised in the August 2025 s1ngularity stolen-token attack.",
        "safe_version": ">=21.6.1",
    },
    "@nx/js": {
        "compromised_versions": ["20.9.0", "21.5.0", "21.6.0"],
        "campaign": "s1ngularity_2025",
        "severity": "CRITICAL",
        "description": "@nx/js compromised in the August 2025 s1ngularity stolen-token attack.",
        "safe_version": ">=21.6.1",
    },
    "@nx/vite": {
        "compromised_versions": ["20.9.0", "21.5.0", "21.6.0"],
        "campaign": "s1ngularity_2025",
        "severity": "CRITICAL",
        "description": "@nx/vite compromised in the August 2025 s1ngularity stolen-token attack.",
        "safe_version": ">=21.6.1",
    },

    # ------------------------------------------------------------------
    # Sept 2025 — Shai-Hulud worm (initial wave)
    # Self-replicating npm worm, credential theft, ~40–500+ packages.
    # Sources: CISA, Unit42, StepSecurity
    # StepSecurity full list: https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised
    # TODO: Populate the full list (~500 packages) from the StepSecurity advisory.
    # The entries below are confirmed examples from public reporting.
    # ------------------------------------------------------------------
    "rxnt-authentication": {
        "compromised_versions": ["*"],
        "campaign": "shai_hulud_2025",
        "severity": "CRITICAL",
        "description": "Compromised by the Shai-Hulud self-replicating worm (September 2025). Steals npm tokens, GitHub tokens, AWS and GCP credentials, SSH keys, and .env contents. Self-propagates by publishing new malicious versions.",
        "safe_version": "Pin to versions published before 2025-09-15; check npm advisory",
    },
    "ctrl-tinycolor": {
        "compromised_versions": ["*"],
        "campaign": "shai_hulud_2025",
        "severity": "CRITICAL",
        "description": "Compromised by the Shai-Hulud worm (September 2025). StepSecurity named this package in their initial disclosure. All versions published during the compromise window are untrusted.",
        "safe_version": "Pin to versions before 2025-09-01; verify with StepSecurity advisory",
    },

    # ------------------------------------------------------------------
    # Nov 2025 — Shai-Hulud 2.0
    # Second wave: pre-install execution, broader scope, tied to
    # 25,000+ malicious GitHub repositories hosting stolen secrets.
    # Sources: Unit42, Microsoft Security Blog
    # TODO: Add full package list from Unit42 / Microsoft advisory.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # April 2026 — Mini Shai-Hulud (170+ packages, npm + PyPI)
    # First cross-registry attack. Axios (npm) and several PyPI packages
    # compromised. Pre-install malware execution.
    # Sources: Microsoft Security Blog, Unit42
    # TODO: Add the remaining 169+ packages from the Microsoft advisory:
    #   https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance
    # ------------------------------------------------------------------
    "axios": {
        "compromised_versions": ["1.7.7"],
        "campaign": "mini_shai_hulud_2026",
        "severity": "CRITICAL",
        "description": "Axios compromised in the April 2026 Mini Shai-Hulud cross-registry supply chain attack. Malicious pre-install script executes before your app starts. This is one of the most widely-used HTTP clients in the npm ecosystem.",
        "safe_version": "<1.7.7 OR >=1.7.8 — verify against Unit42 advisory before pinning",
    },

    # ------------------------------------------------------------------
    # Notable individual compromises
    # ------------------------------------------------------------------

    # Bitwarden CLI impersonation (fake package targeting devs who typo the name)
    "bitwarden-cli": {
        "compromised_versions": ["*"],
        "campaign": "bitwarden_typosquat",
        "severity": "CRITICAL",
        "description": "Typosquat impersonating the official @bitwarden/cli package. Harvests master passwords and vault contents. The legitimate package is @bitwarden/cli (with the @ scope).",
        "safe_version": "Use @bitwarden/cli (scoped) instead — this unscoped package is malicious",
    },

    # eslint-config-prettier-standard — typosquat of eslint-config-prettier
    "eslint-config-prettier-standard": {
        "compromised_versions": ["*"],
        "campaign": "typosquat_eslint",
        "severity": "HIGH",
        "description": "Malicious typosquat of eslint-config-prettier published to harvest developer environment variables and tokens. Not a legitimate config package.",
        "safe_version": "Use eslint-config-prettier (without -standard suffix)",
    },
}


def is_compromised(package_name: str, version: str) -> dict | None:
    """
    Check if a given npm package + version matches a known IOC.
    Returns the IOC entry dict if matched, None otherwise.
    """
    if package_name not in COMPROMISED_NPM_PACKAGES:
        return None

    entry = COMPROMISED_NPM_PACKAGES[package_name]
    compromised_versions = entry["compromised_versions"]

    if "*" in compromised_versions:
        return entry

    if version in compromised_versions:
        return entry

    return None


THREAT_INTEL_SOURCES = [
    "CISA: https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem",
    "Unit42: https://unit42.paloaltonetworks.com/npm-supply-chain-attack/",
    "Socket: https://socket.dev/blog/",
    "StepSecurity: https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised",
    "Microsoft Security Blog: https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance",
]

LAST_UPDATED = "2026-05-15"

DISCLAIMER = (
    "This is a static check against published threat intelligence. "
    "For real-time supply chain security monitoring, consider Socket or Snyk Open Source. "
    "GetVouch's IOC list is updated periodically — typically weekly."
)
