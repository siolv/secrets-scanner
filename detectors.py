"""Detection rules for the secrets scanner.

Each rule is a regex with one named group, ``secret``. The scanner masks that
group before anything is written to disk, so the report never repeats a live
credential. Rotation instructions live in rotation.py.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    provider: str
    pattern: re.Pattern
    severity: str                 # Critical / High / Medium
    description: str
    priority: int = 10            # higher wins when two rules match one secret
    min_length: int = 8
    min_entropy: float = 0.0      # 0 disables the entropy check
    mask_style: str = "partial"   # partial | header


RULES: list[Rule] = [
    Rule(
        id="aws_access_key",
        name="AWS access key ID",
        provider="aws",
        pattern=re.compile(r"\b(?P<secret>AKIA[0-9A-Z]{16})\b"),
        severity="Critical",
        description="A live-looking AWS access key ID. Anyone with the paired "
        "secret can use your AWS account and bill you.",
        priority=100,
        min_length=20,
    ),
    Rule(
        id="aws_secret_key",
        name="AWS secret access key",
        provider="aws",
        pattern=re.compile(
            r"(?i)aws_?secret_?access_?key\s*[:=]\s*[\"']?"
            r"(?P<secret>[A-Za-z0-9/+=]{40})"
        ),
        severity="Critical",
        description="The secret half of an AWS key pair. Paired with an access key "
        "ID, it gives full access to whatever that IAM user can do.",
        priority=95,
        min_length=40,
        min_entropy=3.2,
    ),
    Rule(
        id="github_token",
        name="GitHub token",
        provider="github",
        pattern=re.compile(r"\b(?P<secret>gh[pousr]_[A-Za-z0-9]{20,})\b"),
        severity="Critical",
        description="A GitHub personal access token. It can read or change code, "
        "issues, and sometimes organization settings.",
        priority=100,
    ),
    Rule(
        id="github_fine_grained",
        name="GitHub fine-grained token",
        provider="github",
        pattern=re.compile(r"\b(?P<secret>github_pat_[A-Za-z0-9_]{20,})\b"),
        severity="Critical",
        description="A fine-grained GitHub token. Its power depends on the scopes "
        "it was given, but treat it as live until proven revoked.",
        priority=100,
    ),
    Rule(
        id="slack_token",
        name="Slack token",
        provider="slack",
        pattern=re.compile(r"\b(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        severity="Critical",
        description="A Slack bot or user token. It can read messages and post as "
        "the app or user.",
        priority=100,
    ),
    Rule(
        id="google_api_key",
        name="Google API key",
        provider="google",
        pattern=re.compile(r"\b(?P<secret>AIza[0-9A-Za-z_-]{35})\b"),
        severity="High",
        description="A Google API key. It can bill requests to your project and, "
        "depending on restrictions, reach enabled APIs.",
        priority=100,
    ),
    Rule(
        id="stripe_live_key",
        name="Stripe live secret key",
        provider="stripe",
        pattern=re.compile(r"\b(?P<secret>(?:sk|rk)_live_[0-9A-Za-z]{16,})\b"),
        severity="Critical",
        description="A live Stripe key. It can create charges, read customers, "
        "and issue refunds.",
        priority=100,
    ),
    Rule(
        id="openai_key",
        name="OpenAI API key",
        provider="openai",
        pattern=re.compile(r"\b(?P<secret>sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b"),
        severity="High",
        description="An OpenAI-style API key. It can spend your balance.",
        priority=90,
    ),
    Rule(
        id="anthropic_key",
        name="Anthropic API key",
        provider="anthropic",
        pattern=re.compile(r"\b(?P<secret>sk-ant-[A-Za-z0-9_-]{20,})\b"),
        severity="High",
        description="An Anthropic API key. It can spend your balance.",
        priority=100,
    ),
    Rule(
        id="sendgrid_key",
        name="SendGrid API key",
        provider="sendgrid",
        pattern=re.compile(
            r"\b(?P<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"
        ),
        severity="High",
        description="A SendGrid key. It can send email as your verified domains.",
        priority=100,
    ),
    Rule(
        id="twilio_key",
        name="Twilio API key",
        provider="twilio",
        pattern=re.compile(r"\b(?P<secret>SK[0-9a-f]{32})\b"),
        severity="High",
        description="A Twilio API key. It can send messages and charge your account.",
        priority=80,
    ),
    Rule(
        id="private_key_block",
        name="Private key block",
        provider="private_key",
        pattern=re.compile(
            r"-----BEGIN (?P<secret>(?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY)-----"
        ),
        severity="Critical",
        description="A private key file. It can impersonate a server, a user, or "
        "a signing identity.",
        priority=100,
        min_length=10,
        mask_style="header",
    ),
    Rule(
        id="url_credentials",
        name="Password inside a URL",
        provider="url_credentials",
        pattern=re.compile(
            r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:(?P<secret>[^/\s@]{6,})@",
            re.I,
        ),
        severity="High",
        description="A username and password embedded in a link. Anyone with the "
        "link can sign in without a second step.",
        priority=80,
    ),
    Rule(
        id="jwt",
        name="JSON Web Token",
        provider="jwt",
        pattern=re.compile(
            r"\b(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
            r"\.[A-Za-z0-9_-]{10,})\b"
        ),
        severity="Medium",
        description="A signed session token. It may stay valid until it expires, "
        "even after a password change.",
        priority=60,
        min_length=30,
    ),
    Rule(
        id="discord_webhook",
        name="Discord webhook link",
        provider="discord",
        pattern=re.compile(
            r"(?P<secret>https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/"
            r"\d+/[A-Za-z0-9_-]+)"
        ),
        severity="Medium",
        description="A Discord webhook URL. Anyone holding it can post into that "
        "channel, and deleting the message does not revoke it.",
        priority=100,
        min_length=40,
    ),
    Rule(
        id="dotenv_assignment",
        name="Sensitive .env value",
        provider="generic",
        pattern=re.compile(
            r"(?i)^[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)"
            r"[A-Z0-9_]*\s*=\s*(?P<secret>[^\s#\"']{8,})"
        ),
        severity="High",
        description="A secret-looking value in an environment file. These files "
        "are often copied into backups, zips, and chat.",
        priority=50,
        min_entropy=2.5,
    ),
    Rule(
        id="generic_assignment",
        name="Secret-looking assignment",
        provider="generic",
        pattern=re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|passwd|password|client_secret|"
            r"access_key)\b\s*[:=]\s*[\"'](?P<secret>[^\"'\s]{12,})[\"']"
        ),
        severity="Medium",
        description="A value assigned to a secret-looking name. It may be a real "
        "credential or a placeholder; the report flags it for a human check.",
        priority=10,
        min_entropy=2.8,
    ),
]

RULES_BY_ID = {rule.id: rule for rule in RULES}
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

PLACEHOLDER_WORDS = (
    "example",
    "sample",
    "your_",
    "your-",
    "yourkey",
    "changeme",
    "change_me",
    "replace",
    "placeholder",
    "dummy",
    "fake",
    "redacted",
    "todo",
    "fixme",
    "xxxx",
    "****",
    "....",
    "${",
    "{{",
    "<",
    ">",
    "none",
    "null",
    "undefined",
    "password",
    "secret",
)

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".gz", ".7z", ".rar", ".tar", ".mp3", ".mp4", ".mov",
    ".avi", ".mkv", ".wav", ".flac", ".exe", ".dll", ".so", ".dylib",
    ".woff", ".woff2", ".ttf", ".otf", ".class", ".pyc", ".sqlite", ".db",
}


def shannon_entropy(text: str) -> float:
    """How random a string looks. Low means repeated or dictionary-like."""
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum(
        (count / total) * math.log2(count / total) for count in counts.values()
    )


def looks_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    if not lowered:
        return True
    if any(word in lowered for word in PLACEHOLDER_WORDS):
        return True
    if len(set(lowered)) <= 2:
        return True
    return False


def mask_secret(value: str, style: str = "partial") -> str:
    """Show just enough to recognise a key without publishing it."""
    value = value.strip()
    if style == "header":
        return "-----BEGIN [REDACTED] PRIVATE KEY-----"
    if len(value) <= 8:
        return "*" * len(value)
    keep = 4
    hidden = "*" * min(24, max(4, len(value) - keep * 2))
    return f"{value[:keep]}{hidden}{value[-keep:]}"


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:12]


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    provider: str
    severity: str
    path: str
    line: int
    line_text: str
    masked: str
    fingerprint: str
    source: str = "working tree"      # or "git history"
    commit: str = ""
    commit_date: str = ""
    commit_author: str = ""

    @property
    def location(self) -> str:
        if self.source == "git history":
            short = self.commit[:8]
            return f"commit {short} ({self.commit_date[:10]}) {self.path}:{self.line}"
        return f"{self.path}:{self.line}"


def scan_line(
    line: str,
    path: str,
    line_number: int,
    source: str = "working tree",
    commit: str = "",
    commit_date: str = "",
    commit_author: str = "",
) -> list[Finding]:
    """Run every rule over one line and return masked findings."""
    lowered = line.lower()
    if "secrets:ignore" in lowered or "pragma: allowlist secret" in lowered:
        return []
    found: list[Finding] = []
    for rule in RULES:
        for match in rule.pattern.finditer(line):
            secret = match.group("secret").strip()
            if len(secret) < rule.min_length:
                continue
            if looks_placeholder(secret):
                continue
            if rule.min_entropy and shannon_entropy(secret) < rule.min_entropy:
                continue
            masked = mask_secret(secret, rule.mask_style)
            preview = line.replace(secret, masked).strip()
            if len(preview) > 220:
                preview = preview[:217] + "..."
            found.append(
                Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    provider=rule.provider,
                    severity=rule.severity,
                    path=path,
                    line=line_number,
                    line_text=preview,
                    masked=masked,
                    fingerprint=fingerprint(secret),
                    source=source,
                    commit=commit,
                    commit_date=commit_date,
                    commit_author=commit_author,
                )
            )
    # One secret can match a provider rule and the generic rule. Keep the most
    # specific rule so the report does not count the same leak twice.
    best: dict[tuple[str, int], Finding] = {}
    for finding in found:
        key = (finding.fingerprint, finding.line)
        current = best.get(key)
        if current is None or RULES_BY_ID[finding.rule_id].priority > RULES_BY_ID[
            current.rule_id
        ].priority:
            best[key] = finding
    return list(best.values())
