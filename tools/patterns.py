"""Secret, placeholder and hidden-Unicode patterns plugin_intake.py needs, copied verbatim from scan.py."""

import re

SECRET_PATTERNS = [
    ("AWS access key", r"AKIA[0-9A-Z]{16}"),
    ("GitHub token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("Anthropic key", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("OpenAI-style key", r"sk-(?:proj-)?[A-Za-z0-9]{32,}"),
    ("Slack token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("Google API key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("Stripe live key", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    (
        "Generic secret assignment",
        r"(?i)(?:api[_-]?key|secret|passwd|password|token)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-/+=]{16,})[\"']",
    ),
]
PLACEHOLDER = re.compile(
    r"(?i)(example|placeholder|changeme|your[_-]|xxxx|dummy|<.*>|\$\{)"
)

HIDDEN_UNICODE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\u00ad\u180e]|[\U000e0000-\U000e007f]"
)


def safe_line(text, mask=()):
    """Make a snippet line safe to print: mask secrets, make hidden Unicode visible.

    A run of Unicode tag characters (ASCII smuggling) becomes one ⟦hidden: "decoded text"⟧
    marker; any other invisible character becomes ⟦U+XXXX⟧.
    """
    text = re.sub(
        "[\U000e0000-\U000e007f]+",
        lambda x: f'⟦hidden: "{render_unicode_tag(x.group(0))}"⟧',
        text,
    )
    for m in mask:
        if m:
            text = text.replace(m, m[:4] + "…[masked]")
    for _, pat in SECRET_PATTERNS:
        text = re.sub(pat, lambda x: x.group(0)[:6] + "…[masked]", text)
    text = re.sub(
        r"[A-Za-z0-9+/=_-]{40,}", lambda x: x.group(0)[:4] + "…[masked]", text
    )
    return HIDDEN_UNICODE.sub(lambda x: f"⟦U+{ord(x.group(0)):04X}⟧", text)[:240]


def render_unicode_tag(line):
    """Decode Unicode tag characters (U+E0020..E007E), the 'ASCII smuggling' channel, back to text."""
    return "".join(chr(ord(c) - 0xE0000) for c in line if 0xE0020 <= ord(c) <= 0xE007E)


def location(rel, text, lines=(), before=2, after=2, mask=()):
    """Build a location dict. The snippet merges nearby hits; None marks a gap."""
    if text is None:
        return {"file": rel, "lines": [], "snippet": [], "note": "file does not exist"}
    src = text.splitlines()
    hits = sorted({n for n in lines if n})
    if not hits:
        return {"file": rel, "lines": [], "snippet": []}
    snip, last = [], 0
    for n in hits:
        lo, hi = max(1, n - before), min(len(src), n + after)
        if last and lo > last + 1:
            snip.append([None, "…"])
        for k in range(max(lo, last + 1), hi + 1):
            snip.append([k, safe_line(src[k - 1], mask)])
        last = max(last, hi)
    return {"file": rel, "lines": hits, "snippet": snip}


