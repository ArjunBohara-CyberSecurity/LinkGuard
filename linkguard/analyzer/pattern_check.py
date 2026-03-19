"""Pattern analysis for LinkGuard."""
from __future__ import annotations

import re
from urllib.parse import ParseResult

from linkguard.analyzer.entropy import entropy_score

KEYWORDS = {
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "free",
    "bonus",
    "bank",
    "password",
    "signin",
    "confirm",
    "unlock",
    "support",
    "alert",
}

ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")


def analyze_patterns(url: str, parsed: ParseResult) -> list[dict]:
    issues: list[dict] = []

    # keywords
    lowered = url.lower()
    hits = [kw for kw in KEYWORDS if kw in lowered]
    if hits:
        issues.append({"type": "keyword", "detail": f"Contains phishing keywords: {', '.join(sorted(hits))}"})

    # hyphens and dots
    hyphens = url.count("-")
    dots = url.count(".")
    if hyphens >= 4:
        issues.append({"type": "pattern", "detail": "Excessive hyphens"})
    if dots >= 5:
        issues.append({"type": "pattern", "detail": "Excessive dots"})

    # suspicious separators
    if "@" in url:
        issues.append({"type": "at", "detail": "Contains '@' in URL"})

    if "//" in parsed.path:
        issues.append({"type": "slashes", "detail": "Double slashes in path"})

    # long URL
    if len(url) >= 90:
        issues.append({"type": "length", "detail": "Very long URL"})

    # encoded chars
    if ENCODED_RE.search(url):
        issues.append({"type": "encoded", "detail": "Contains URL-encoded characters"})

    # random-looking labels
    labels = [p for p in parsed.path.split("/") if p]
    for label in labels[:4]:  # limit noise
        if len(label) >= 12 and entropy_score(label) >= 3.8:
            issues.append({"type": "random", "detail": "Random-looking path segment"})
            break

    # misleading https in path/query
    if parsed.scheme.lower() == "http" and "https" in url.lower():
        issues.append({"type": "https_mislead", "detail": "HTTPS mentioned in path/query on HTTP URL"})

    # odd ports
    if parsed.port and parsed.port not in {80, 443}:
        issues.append({"type": "port", "detail": f"Unusual port: {parsed.port}"})

    # suspicious query
    if parsed.query and len(parsed.query) >= 60:
        issues.append({"type": "query", "detail": "Large query string"})

    return issues
