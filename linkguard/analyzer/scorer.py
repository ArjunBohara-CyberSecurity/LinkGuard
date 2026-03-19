"""Scoring system for LinkGuard."""
from __future__ import annotations

SCORES = {
    "keyword": 20,
    "ip": 30,
    "entropy": 15,
    "typosquat": 25,
    "homoglyph": 25,
    "brandish": 10,
    "punycode": 25,
    "hyphen": 10,
    "digits": 10,
    "domain_length": 10,
    "tld": 20,
    "subdomain": 15,
    "pattern": 10,
    "length": 10,
    "encoded": 10,
    "random": 15,
    "query": 10,
    "at": 20,
    "slashes": 10,
    "https_mislead": 15,
    "port": 15,
    "protocol": 10,
    "blacklist": 40,
    "invalid": 50,
}


def score_issues(issues: list[dict]) -> int:
    score = 0
    for issue in issues:
        score += SCORES.get(issue.get("type", ""), 5)
    return min(score, 100)


def verdict_from_score(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"
