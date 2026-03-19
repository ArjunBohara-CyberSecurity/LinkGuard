"""Core analysis engine for LinkGuard."""
from __future__ import annotations

import os

from linkguard.analyzer.domain_check import analyze_domain
from linkguard.analyzer.pattern_check import analyze_patterns
from linkguard.analyzer.entropy import entropy_score
from linkguard.analyzer.scorer import score_issues, verdict_from_score
from linkguard.utils.helpers import normalize_url, parse_url, extract_host, load_json


def _data_dir() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


def load_lists() -> tuple[set[str], dict]:
    data_dir = _data_dir()
    whitelist = set(load_json(os.path.join(data_dir, "whitelist.json")).get("domains", []))
    blacklist = load_json(os.path.join(data_dir, "blacklist.json"))
    return whitelist, blacklist


def analyze_url(url: str, whitelist: set[str], blacklist: dict) -> dict:
    raw_url = url
    normalized, had_scheme = normalize_url(url)
    parsed = parse_url(normalized)

    host = extract_host(parsed.netloc)
    issues = []
    meta = {
        "raw_url": raw_url,
        "normalized_url": normalized,
        "scheme": parsed.scheme,
        "host": host,
        "path": parsed.path,
        "query": parsed.query,
        "had_scheme": had_scheme,
    }

    if not host:
        issues.append({"type": "invalid", "detail": "Could not extract host"})
        score = 100
        verdict = "HIGH"
        return {"meta": meta, "issues": issues, "score": score, "verdict": verdict}

    if host in whitelist:
        issues.append({"type": "whitelist", "detail": "Domain is whitelisted"})
        return {"meta": meta, "issues": issues, "score": 0, "verdict": "LOW"}

    bl_hits = []
    for item in blacklist.get("domains", []):
        if host == item:
            bl_hits.append(f"Blacklisted domain: {item}")
    for pattern in blacklist.get("patterns", []):
        try:
            import re

            if re.search(pattern, normalized, re.IGNORECASE):
                bl_hits.append(f"Blacklisted pattern: {pattern}")
        except re.error:
            continue
    for hit in bl_hits:
        issues.append({"type": "blacklist", "detail": hit})

    if not parsed.scheme:
        issues.append({"type": "protocol", "detail": "Missing URL scheme"})
    elif parsed.scheme.lower() != "https":
        issues.append({"type": "protocol", "detail": "Not using HTTPS"})

    domain_issues, domain_meta = analyze_domain(host)
    issues.extend(domain_issues)
    meta.update(domain_meta)

    pattern_issues = analyze_patterns(normalized, parsed)
    issues.extend(pattern_issues)

    ent = entropy_score(normalized)
    if ent >= 4.2:
        issues.append({"type": "entropy", "detail": f"High URL entropy ({ent:.2f})"})
    meta["url_entropy"] = ent

    score = score_issues(issues)
    verdict = verdict_from_score(score)

    if bl_hits and verdict != "HIGH":
        verdict = "HIGH"
        score = max(score, 90)

    return {"meta": meta, "issues": issues, "score": score, "verdict": verdict}
