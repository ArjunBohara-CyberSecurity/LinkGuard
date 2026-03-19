"""Domain analysis for LinkGuard."""
from __future__ import annotations

import ipaddress

from linkguard.utils.helpers import split_domain, is_ip, normalize_homoglyphs, has_punycode, digit_ratio


BRANDS = {
    "google",
    "facebook",
    "amazon",
    "apple",
    "microsoft",
    "paypal",
    "netflix",
    "instagram",
    "linkedin",
    "github",
    "dropbox",
    "twitter",
    "x",
    "tiktok",
    "snapchat",
    "whatsapp",
    "telegram",
    "discord",
    "reddit",
    "pinterest",
    "youtube",
    "spotify",
    "zoom",
    "slack",
    "salesforce",
    "oracle",
    "ibm",
    "intel",
    "amd",
    "nvidia",
    "samsung",
    "huawei",
    "xiaomi",
    "sony",
    "adidas",
    "nike",
    "ebay",
    "walmart",
    "target",
    "costco",
    "bestbuy",
    "shopify",
    "etsy",
    "aliexpress",
    "flipkart",
    "paytm",
    "phonepe",
    "venmo",
    "cashapp",
    "stripe",
    "square",
    "wise",
    "bankofamerica",
    "chase",
    "wellsfargo",
    "citibank",
    "hsbc",
    "barclays",
    "santander",
    "natwest",
    "ing",
    "standardchartered",
    "icici",
    "hdfc",
    "axisbank",
    "sbi",
    "kotak",
    "yesbank",
    "pnc",
    "usbank",
    "capitalone",
    "americanexpress",
    "mastercard",
    "visa",
    "discover",
    "adobe",
    "office365",
    "outlook",
    "yahoo",
    "steam",
    "epicgames",
    "roblox",
    "riotgames",
    "twitch",
    "blizzard",
    "playstation",
    "xbox",
    "coinbase",
    "binance",
    "kraken",
    "metamask",
    "blockchain",
    "proton",
    "protonmail",
    "icloud",
    "gmail",
    "mail",
    "canva",
    "notion",
    "figma",
    "airbnb",
    "booking",
    "expedia",
    "uber",
    "ola",
    "lyft",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
    "work",
    "click",
    "link",
    "zip",
    "mov",
    "cam",
    "men",
    "rest",
    "bar",
    "icu",
    "quest",
    "fit",
    "surf",
    "lol",
}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(
                prev[j] + 1,      # deletion
                curr[j - 1] + 1,  # insertion
                prev[j - 1] + cost  # substitution
            ))
        prev = curr
    return prev[-1]


def analyze_domain(host: str) -> tuple[list[dict], dict]:
    issues: list[dict] = []
    meta: dict = {}

    if is_ip(host):
        issues.append({"type": "ip", "detail": "IP-based URL"})
        return issues, meta

    if has_punycode(host):
        issues.append({"type": "punycode", "detail": "Punycode domain detected"})

    domain, tld, subdomains = split_domain(host)
    meta["domain"] = domain
    meta["tld"] = tld
    meta["subdomains"] = subdomains

    if tld in SUSPICIOUS_TLDS:
        issues.append({"type": "tld", "detail": f"Suspicious TLD (.{tld})"})

    # subdomain abuse
    for label in subdomains:
        label_norm = normalize_homoglyphs(label)
        if label_norm in BRANDS and label_norm not in domain:
            issues.append({"type": "subdomain", "detail": f"Brand in subdomain: {label}"})
            break

    # typosquatting / brand-like domain / homoglyph spoof
    domain_label = domain.split(".")[0] if domain else ""
    if domain_label:
        domain_norm = normalize_homoglyphs(domain_label)
        for brand in BRANDS:
            if domain_norm == brand and domain_label != brand:
                issues.append({"type": "homoglyph", "detail": f"Homoglyph spoofing ({brand})"})
                break
            if domain_norm == brand:
                continue
            if levenshtein(domain_norm, brand) <= 2:
                issues.append({"type": "typosquat", "detail": f"Possible typosquatting ({brand})"})
                break
            if normalize_homoglyphs(domain_label) == brand:
                issues.append({"type": "typosquat", "detail": f"Possible typosquatting ({brand})"})
                break
            if brand in domain_norm and domain_norm != brand:
                issues.append({"type": "brandish", "detail": f"Brand-like domain: {brand}"})
                break

        # hyphen tricks
        if domain_label.startswith("-") or domain_label.endswith("-") or "--" in domain_label:
            issues.append({"type": "hyphen", "detail": "Suspicious hyphen placement"})

        # digit-heavy domains
        if len(domain_label) >= 6 and digit_ratio(domain_label) >= 0.4:
            issues.append({"type": "digits", "detail": "Digit-heavy domain label"})

    # too many subdomains
    if len(subdomains) >= 3:
        issues.append({"type": "subdomain", "detail": "Excessive subdomains"})

    if len(host) >= 60:
        issues.append({"type": "domain_length", "detail": "Very long host name"})

    return issues, meta
