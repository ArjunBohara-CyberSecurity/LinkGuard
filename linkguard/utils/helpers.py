"""Helper utilities for LinkGuard."""
from __future__ import annotations

import json
import os
import re
from urllib.parse import urlparse
import ipaddress

COMMON_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int",
    "io", "co", "us", "uk", "in", "au", "ca", "de", "fr", "jp", "cn",
    "ru", "br", "it", "es", "nl", "se", "no", "fi", "dk", "pl", "ch",
    "ae", "sa", "sg", "kr", "tr", "mx", "za", "nz", "ie", "pt", "gr",
    "be", "at", "id", "my", "ph", "th", "vn", "hk", "tw", "il",
    "me", "dev", "app", "tech", "cloud", "online", "site", "info", "biz",
}

MULTI_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.in", "firm.in", "net.in", "org.in",
    "com.br", "com.mx", "com.tr",
}

HOMOGLYPHS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
}


def normalize_url(url: str) -> tuple[str, bool]:
    url = (url or "").strip()
    had_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url))
    url = url.replace(" ", "")
    if not had_scheme and url:
        url = "http://" + url
    return url, had_scheme


def parse_url(url: str):
    return urlparse(url)


def extract_host(netloc: str) -> str:
    if not netloc:
        return ""
    # strip credentials
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]
    # IPv6 in brackets
    if netloc.startswith("[") and "]" in netloc:
        host = netloc.split("]", 1)[0][1:]
    else:
        host = netloc.split(":", 1)[0]
    return host.lower()


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def split_domain(host: str) -> tuple[str, str, list[str]]:
    parts = host.split(".")
    if len(parts) <= 1:
        return host, "", []

    last_two = ".".join(parts[-2:])
    if last_two in MULTI_TLDS and len(parts) >= 3:
        tld = last_two
        sld = parts[-3]
        domain = f"{sld}.{tld}"
        subdomains = parts[:-3]
        return domain, tld, subdomains

    tld = parts[-1]
    sld = parts[-2] if len(parts) >= 2 else ""
    if tld not in COMMON_TLDS and len(parts) >= 3:
        # guess last two as domain for unknown tlds
        sld = parts[-2]
    domain = f"{sld}.{tld}" if sld else host
    subdomains = parts[:-2] if len(parts) > 2 else []
    return domain, tld, subdomains


def normalize_homoglyphs(text: str) -> str:
    return "".join(HOMOGLYPHS.get(c, c) for c in text.lower())


def has_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    digits = sum(1 for c in text if c.isdigit())
    return digits / max(1, len(text))


def load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    # tolerate UTF-8 BOM if present
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def color(text: str, name: str) -> str:
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "reset": "\033[0m",
    }
    return f"{colors.get(name, '')}{text}{colors['reset']}"
