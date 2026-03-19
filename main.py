"""LinkGuard - Offline Phishing URL Detection Tool"""
from __future__ import annotations

import argparse
import os
from datetime import datetime

from linkguard.analyzer.engine import analyze_url, load_lists
from linkguard.utils.helpers import color, ensure_dir


def print_report(result: dict) -> None:
    meta = result["meta"]
    issues = result["issues"]
    score = result["score"]
    verdict = result["verdict"]

    print(color("[!] URL:", "yellow"), meta.get("raw_url", ""))
    print(color("[!] Normalized:", "yellow"), meta.get("normalized_url", ""))
    print(color("[!] Host:", "yellow"), meta.get("host", ""))

    if meta.get("domain"):
        print(color("[!] Domain:", "yellow"), meta.get("domain"))
    if meta.get("tld"):
        print(color("[!] TLD:", "yellow"), meta.get("tld"))

    if not issues:
        print(color("[+] Issues Detected:", "green"), "None")
    else:
        print(color("[+] Issues Detected:", "green"))
        for i in issues:
            print(f"- {i['detail']}")

    score_color = "green" if score < 40 else "yellow" if score < 70 else "red"
    verdict_color = "green" if verdict == "LOW" else "yellow" if verdict == "MEDIUM" else "red"
    print(color("[!] Risk Score:", score_color), score)
    print(color("[!] Verdict:", verdict_color), f"{verdict} RISK")


def save_report(result: dict, out_dir: str) -> str:
    ensure_dir(out_dir)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"report_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        import json

        json.dump(result, f, indent=2)
    return path


def load_urls_from_file(path: str) -> list[str]:
    urls = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def main() -> None:
    parser = argparse.ArgumentParser(description="LinkGuard - Offline Phishing URL Detector")
    parser.add_argument("-u", "--url", help="Single URL to analyze")
    parser.add_argument("-f", "--file", help="File with URLs (one per line)")
    parser.add_argument("-s", "--save", action="store_true", help="Save report JSON")
    parser.add_argument("--ui", action="store_true", help="Launch GUI (customtkinter)")
    args = parser.parse_args()

    whitelist, blacklist = load_lists()
    base_dir = os.path.dirname(__file__)
    reports_dir = os.path.join(base_dir, "linkguard", "reports")

    if args.ui:
        from linkguard.ui import main as ui_main

        ui_main()
        return

    if args.file:
        urls = load_urls_from_file(args.file)
        for u in urls:
            result = analyze_url(u, whitelist, blacklist)
            print_report(result)
            print("")
            if args.save:
                path = save_report(result, reports_dir)
                print(color("[+] Saved:", "green"), path)
        return

    if args.url:
        result = analyze_url(args.url, whitelist, blacklist)
        print_report(result)
        if args.save:
            path = save_report(result, reports_dir)
            print(color("[+] Saved:", "green"), path)
        return

    # interactive
    try:
        while True:
            url = input("Enter URL (or 'q' to quit): ").strip()
            if url.lower() in {"q", "quit", "exit"}:
                break
            result = analyze_url(url, whitelist, blacklist)
            print_report(result)
            print("")
    except KeyboardInterrupt:
        print("\nExiting.")


if __name__ == "__main__":
    main()
