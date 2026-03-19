"""LinkGuard GUI (CustomTkinter)."""
from __future__ import annotations

import json
import math
import os
import sys
from datetime import datetime

if __package__ in {None, ""}:
    parent_dir = os.path.dirname(os.path.dirname(__file__))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)

try:
    import customtkinter as ctk
except Exception:  # pragma: no cover
    ctk = None

from linkguard.analyzer.engine import analyze_url, load_lists
from linkguard.utils.helpers import ensure_dir


class LinkGuardUI:
    def __init__(self) -> None:
        if ctk is None:
            raise RuntimeError("customtkinter is not installed")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.app = ctk.CTk()
        self.app.title("LinkGuard - Offline Phishing Detector")
        self.app.geometry("900x560")
        self.app.minsize(780, 520)

        self._build_layout()

    def _build_layout(self) -> None:
        container = ctk.CTkFrame(self.app, corner_radius=12)
        container.pack(fill="both", expand=True, padx=18, pady=18)

        self.title_label = ctk.CTkLabel(
            container,
            text="LINKGUARD",
            font=("Segoe UI", 28, "bold"),
            text_color="#FF4D4D",
        )
        self.title_label.pack(anchor="w", padx=18, pady=(18, 0))

        self.neon_bar = ctk.CTkProgressBar(
            container,
            height=6,
            corner_radius=10,
            fg_color="#222222",
            progress_color="#FF4D4D",
        )
        self.neon_bar.pack(fill="x", padx=18, pady=(6, 12))
        self.neon_bar.configure(mode="indeterminate")
        self.neon_bar.start()

        subtitle = ctk.CTkLabel(
            container,
            text="Offline Phishing URL Detection",
            font=("Segoe UI", 14),
            text_color="#B0B0B0",
        )
        subtitle.pack(anchor="w", padx=18, pady=(0, 12))

        self.url_entry = ctk.CTkEntry(
            container,
            placeholder_text="Enter URL to scan",
            height=40,
            font=("Segoe UI", 14),
        )
        self.url_entry.pack(fill="x", padx=18, pady=(0, 12))

        btn_row = ctk.CTkFrame(container, fg_color="transparent")
        btn_row.pack(fill="x", padx=18)

        scan_btn = ctk.CTkButton(
            btn_row,
            text="Scan",
            height=36,
            fg_color="#FF4D4D",
            hover_color="#E13B3B",
            font=("Segoe UI", 13, "bold"),
            command=self.scan,
        )
        scan_btn.pack(side="left")

        clear_btn = ctk.CTkButton(
            btn_row,
            text="Clear",
            height=36,
            fg_color="#303030",
            hover_color="#3C3C3C",
            font=("Segoe UI", 12),
            command=self.clear,
        )
        clear_btn.pack(side="left", padx=(10, 0))

        save_btn = ctk.CTkButton(
            btn_row,
            text="Save Report",
            height=36,
            fg_color="#1F6FEB",
            hover_color="#1B5BC5",
            font=("Segoe UI", 12),
            command=self.save_report,
        )
        save_btn.pack(side="left", padx=(10, 0))

        self.verdict_label = ctk.CTkLabel(
            container,
            text="Verdict: -",
            font=("Segoe UI", 16, "bold"),
            text_color="#B0B0B0",
        )
        self.verdict_label.pack(anchor="w", padx=18, pady=(16, 6))

        self.score_label = ctk.CTkLabel(
            container,
            text="Risk Score: -",
            font=("Segoe UI", 14),
            text_color="#B0B0B0",
        )
        self.score_label.pack(anchor="w", padx=18)

        self.output_box = ctk.CTkTextbox(
            container,
            wrap="word",
            font=("Consolas", 12),
            height=220,
        )
        self.output_box.pack(fill="both", expand=True, padx=18, pady=(12, 18))

        self.output_box.insert("1.0", "Scan a URL to see detailed results...\n")
        self.output_box.configure(state="disabled")

        self.last_result = None
        self._pulse_t = 0.0
        self._animate()

    def _animate(self) -> None:
        # Subtle neon pulse on title and bar
        self._pulse_t += 0.08
        glow = (math.sin(self._pulse_t) + 1.0) / 2.0
        r = int(220 + 35 * glow)
        g = int(60 + 30 * glow)
        b = int(60 + 30 * glow)
        color_hex = f"#{r:02X}{g:02X}{b:02X}"
        self.title_label.configure(text_color=color_hex)
        self.neon_bar.configure(progress_color=color_hex)
        self.app.after(60, self._animate)

    def _render(self, result: dict) -> None:
        meta = result["meta"]
        issues = result["issues"]
        score = result["score"]
        verdict = result["verdict"]

        verdict_color = "#7CFC90" if verdict == "LOW" else "#FFD166" if verdict == "MEDIUM" else "#FF4D4D"
        self.verdict_label.configure(text=f"Verdict: {verdict} RISK", text_color=verdict_color)
        self.score_label.configure(text=f"Risk Score: {score}")

        lines = []
        lines.append(f"URL: {meta.get('raw_url', '')}")
        lines.append(f"Normalized: {meta.get('normalized_url', '')}")
        lines.append(f"Host: {meta.get('host', '')}")
        if meta.get("domain"):
            lines.append(f"Domain: {meta.get('domain')}")
        if meta.get("tld"):
            lines.append(f"TLD: .{meta.get('tld')}")
        lines.append("")

        if not issues:
            lines.append("Issues Detected: None")
        else:
            lines.append("Issues Detected:")
            for i in issues:
                lines.append(f"- {i['detail']}")

        self.output_box.configure(state="normal")
        self.output_box.delete("1.0", "end")
        self.output_box.insert("1.0", "\n".join(lines))
        self.output_box.configure(state="disabled")

    def scan(self) -> None:
        url = self.url_entry.get().strip()
        if not url:
            return
        self.verdict_label.configure(text="Verdict: SCANNING...", text_color="#66D9FF")
        self.app.update_idletasks()
        whitelist, blacklist = load_lists()
        result = analyze_url(url, whitelist, blacklist)
        self.last_result = result
        self._render(result)

    def clear(self) -> None:
        self.url_entry.delete(0, "end")
        self.output_box.configure(state="normal")
        self.output_box.delete("1.0", "end")
        self.output_box.insert("1.0", "Scan a URL to see detailed results...\n")
        self.output_box.configure(state="disabled")
        self.verdict_label.configure(text="Verdict: -", text_color="#B0B0B0")
        self.score_label.configure(text="Risk Score: -")
        self.last_result = None

    def save_report(self) -> None:
        if not self.last_result:
            return
        out_dir = os.path.join(os.path.dirname(__file__), "reports")
        ensure_dir(out_dir)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(out_dir, f"report_{ts}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.last_result, f, indent=2)
        self.output_box.configure(state="normal")
        self.output_box.insert("end", f"\n\nSaved report to {path}")
        self.output_box.configure(state="disabled")

    def run(self) -> None:
        self.app.mainloop()


def main() -> None:
    if ctk is None:
        print("customtkinter is not installed. Install with: pip install customtkinter")
        sys.exit(1)
    ui = LinkGuardUI()
    ui.run()


if __name__ == "__main__":
    main()
