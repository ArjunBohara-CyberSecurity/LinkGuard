"""Entropy calculations for LinkGuard."""
from __future__ import annotations

import math


def entropy_score(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    ent = 0.0
    length = len(text)
    for c in counts.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent
