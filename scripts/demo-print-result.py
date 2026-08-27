#!/usr/bin/env python3
"""Plain-English summary for demo recordings."""
from __future__ import annotations

import json
import sys


def main() -> None:
    path = sys.argv[1]
    label = sys.argv[2] if len(sys.argv) > 2 else "Result"
    r = json.load(open(path, encoding="utf-8"))

    score = float(r.get("score", 0))
    verdict = r.get("threat_level", "Unknown")
    target = r.get("target", "?")

    hits = [i for i in r.get("indicators", []) if i.get("triggered")]
    lines: list[str] = []
    for i in hits:
        proto = (i.get("protocol") or "?").upper()
        title = i.get("title") or "indicator"
        detail = (i.get("detail") or "").strip()
        if detail and len(detail) < 100:
            line = f"  • [{proto}] {title} — {detail}"
        else:
            line = f"  • [{proto}] {title}"
        if proto == "NMAP":
            lines.insert(0, line)
        else:
            lines.append(line)

    bar = "=" * 58
    print()
    print(bar)
    print(f"  {label}")
    print(bar)
    print(f"  Target  : {target}")
    print(f"  Score   : {score:.0f}%")
    print(f"  Verdict : {verdict}")
    print()
    if lines:
        print("  Key findings:")
        for line in lines[:6]:
            print(line)
        if len(lines) > 6:
            print(f"  … and {len(lines) - 6} more (see JSON report)")
    else:
        print("  No honeypot indicators on the ports tested.")
    print(bar)
    print()


if __name__ == "__main__":
    main()
