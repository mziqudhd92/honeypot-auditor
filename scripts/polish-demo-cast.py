#!/usr/bin/env python3
"""Polish an asciinema v2 cast for demo GIFs.

Compress long probe/progress waits, but PRESERVE human reading pauses after
results (marked ``reading pause`` in the demo script).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Start of a protected reading window (demo prints this explicitly).
READING_PAUSE = re.compile(r"reading pause", re.I)

# Also treat finale scoreboard as a reading window if marker is missing.
RESULT_SETTLE = re.compile(
    r"(Why this score|Report written|SCOREBOARD|TOUR COMPLETE|demo finished|"
    r"Suspected Honeypot|Confirmed Honeypot|Key findings)",
    re.I,
)

PROGRESS_MARKERS = re.compile(
    r"(Auditing target|Finished |probing|deep audit in progress|▮|⠋|⠙|⠹|⠸|⠼|⠴|⠦|⠧|⠇|⠏)",
    re.I,
)


def load_cast(path: Path) -> tuple[dict, list[list]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise SystemExit(f"empty cast: {path}")
    header = json.loads(lines[0])
    events: list[list] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        events.append(json.loads(line))
    return header, events


def polish(
    events: list[list],
    *,
    max_idle: float,
    progress_idle: float,
    reading_hold: float,
) -> list[list]:
    if not events:
        return events

    out: list[list] = []
    new_t = 0.0
    prev_old_t = float(events[0][0])
    hold_until = 0.0
    last_progress_emit = -1e9
    protect_next_gap = False

    for ev in events:
        old_t, etype, data = ev[0], ev[1], ev[2]
        gap = max(0.0, float(old_t) - prev_old_t)
        prev_old_t = float(old_t)

        text = data if isinstance(data, str) else ""
        is_progress = bool(PROGRESS_MARKERS.search(text))

        if protect_next_gap:
            # Keep the intentional sleep after "reading pause" (capped to reading_hold).
            gap = min(gap, reading_hold) if gap > 0 else gap
            # If the sleep was already truncated by asciinema, enforce a floor.
            if gap < reading_hold * 0.6:
                gap = reading_hold
            protect_next_gap = False
        elif is_progress:
            tentative = new_t + min(gap, progress_idle)
            if tentative - last_progress_emit < 0.18:
                continue
            gap = min(gap, progress_idle)
        else:
            gap = min(gap, max_idle)

        new_t += gap
        if new_t < hold_until:
            new_t = hold_until

        out.append([round(new_t, 6), etype, data])
        if is_progress:
            last_progress_emit = new_t

        if etype == "o" and READING_PAUSE.search(text):
            protect_next_gap = True
            hold_until = new_t + reading_hold
        elif etype == "o" and RESULT_SETTLE.search(text):
            # Soft hold while the panel is still streaming; reading pause is stronger.
            hold_until = max(hold_until, new_t + min(3.0, reading_hold * 0.35))

    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument(
        "--max-idle",
        type=float,
        default=0.55,
        help="cap general idle gaps (typing / scene changes)",
    )
    ap.add_argument(
        "--progress-idle",
        type=float,
        default=0.12,
        help="cap idle during progress/probe frames",
    )
    ap.add_argument(
        "--reading-hold",
        type=float,
        default=9.0,
        help="seconds to keep on screen after each reading-pause marker",
    )
    args = ap.parse_args()

    header, events = load_cast(args.input)
    polished = polish(
        events,
        max_idle=args.max_idle,
        progress_idle=args.progress_idle,
        reading_hold=args.reading_hold,
    )
    header = dict(header)
    if polished:
        header["duration"] = polished[-1][0]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(header, ensure_ascii=False) + "\n")
        for ev in polished:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")

    raw_dur = float(events[-1][0]) if events else 0.0
    new_dur = float(polished[-1][0]) if polished else 0.0
    print(
        f"polished {args.input.name}: {raw_dur:.1f}s → {new_dur:.1f}s ({len(polished)} events)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
