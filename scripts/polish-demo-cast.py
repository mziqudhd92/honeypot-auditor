#!/usr/bin/env python3
"""Polish an asciinema v2 cast for demo GIFs.

- Compress long idle gaps (progress bars / probe waits) so a 90s probe does not
  force viewers to wait wall-clock time.
- After result panels (score / threat / HIT tables), enforce a readable hold.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

RESULT_MARKERS = re.compile(
    r"(Honeyscore|Threat level|Suspected Honeypot|Confirmed Honeypot|"
    r"Likely Real Host|Key findings|Why this score|SCENE \d|SCOREBOARD|"
    r"silent-accept|KEX facade|high-signal|TOUR COMPLETE)",
    re.I,
)
PROGRESS_MARKERS = re.compile(
    r"(Auditing target|Finished |probing|deep audit|▮|⠋|⠙|⠹|⠸|⠼|⠴|⠦|⠧|⠇|⠏)",
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
    result_hold: float,
    progress_idle: float,
) -> list[list]:
    if not events:
        return events

    out: list[list] = []
    new_t = 0.0
    prev_old_t = float(events[0][0])
    hold_until = 0.0
    last_progress_emit = -1e9

    for ev in events:
        old_t, etype, data = ev[0], ev[1], ev[2]
        gap = max(0.0, float(old_t) - prev_old_t)
        prev_old_t = float(old_t)

        text = data if isinstance(data, str) else ""
        is_progress = bool(PROGRESS_MARKERS.search(text))
        if is_progress:
            # Keep a sparse heartbeat of progress frames; drop the rest so a
            # 90s probe does not become a 90s GIF.
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

        if etype == "o" and RESULT_MARKERS.search(text):
            # Keep the panel on screen long enough to read.
            hold_until = new_t + result_hold

    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--max-idle", type=float, default=0.45, help="cap general idle gaps")
    ap.add_argument(
        "--progress-idle",
        type=float,
        default=0.12,
        help="cap idle during progress/probe frames",
    )
    ap.add_argument(
        "--result-hold",
        type=float,
        default=2.8,
        help="minimum extra hold after result markers (stacked with demo sleeps)",
    )
    args = ap.parse_args()

    header, events = load_cast(args.input)
    polished = polish(
        events,
        max_idle=args.max_idle,
        result_hold=args.result_hold,
        progress_idle=args.progress_idle,
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
        f"polished {args.input.name}: {raw_dur:.1f}s → {new_dur:.1f}s "
        f"({len(polished)} events)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
