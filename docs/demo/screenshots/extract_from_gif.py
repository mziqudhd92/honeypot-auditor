#!/usr/bin/env python3
"""Extract Medium/docs stills from the v1.0.0 lab-tour GIF."""
from __future__ import annotations

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent
GIF = ROOT.parent / "honeypot-auditor-lab-tour-v1.0.0.gif"

SHOTS = [
    (0.05, "01-title-three-faces", "Opening title — THREE FACES · v1.0.0"),
    (2.2, "02-scene1-cowrie", "Scene 1 / 3 — Cowrie intro card"),
    (5.5, "03-cowrie-score-panel", "Cowrie — Confirmed Honeypot 100% score panel"),
    (15.0, "04-cowrie-why-this-score", "Cowrie — why this score / KEX facade details"),
    (24.5, "05-scene2-deep", "Scene 2 / 3 — OpenCanary / dd-stack (--deep)"),
    (33.0, "06-deep-verdict-triggers", "Deep audit — key findings, verdict, triggers"),
    (40.5, "07-scene3-tarpit", "Scene 3 / 3 — silent-accept tarpit intro"),
    (44.5, "08-tarpit-score-panel", "Tarpit — score panel"),
    (54.0, "09-tarpit-hit-lines", "Tarpit — HIT lines / silent-accept reading pause"),
    (65.5, "10-final-scoreboard", "Lab tour scoreboard — Cowrie 100% · dd-stack 88% · tarpit 60%"),
]


def main() -> None:
    im = Image.open(GIF)
    starts: list[float] = []
    t = 0.0
    for i in range(im.n_frames):
        starts.append(t)
        im.seek(i)
        t += im.info.get("duration", 100) / 1000.0

    def frame_at(sec: float) -> int:
        idx = 0
        for i, s in enumerate(starts):
            if s <= sec:
                idx = i
            else:
                break
        return idx

    for old in ROOT.glob("*.png"):
        old.unlink()

    rows = ["# Lab-tour screenshots (v1.0.0)", "", "Stills from `../honeypot-auditor-lab-tour-v1.0.0.gif`.", "", "| File | Caption |", "|------|---------|"]
    for sec, slug, caption in SHOTS:
        idx = frame_at(sec)
        im.seek(idx)
        path = ROOT / f"{slug}.png"
        im.convert("RGB").save(path, "PNG", optimize=True)
        rows.append(f"| `{path.name}` | {caption} |")
        print(path.name, f"frame={idx}")

    rows += ["", "Regenerate:", "", "```bash", "python3 docs/demo/screenshots/extract_from_gif.py", "```", ""]
    (ROOT / "README.md").write_text("\n".join(rows) + "\n")


if __name__ == "__main__":
    main()
