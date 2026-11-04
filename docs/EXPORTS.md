# Report exports

| `--format` | Output | Notes |
|------------|--------|-------|
| `json` (default) | `.json` | Full audit payload; top-level `observables` always present (may be `{}`) |
| `sarif` | `.sarif` | Static-analysis interchange |
| `html` / `csv` / `markdown` | `.html` / `.csv` / `.md` | Human-readable summaries |
| `stix` | `.stix.json` | STIX **2.1** bundle (SCO + Infrastructure + Indicator). File only — no TAXII push |
| `misp` | `.misp.json` | MISP event JSON with attributes/tags. File only — no live MISP sync |

Subnet scans: `stix` merges all hosts into one bundle; `misp` writes `{ "response": [ Event, … ] }`.

Also available from the interactive wizard export step and the Python SDK
(`Auditor(..., output_format="stix"|"misp", shodan_history=True)`).

Reports are written owner-only (`0600`) because they may contain target evidence.

Shared builder: `honeypot_auditor.reporters.cti_context.build_cti_context`.
