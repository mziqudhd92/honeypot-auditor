# Plugins

Honeypot Auditor supports two extension mechanisms:

## Declarative signatures (data)

JSON/YAML packs under `signatures/core/` and community contrib packs.
Validated offline with:

```bash
honeypot-auditor check-sig path/to/pack.json
```

Signatures use **declarative primitives only** (`regex`, `header_sequence`, `ja3s_equals`, …).
No arbitrary Python hooks in YAML packs.

## Entry-point plugins (code)

Python packages register probes via `pyproject.toml`:

```toml
[project.entry-points."honeypot_auditor.plugins"]
my_trap_pack = "my_trap_pack:register"
```

Plugin module:

```python
def register(registry):
    registry["custom_proto"] = my_probe_fn
```

Plugins are vetted PyPI packages; YAML remains declarative-only.

See also [SIGNATURES.md](SIGNATURES.md).
