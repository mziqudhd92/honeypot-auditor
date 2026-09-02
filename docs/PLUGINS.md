# Plugins

Honeypot Auditor supports declarative signatures, active-probe plugins, and explicitly selected
passive-intelligence providers.

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

## Passive-intelligence providers (explicit opt-in)

A provider package exposes one callable through a separate entry-point group:

```toml
[project.entry-points."honeypot_auditor.intel"]
example = "example_provider:lookup"
```

The callable accepts the resolved IP and an optional API key, and returns `list[Indicator]`:

```python
from honeypot_auditor.models import Indicator


def lookup(ip: str, api_key: str | None) -> list[Indicator]:
    return [
        Indicator(
            id="reputation",
            title="Provider reputation result",
            category="shodan",
            triggered=False,
            detail=f"no passive match for {ip}",
        )
    ]
```

Providers never run merely because they are installed. The operator must select each one:

```bash
HONEYPOT_AUDITOR_INTEL_EXAMPLE_KEY=... \
  honeypot-auditor --target 203.0.113.10 --intel-provider example --confirm-authorized
```

`--intel-key example=...` is available for controlled automation, but the environment variable is
preferred because it is less likely to enter shell history. Provider names are validated, only the
selected entry point is imported, and each provider runs once per host. Returned IDs are namespaced as
`intel.<provider>.*`; categories are restricted to `shodan` (the backwards-compatible passive-intel
score bucket) or `info`. Provider failures become skipped indicators, and API keys are redacted from
errors and reports.

See also [SIGNATURES.md](SIGNATURES.md).
