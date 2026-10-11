"""Wizard helper tests (input validation, plan building, and interactive flow)."""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from honeypot_auditor import wizard
from honeypot_auditor.engine import Auditor


def test_parse_ports_accepts_lists_and_dedupes():
    assert wizard.parse_ports("22, 23") == ["22,23"]
    assert wizard.parse_ports("22,22,8081") == ["22,8081"]
    assert wizard.parse_ports("") == []
    assert wizard.parse_ports("  9  ") == ["9"]


@pytest.mark.parametrize("bad", ["abc", "22;23", "70000", "0", "22,-1"])
def test_parse_ports_rejects_garbage(bad):
    with pytest.raises(ValueError):
        wizard.parse_ports(bad)


def test_build_auditor_maps_answers():
    auditor = wizard._build_auditor(
        target="127.0.0.1",
        preset="iana",
        ports="22,23",
        deep=True,
        timeout=5,
        confirm_authorized=False,
    )
    assert isinstance(auditor, Auditor)
    assert auditor.target == "127.0.0.1"
    assert auditor.preset == "iana"
    assert auditor.extra_ports == ["22,23"]
    assert auditor.deep is True
    assert auditor.timeout == 5.0
    assert auditor.confirm_authorized is False


def test_resolve_target_rejects_garbage():
    with pytest.raises(ValueError):
        wizard._resolve_target("   ")
    with pytest.raises(OSError):
        wizard._resolve_target("this-host-does-not-exist-hpaudit.invalid")


def test_resolve_target_resolves_loopback():
    assert wizard._resolve_target("localhost") == "127.0.0.1"


def test_resolve_target_accepts_private_cidr():
    assert wizard._resolve_target("192.168.1.0/24") == "192.168.1.1"


def test_target_needs_authorization_for_public_hosts():
    assert wizard._target_needs_authorization("1.1.1.1") is True
    assert wizard._target_needs_authorization("127.0.0.1") is False
    assert wizard._target_needs_authorization("10.0.0.0/24") is False


def test_run_one_sets_confirm_authorized_after_public_yes(monkeypatch):
    """Public-target confirmation must flip confirm_authorized before Auditor.run."""
    answers = iter(
        [
            "1.1.1.1",  # target
            "iana",  # preset
            "",  # ports
            False,  # deep
            3,  # timeout
            True,  # authorized
            "skip",  # export report file as
            False,  # audit another?
            False,  # show history?
        ]
    )
    captured: dict = {}

    class _FakeAuditor:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run(self):
            from honeypot_auditor.models import AuditReport

            return AuditReport(
                target="1.1.1.1",
                resolved_ip="1.1.1.1",
                score=0.0,
                threat_level="CLEAN",
                category_hits={},
                confidence="low",
                indicators=[],
            )

    monkeypatch.setattr(wizard.Prompt, "ask", lambda *a, **k: next(answers))
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *a, **k: next(answers))
    monkeypatch.setattr(wizard.IntPrompt, "ask", lambda *a, **k: next(answers))
    monkeypatch.setattr(wizard, "Auditor", _FakeAuditor)
    monkeypatch.setattr(wizard, "render", lambda *a, **k: None)
    monkeypatch.setattr(wizard.storage, "save_report", lambda *a, **k: 1)
    monkeypatch.setattr(wizard, "print_cli_header", lambda: None)

    assert wizard.run_wizard() == 0
    assert captured.get("confirm_authorized") is True


# --------------------------------------------------------------------------
# Interactive-flow tests — prompts scripted, engine and storage stubbed.
# --------------------------------------------------------------------------
def _console():
    buf = io.StringIO()
    return Console(file=buf, force_terminal=False, width=200), buf


def _report():
    from honeypot_auditor.models import AuditReport

    return AuditReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        score=12.5,
        threat_level="LOW",
        category_hits={},
        confidence="low",
        indicators=[],
    )


class _ScriptAuditor:
    """Records constructor kwargs; run() raises run_exc when scripted to."""

    instances: list[dict] = []
    run_exc: Exception | None = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        type(self).instances.append(kwargs)

    def run(self):
        if type(self).run_exc:
            raise type(self).run_exc
        return _report()


@pytest.fixture()
def scripted_wizard(monkeypatch):
    """Patch every external the wizard touches; tests script prompt answers."""

    def install(answers, *, run_exc=None, save_exc=None, history=None):
        _ScriptAuditor.instances = []
        _ScriptAuditor.run_exc = run_exc
        stream = iter(answers)
        monkeypatch.setattr(wizard.Prompt, "ask", lambda *a, **k: next(stream))
        monkeypatch.setattr(wizard.Confirm, "ask", lambda *a, **k: next(stream))
        monkeypatch.setattr(wizard.IntPrompt, "ask", lambda *a, **k: next(stream))
        monkeypatch.setattr(wizard, "Auditor", _ScriptAuditor)
        monkeypatch.setattr(wizard, "render", lambda *a, **k: None)
        monkeypatch.setattr(wizard, "print_cli_header", lambda: None)
        if save_exc is not None:
            monkeypatch.setattr(
                wizard.storage, "save_report", lambda *a, **k: (_ for _ in ()).throw(save_exc)
            )
        else:
            monkeypatch.setattr(wizard.storage, "save_report", lambda *a, **k: 42)
        if history is not None:
            monkeypatch.setattr(wizard.storage, "list_audits", lambda limit=10: history)

    return install


_PRIVATE_RUN = ["127.0.0.1", "both", "", False, 3, "skip"]
_PUBLIC_RUN = ["1.1.1.1", "both", "", False, 3, True, "skip"]


def test_ask_target_retries_on_unresolvable_and_empty(monkeypatch):
    stream = iter(["no-such-host-hpaudit.invalid", "   ", "127.0.0.1"])
    monkeypatch.setattr(wizard.Prompt, "ask", lambda *a, **k: next(stream))
    console, buf = _console()
    assert wizard._ask_target(console) == "127.0.0.1"
    text = buf.getvalue()
    assert "cannot resolve" in text and "target is empty" in text


def test_ask_target_prints_subnet_summary(monkeypatch):
    monkeypatch.setattr(wizard.Prompt, "ask", lambda *a, **k: "10.0.0.0/24")
    console, buf = _console()
    assert wizard._ask_target(console) == "10.0.0.0/24"
    text = buf.getvalue()
    assert "subnet 10.0.0.0/24" in text and "hosts" in text
    assert "private/loopback" in text


def test_ask_target_prints_public_host_warning(monkeypatch):
    monkeypatch.setattr(wizard.Prompt, "ask", lambda *a, **k: "1.1.1.1")
    console, buf = _console()
    assert wizard._ask_target(console) == "1.1.1.1"
    assert "PUBLIC target" in buf.getvalue()


def test_ask_ports_falls_back_to_preset_on_garbage(monkeypatch):
    monkeypatch.setattr(wizard.Prompt, "ask", lambda *a, **k: "abc,70000")
    console, buf = _console()
    assert wizard._ask_ports(console) == ""
    assert "using the preset ports" in buf.getvalue()


def test_ask_ports_accepts_valid_list(monkeypatch):
    monkeypatch.setattr(wizard.Prompt, "ask", lambda *a, **k: "22, 8081")
    console, _buf = _console()
    assert wizard._ask_ports(console) == "22,8081"


def test_run_one_private_target_never_asks_authorization(scripted_wizard):
    console, buf = _console()
    scripted_wizard(_PRIVATE_RUN)
    wizard._run_one(console)
    assert len(_ScriptAuditor.instances) == 1
    assert _ScriptAuditor.instances[0]["confirm_authorized"] is False
    assert "PUBLIC" not in buf.getvalue()
    assert "saved to local SQLite as audit #42" in buf.getvalue()


def test_run_one_resets_out_of_range_timeout(scripted_wizard):
    console, _buf = _console()
    scripted_wizard(["127.0.0.1", "both", "", False, 99, "skip"])
    wizard._run_one(console)
    assert _ScriptAuditor.instances[0]["timeout"] == 3.0


def test_run_one_public_target_requires_confirmation(scripted_wizard):
    console, buf = _console()
    scripted_wizard(_PUBLIC_RUN)
    wizard._run_one(console)
    assert _ScriptAuditor.instances[0]["confirm_authorized"] is True
    assert "This target is PUBLIC" in buf.getvalue()


def test_run_one_public_target_declined_aborts(scripted_wizard):
    console, buf = _console()
    scripted_wizard(["1.1.1.1", "both", "", False, 3, False, "skip"])
    wizard._run_one(console)
    assert _ScriptAuditor.instances == []  # no Auditor built, no probes
    assert "Aborted — no probes sent" in buf.getvalue()


def test_run_one_permission_error_is_reported(scripted_wizard):
    console, buf = _console()
    scripted_wizard(
        ["1.1.1.1", "both", "", False, 3, True, "skip"],
        run_exc=PermissionError("not authorized"),
    )
    wizard._run_one(console)
    assert "requires authorization confirmation" in buf.getvalue()


def test_run_one_generic_failure_is_reported(scripted_wizard):
    console, buf = _console()
    scripted_wizard(_PRIVATE_RUN, run_exc=RuntimeError("probe boom"))
    wizard._run_one(console)
    assert "Audit failed: probe boom" in buf.getvalue()


def test_run_one_storage_error_still_renders(scripted_wizard):
    console, buf = _console()
    scripted_wizard(_PRIVATE_RUN, save_exc=OSError("db locked"))
    wizard._run_one(console)
    assert "report not saved (storage error: db locked)" in buf.getvalue()


def test_offer_report_file_exports_and_reports_path(monkeypatch):
    console, buf = _console()
    stream = iter(["json", "custom-report.json"])
    monkeypatch.setattr(wizard.Prompt, "ask", lambda *a, **k: next(stream))
    monkeypatch.setattr(
        "honeypot_auditor.cli._export_report",
        lambda report, path, fmt: f"/tmp/{path}",
    )
    wizard._offer_report_file(console, _report())
    assert "JSON report written to /tmp/custom-report.json" in buf.getvalue()


def test_offer_report_file_export_failure_is_reported(monkeypatch):
    console, buf = _console()
    stream = iter(["csv", "out.csv"])
    monkeypatch.setattr(wizard.Prompt, "ask", lambda *a, **k: next(stream))

    def _boom(report, path, fmt):
        raise OSError("disk full")

    monkeypatch.setattr("honeypot_auditor.cli._export_report", _boom)
    wizard._offer_report_file(console, _report())
    assert "export failed" in buf.getvalue() and "disk full" in buf.getvalue()


def test_offer_report_file_skip_is_silent(monkeypatch):
    console, buf = _console()
    monkeypatch.setattr(wizard.Prompt, "ask", lambda *a, **k: "skip")
    wizard._offer_report_file(console, _report())
    assert buf.getvalue() == ""


def test_show_history_empty(monkeypatch):
    console, buf = _console()
    monkeypatch.setattr(wizard.storage, "list_audits", lambda limit=10: [])
    wizard._show_history(console)
    assert "No audits saved yet" in buf.getvalue()


def test_show_history_prints_rows_with_deep_mark(monkeypatch):
    console, buf = _console()
    monkeypatch.setattr(
        wizard.storage,
        "list_audits",
        lambda limit=10: [
            {
                "id": 7,
                "created_at": "2026-10-08 10:00:00",
                "target": "127.0.0.1",
                "score": 88.5,
                "threat_level": "HIGH",
                "deep": 1,
            },
            {
                "id": 6,
                "created_at": "2026-10-07 09:00:00",
                "target": "10.0.0.5",
                "score": 4.0,
                "threat_level": "CLEAN",
                "deep": 0,
            },
        ],
    )
    wizard._show_history(console)
    text = buf.getvalue()
    assert "Recent audits" in text and "(deep)" in text
    assert "127.0.0.1" in text and "88.5" in text and "10.0.0.5" in text


def test_run_wizard_loops_and_shows_history(scripted_wizard):
    console, buf = _console()
    scripted_wizard(
        _PRIVATE_RUN + [True] + _PRIVATE_RUN + [False, True],
        history=[
            {
                "id": 42,
                "created_at": "2026-10-08 10:00:00",
                "target": "127.0.0.1",
                "score": 12.5,
                "threat_level": "LOW",
                "deep": 0,
            }
        ],
    )
    assert wizard.run_wizard(console) == 0
    assert len(_ScriptAuditor.instances) == 2
    assert "Recent audits" in buf.getvalue()
    assert "Done — hang up clean." in buf.getvalue()


def test_run_wizard_exits_without_history_when_declined(scripted_wizard):
    console, buf = _console()
    scripted_wizard(_PRIVATE_RUN + [False, False], history=[])
    assert wizard.run_wizard(console) == 0
    assert "Recent audits" not in buf.getvalue()
