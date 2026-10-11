"""Declarative signature loader + matcher + evaluator tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from honeypot_auditor.config.tells.mysql import MYSQL_STOCK_CAP_BLOCK
from honeypot_auditor.models import Indicator
from honeypot_auditor.signatures.loader import (
    SignaturePack,
    SignatureRule,
    load_core_pack,
    load_signature_file,
    match_rule,
    validate_signature_doc,
)


def test_core_pack_loads():
    pack = load_core_pack()
    assert len(pack.rules) >= 2


def test_exact_bytes_rejects_empty_needle():
    from honeypot_auditor.signatures.loader import SignatureRule, match_rule

    rule = SignatureRule(
        id="bad.empty",
        title="empty",
        primitive="exact_bytes",
        params={"value": ""},
    )
    assert match_rule(rule, body=b"anything") is False
    errors = validate_signature_doc(
        {
            "name": "x",
            "version": "1",
            "rules": [
                {
                    "id": "bad.empty",
                    "title": "empty",
                    "primitive": "exact_bytes",
                    "params": {"value": ""},
                }
            ],
        }
    )
    assert any("non-empty" in e for e in errors)


def test_validate_rejects_banned_keys():
    errors = validate_signature_doc({"match": "evil()", "rules": []})
    assert any("banned" in e for e in errors)


def test_match_regex_primitive():

    path = (
        Path(__file__).resolve().parents[1] / "src/honeypot_auditor/signatures/core/ftp_desert.json"
    )
    pack = load_signature_file(path)
    rule = pack.rules[0]
    assert match_rule(rule, body=b"500 Unknown command")


def test_malicious_yaml_cannot_exec():
    doc = {"rules": [{"id": "x", "primitive": "exec", "params": {}}]}
    errors = validate_signature_doc(doc)
    assert errors


def _ind(**kwargs) -> Indicator:
    defaults = {"id": "probe.x", "title": "x", "category": "static_signature"}
    defaults.update(kwargs)
    return Indicator(**defaults)


# --------------------------------------------------------------------------
# loader: match_rule primitives
# --------------------------------------------------------------------------
def _rule(primitive, **params):
    return SignatureRule(id="r.1", title="rule", primitive=primitive, params=params)


def test_match_rule_header_sequence_and_absent():
    seq = _rule("header_sequence", names=["Server", "X-Powered-By"])
    assert match_rule(seq, headers=["Server", "X-Powered-By"]) is True
    assert match_rule(seq, headers=["Server"]) is False
    assert match_rule(seq, headers=None) is False

    absent = _rule("header_absent", name="X-Squid-Error")
    assert match_rule(absent, headers=["Server", "Date"]) is True
    assert match_rule(absent, headers=["server", "x-squid-error"]) is False
    assert match_rule(absent, headers=None) is False


def test_match_rule_ja3s_and_http2_settings():
    ja3s = _rule("ja3s_equals", expect="deadbeef")
    assert match_rule(ja3s, ja3s="deadbeef") is True
    assert match_rule(ja3s, ja3s="other") is False
    assert match_rule(_rule("ja3s_equals", expect=""), ja3s="deadbeef") is False

    order = _rule("http2_settings_sequence", order=["a", "b"])
    assert match_rule(order, headers=["a", "b"]) is True
    assert match_rule(order, headers=["b", "a"]) is False


def test_match_rule_regex_exact_bytes_and_unknown():
    assert match_rule(_rule("regex", pattern="honeypot"), body=b"welcome to honeypot") is True
    assert match_rule(_rule("regex", pattern="^prod"), body=b"prod cluster") is True
    assert match_rule(_rule("regex", pattern="zzz"), body=b"nope") is False

    assert match_rule(_rule("exact_bytes", value="Dionaea"), body=b"x Dionaea y") is True
    assert match_rule(_rule("exact_bytes", value=b"\x00\x01"), body=b"\x00\x01") is True

    assert match_rule(_rule("jmespath", query="a.b"), body=b"{}") is False
    assert match_rule(_rule("totally-unknown"), body=b"x") is False


def test_validate_signature_doc_reports_bad_regex_and_types():
    doc = {
        "rules": [
            {"id": "x", "primitive": "regex", "params": {"pattern": "(unclosed"}},
            {"id": "y", "primitive": "exec"},
            "not-an-object",
        ],
        "exec": "evil",
    }
    errors = validate_signature_doc(doc)
    assert any("invalid regex" in e for e in errors)
    assert any("unknown primitive" in e for e in errors)
    assert any("must be an object" in e for e in errors)
    assert any("banned key" in e for e in errors)

    assert validate_signature_doc("not a dict") == ["root must be an object"]
    assert validate_signature_doc({"rules": "nope"}) == ["rules must be a list"]


def test_load_signature_file_builds_rules(tmp_path):
    path = tmp_path / "pack.json"
    path.write_text(
        json.dumps(
            {
                "name": "lab",
                "version": "3",
                "rules": [
                    {
                        "id": "lab.one",
                        "title": "one",
                        "category": "lab_signature",
                        "primitive": "exact_bytes",
                        "params": {"value": "CANARY"},
                        "remediation": "n/a",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    pack = load_signature_file(path)
    assert pack.name == "lab" and pack.version == "3"
    rule = pack.rules[0]
    assert rule.id == "lab.one" and rule.category == "lab_signature"
    assert rule.params == {"value": "CANARY"} and rule.remediation == "n/a"


def test_load_signature_file_rejects_yaml_without_pyyaml(tmp_path, monkeypatch):
    import builtins

    path = tmp_path / "pack.yaml"
    path.write_text("name: x\nrules: []\n", encoding="utf-8")

    real_import = builtins.__import__

    def _no_yaml(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("no pyyaml")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_yaml)
    with pytest.raises(ImportError, match="pyyaml required"):
        load_signature_file(path)


# --------------------------------------------------------------------------
# evaluator: pack selection + rule matching against indicator evidence
# --------------------------------------------------------------------------
def test_evaluate_signatures_matches_body_evidence(monkeypatch):
    from honeypot_auditor.signatures import evaluate

    pack = SignaturePack(
        name="t",
        version="1",
        rules=[_rule("exact_bytes", value="HONEYPOT-PLACEHOLDER-XYZ")],
    )
    monkeypatch.setattr(evaluate, "_load_active_pack", lambda: pack)
    out = evaluate.evaluate_signatures(
        [_ind(evidence="220 welcome to HONEYPOT-PLACEHOLDER-XYZ srv")]
    )
    assert len(out) == 1
    assert out[0].id == "r.1" and out[0].protocol == "signature"
    assert out[0].triggered is True and "pack t" in out[0].detail


def test_evaluate_signatures_skips_existing_ids_and_skipped_indicators(monkeypatch):
    from honeypot_auditor.signatures import evaluate

    pack = SignaturePack(
        name="t",
        version="1",
        rules=[_rule("exact_bytes", value="STOCK-XYZ")],  # same id as the indicator
    )
    monkeypatch.setattr(evaluate, "_load_active_pack", lambda: pack)
    assert evaluate.evaluate_signatures([_ind(id="r.1", evidence="STOCK-XYZ")]) == []

    # skipped indicators carry no usable evidence
    assert evaluate.evaluate_signatures([_ind(skipped=True, evidence="STOCK-XYZ")]) == []


def test_evaluate_signatures_header_and_ja3s_rules(monkeypatch):
    from honeypot_auditor.signatures import evaluate

    http_ind = _ind(evidence="HTTP/1.1 407 denial\r\nVia: 1.1 localhost\r\nX-Powered-By: PHP")
    ja3s_ind = _ind(evidence=json.dumps({"ja3s": "cafed00d"}))
    pack = SignaturePack(
        name="t",
        version="1",
        rules=[
            _rule("header_sequence", names=["Via", "X-Powered-By"]),
            _rule("ja3s_equals", expect="cafed00d"),
        ],
    )
    monkeypatch.setattr(evaluate, "_load_active_pack", lambda: pack)
    out = evaluate.evaluate_signatures([http_ind, ja3s_ind])
    assert {i.fingerprint_type for i in out} == {"sig_header_sequence", "sig_ja3s_equals"}


def test_evaluate_signatures_ja3s_rule_needs_exact_match(monkeypatch):
    from honeypot_auditor.signatures import evaluate

    pack = SignaturePack(name="t", version="1", rules=[_rule("ja3s_equals", expect="aa")])
    monkeypatch.setattr(evaluate, "_load_active_pack", lambda: pack)
    assert evaluate.evaluate_signatures([_ind(evidence=json.dumps({"ja3s": "bb"}))]) == []
    # non-JSON evidence, non-dict JSON, and missing evidence all yield no ja3s
    assert evaluate.evaluate_signatures([_ind(evidence="not json")]) == []
    assert evaluate.evaluate_signatures([_ind(evidence="[1,2]")]) == []
    assert evaluate.evaluate_signatures([_ind()]) == []


def test_evaluate_signatures_swallows_pack_load_failure(monkeypatch, caplog):
    from honeypot_auditor.signatures import evaluate

    def _boom():
        raise RuntimeError("pack dir missing")

    monkeypatch.setattr(evaluate, "_load_active_pack", _boom)
    with caplog.at_level("WARNING"):
        assert evaluate.evaluate_signatures([_ind()]) == []
    assert "signature pack load failed" in caplog.text


def test_evaluate_signatures_warns_on_empty_pack(monkeypatch, caplog):
    from honeypot_auditor.signatures import evaluate

    monkeypatch.setattr(
        evaluate, "_load_active_pack", lambda: SignaturePack(name="empty", version="1")
    )
    with caplog.at_level("WARNING"):
        assert evaluate.evaluate_signatures([_ind()]) == []
    assert "has no rules" in caplog.text


def test_load_active_pack_core_is_default(monkeypatch):
    from honeypot_auditor.signatures import evaluate

    monkeypatch.setattr(evaluate.settings, "signature_pack", "core")
    sentinel = SignaturePack(name="core", version="1")
    monkeypatch.setattr(evaluate, "load_core_pack", lambda: sentinel)
    assert evaluate._load_active_pack() is sentinel


def _fake_contrib_path(root):
    """Path stand-in whose .resolve().parents[1] is `root` (holds signatures/contrib)."""

    class _FakePath:
        def __init__(self, *_args):
            pass

        def resolve(self):
            return self

        parents = property(lambda self: [None, root])

    return _FakePath


def test_load_active_pack_reads_contrib_directory(monkeypatch, tmp_path):
    from honeypot_auditor.signatures import evaluate

    contrib = tmp_path / "signatures" / "contrib"
    contrib.mkdir(parents=True)
    (contrib / "extra.json").write_text(
        json.dumps(
            {
                "name": "community",
                "rules": [
                    {
                        "id": "c.1",
                        "title": "one",
                        "primitive": "exact_bytes",
                        "params": {"value": "ZZ"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (contrib / "ignored.txt").write_text("not a pack", encoding="utf-8")

    monkeypatch.setattr(evaluate, "Path", _fake_contrib_path(tmp_path))
    monkeypatch.setattr(evaluate.settings, "signature_pack", "community")
    pack = evaluate._load_active_pack()
    assert pack.name == "community"
    assert [r.id for r in pack.rules] == ["c.1"]


def test_load_active_pack_falls_back_when_contrib_empty(monkeypatch, tmp_path):
    from honeypot_auditor.signatures import evaluate

    # contrib/ exists but has no pack files
    (tmp_path / "signatures" / "contrib").mkdir(parents=True)

    monkeypatch.setattr(evaluate, "Path", _fake_contrib_path(tmp_path))
    monkeypatch.setattr(evaluate.settings, "signature_pack", "community")
    sentinel = SignaturePack(name="core", version="1")
    monkeypatch.setattr(evaluate, "load_core_pack", lambda: sentinel)
    assert evaluate._load_active_pack() is sentinel


# --------------------------------------------------------------------------
# protocol matcher units (config/signatures/*)
# --------------------------------------------------------------------------
def test_match_smb_static_ntlm_challenge():
    from honeypot_auditor.config.signatures.smb import match_smb_static_ntlm_challenge

    assert match_smb_static_ntlm_challenge([b"AAAAAAAA"]) is None
    assert match_smb_static_ntlm_challenge([b"A" * 8, b"B" * 8]) is None
    detail = match_smb_static_ntlm_challenge([b"SALT0001", b"SALT0001"])
    assert detail is not None and "identical NTLM" in detail


def test_match_smb_bogus_pipe_branches():
    from honeypot_auditor.config.signatures.smb import match_smb_bogus_pipe

    assert "bogus named pipe accepted" in match_smb_bogus_pipe(None, "opened", accepted=True)
    assert match_smb_bogus_pipe(0xC0000034, "NTSTATUS", accepted=False) is None
    assert "bogus pipe NTSTATUS 0xC00000CC" in match_smb_bogus_pipe(
        0xC00000CC, "NTSTATUS", accepted=False
    )
    assert "failed messily" in match_smb_bogus_pipe(
        None, "connection reset by peer", accepted=False
    )
    assert match_smb_bogus_pipe(None, "clean transport close", accepted=False) is None


def test_match_smb_ghost_share_branches():
    from honeypot_auditor.config.signatures.smb import match_smb_ghost_share

    assert "TREE_CONNECT accepted" in match_smb_ghost_share(None, "ok", accepted=True)
    assert match_smb_ghost_share(0xC00000CC, "NTSTATUS", accepted=False) is None
    assert "ghost share NTSTATUS" in match_smb_ghost_share(0xC000000D, "NTSTATUS", accepted=False)
    assert "failed messily" in match_smb_ghost_share(None, "timed out", accepted=False)
    assert match_smb_ghost_share(None, "closed cleanly", accepted=False) is None


def test_match_smb_stock_shares_tiers():
    from honeypot_auditor.config.signatures.smb import match_smb_stock_shares

    detail, gated = match_smb_stock_shares(["honeypot", "IPC$", "C$"])
    assert detail is not None and "honeypot" in detail and gated is False

    detail, gated = match_smb_stock_shares(["tmp", "public"])
    assert detail is not None and gated is True

    assert match_smb_stock_shares(["tmp"]) == (None, False)
    assert match_smb_stock_shares(["ADMIN$", "", "print$"]) == (None, False)


def test_match_smb_negotiate_deficit_branches():
    from honeypot_auditor.config.signatures.smb import match_smb_negotiate_deficit

    assert match_smb_negotiate_deficit({}) is None
    assert "legacy dialect NT LM 0.12" in match_smb_negotiate_deficit({"dialect": "NT LM 0.12"})
    assert match_smb_negotiate_deficit({"dialect": "SMB 1.0"}) is not None
    assert "legacy dialect 0x0202" in match_smb_negotiate_deficit({"dialect": 0x0202})
    assert (
        match_smb_negotiate_deficit({"dialect": 0x0311, "supports_encryption": False})
        == "SMB 3.1.1 without encryption capability"
    )
    assert match_smb_negotiate_deficit({"dialect": 0x0311, "supports_encryption": True}) is None
    assert match_smb_negotiate_deficit({"dialect": 0x0300}) is None


def test_match_smb_target_info_mismatch():
    ntlm = pytest.importorskip("impacket.ntlm")
    from honeypot_auditor.config.signatures.smb import match_smb_target_info_mismatch

    def _av(pairs):
        return {key: (len(val), val) for key, val in pairs.items()}

    samba = {ntlm.NTLMSSP_AV_HOSTNAME: "SAMBA-01".encode("utf-16le")}
    clean = {ntlm.NTLMSSP_AV_HOSTNAME: "WIN-SRV".encode("utf-16le")}
    dns_samba = {ntlm.NTLMSSP_AV_DNS_HOSTNAME: "ubuntu-srv.lab".encode("utf-16le")}

    assert match_smb_target_info_mismatch("Windows 5.1", {"av_pairs": _av(samba)}) is not None
    assert match_smb_target_info_mismatch("Windows 5.1", {"av_pairs": _av(dns_samba)}) is not None
    assert match_smb_target_info_mismatch("Windows 5.1", {"av_pairs": _av(clean)}) is None
    assert match_smb_target_info_mismatch("Windows 5.1", {}) is None
    assert match_smb_target_info_mismatch("Unix", {"av_pairs": _av(samba)}) is None


def test_match_postgres_signatures():
    from honeypot_auditor.config.signatures.postgres import (
        match_postgres_auth_c_blob,
        match_postgres_cleartext_only,
    )

    auth_ok = b"R" + b"\x00\x00\x00\x08" + b"\x00\x00\x00\x03"
    assert match_postgres_cleartext_only(b"N", auth_ok) is not None
    assert match_postgres_cleartext_only(b"S", auth_ok) is None  # SSL accepted
    assert match_postgres_cleartext_only(b"N", b"R\x00\x00\x00\x08\x00\x00\x00\x05") is None

    blob = b"...Fauth.c...L326...Rauth_failed..."
    assert match_postgres_auth_c_blob(blob) is not None
    assert match_postgres_auth_c_blob(b"Fauth.cL326Rauth_failed") is not None
    assert match_postgres_auth_c_blob(b"auth.c 326 other routine") is None
    assert match_postgres_auth_c_blob(b"") is None


def test_match_mysql_eol_and_handshake():
    from honeypot_auditor.config.signatures.mysql import (
        match_mysql_eol_banner,
        match_mysql_stock_handshake,
    )

    assert match_mysql_eol_banner("") is None
    assert match_mysql_eol_banner("8.0.36") is None
    assert "EOL MySQL greeting" in match_mysql_eol_banner("5.5.62-0ubuntu0.14.04.1")

    raw = b"\x00" * 4 + MYSQL_STOCK_CAP_BLOCK + b"mysql_native_password"
    assert match_mysql_stock_handshake(raw) is not None
    assert match_mysql_stock_handshake(b"\x00" * 4 + MYSQL_STOCK_CAP_BLOCK) is None
    assert match_mysql_stock_handshake(b"mysql_native_password only") is None


def test_match_mysql_pkt_order():
    from honeypot_auditor.config.signatures.mysql import match_mysql_pkt_order

    raw = b"\x00\x00\x00\x02\xff\x04#Expected seq(2) got seq(3)"
    detail = match_mysql_pkt_order(raw)
    assert detail is not None and "emulator seq FSM" in detail
    assert match_mysql_pkt_order(b"\x00\x00\x00\x02\x00\x00ok") is None


def test_extract_mysql_scramble_variants():
    from honeypot_auditor.config.signatures.mysql import extract_mysql_scramble

    assert extract_mysql_scramble(b"") == b""
    assert extract_mysql_scramble(b"\x01\x02\x03") == b""
    assert extract_mysql_scramble(b"\xff" * 8) == b""  # no protocol-10 byte at all

    part1 = b"ABCDEFGH"
    # plugin_len 21 → part 2 is 13 bytes: 12 scramble bytes + NUL terminator
    part2 = b"123456789012"
    greeting = (
        b"\x00\x00\x00\x01"  # header
        b"\x0a5.5.62\x00"  # protocol + version
        b"\x01\x00\x00\x00" + part1 + b"\x00"  # connection id  # auth part 1 + filler
        b"\xf7\xff"  # capability low
        b"\x08"  # charset
        b"\x02\x00"  # status
        b"\x00\x0f"  # capability high
        b"\x15"  # auth plugin data len (21)
        + b"\x00" * 10  # reserved
        + part2
        + b"\x00"  # auth part 2 (12 scramble bytes + NUL)
        + b"mysql_native_password\x00"
    )
    assert extract_mysql_scramble(greeting) == part1 + part2

    truncated = greeting[:24]  # header+version+connid+part1 only → falls back to part1
    assert extract_mysql_scramble(truncated) == part1


def test_match_mysql_scramble_frozen():
    from honeypot_auditor.config.signatures.mysql import match_mysql_scramble_frozen

    assert match_mysql_scramble_frozen(b"short", b"short") is None
    assert match_mysql_scramble_frozen(b"A" * 8, b"B" * 8) is None
    assert "scramble frozen" in match_mysql_scramble_frozen(b"A" * 12, b"A" * 12)


def test_match_mysql_auth_error_clone():
    from honeypot_auditor.config.signatures.mysql import match_mysql_auth_error_clone

    packet = b"\x00\x00\x00\x01\xff\x17\x04Access denied for user 'root'@'localhost'"
    clone = match_mysql_auth_error_clone(packet, packet, "root", "svc")
    assert clone is not None and "distinct users" in clone

    generic = b"\x00\x00\x00\x01\xff\x17\x04Access denied for user (using password: YES)"
    assert match_mysql_auth_error_clone(generic, generic, "root", "svc") is not None

    assert match_mysql_auth_error_clone(generic, generic, "root", "root") is None
    assert match_mysql_auth_error_clone(generic, b"different", "root", "svc") is None
    assert match_mysql_auth_error_clone(b"", generic, "root", "svc") is None
    ok_packet = b"\x00\x00\x00\x01\x00\x00ok"
    assert match_mysql_auth_error_clone(ok_packet, ok_packet, "root", "svc") is None
    unattributed = b"\x00\x00\x00\x01\xff\x17\x04no idea what happened"
    assert match_mysql_auth_error_clone(unattributed, unattributed, "root", "svc") is None


def test_match_http_proxy_lure_and_stock_cert():
    from honeypot_auditor.config.signatures.http import (
        match_http_proxy_lure,
        match_tls_stock_cert,
    )

    assert match_http_proxy_lure("") is None
    assert match_http_proxy_lure("HTTP/1.1 407 ok") is None
    assert "Via: localhost" in match_http_proxy_lure("407\r\nVia: 1.1 localhost")
    assert "frozen squid/3.3.8" in match_http_proxy_lure("Server: squid/3.3.8")
    assert "ISA proxy deny phrase" in match_http_proxy_lure("Web proxy service is denied")

    assert match_tls_stock_cert("CN=real.corp") is None
    assert "cowrie" in match_tls_stock_cert("CN=cowrie, O=honeypot")


def test_claimed_os_from_banner():
    from honeypot_auditor.config.signatures.common import claimed_os_from_banner

    assert claimed_os_from_banner("Microsoft-IIS/7.5") == "windows"
    assert claimed_os_from_banner("220 ProFTPD Server (Ubuntu)") == "linux"
    assert claimed_os_from_banner("OpenSSH_7.2") == "linux"
    assert claimed_os_from_banner("") == ""
    assert claimed_os_from_banner("nginx") == ""
