"""Package layout: one probe module per protocol."""

from honeypot_auditor.probes import PROBE_BY_PROTOCOL, probe_ssh
from honeypot_auditor.probes.core import probe_ssh as core_probe_ssh
from honeypot_auditor.probes.extended import probe_http


def test_probe_registry_covers_all_basic_protocols():
    assert set(PROBE_BY_PROTOCOL) == {
        "ssh",
        "telnet",
        "smb",
        "ftp",
        "http",
        "redis",
        "smtp",
        "vnc",
        "sip",
        "mysql",
        "pop3",
        "imap",
        "postgres",
        "git",
        "rdp",
        "httpproxy",
        "mssql",
        "mongodb",
    }
    assert PROBE_BY_PROTOCOL["ssh"] is probe_ssh


def test_legacy_core_and_extended_reexport():
    assert core_probe_ssh is probe_ssh
    assert probe_http is PROBE_BY_PROTOCOL["http"]
