"""Package layout: one probe module per protocol."""

from honeypot_auditor.probes import PROBE_BY_PROTOCOL, probe_ssh
from honeypot_auditor.probes.core import probe_ssh as core_probe_ssh
from honeypot_auditor.probes.extended import probe_http
from honeypot_auditor.probes.udp import discover_udp_engines

# Built-in TCP/legacy engines that must always be present (UDP engines are
# discovered dynamically from probes.udp.* and must not hard-fail this set).
_REQUIRED_CORE = frozenset(
    {
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
        "mqtt",
        "snmp",
        "elasticsearch",
        "docker",
        "ipp",
        "memcached",
        "kubernetes",
    }
)


def test_probe_registry_covers_all_basic_protocols():
    assert _REQUIRED_CORE <= set(PROBE_BY_PROTOCOL)
    assert PROBE_BY_PROTOCOL["ssh"] is probe_ssh
    for eng in discover_udp_engines():
        assert eng.name in PROBE_BY_PROTOCOL
        assert PROBE_BY_PROTOCOL[eng.name] is eng.probe


def test_legacy_core_and_extended_reexport():
    assert core_probe_ssh is probe_ssh
    assert probe_http is PROBE_BY_PROTOCOL["http"]
