"""Tests for config helpers and port presets."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from honeypot_auditor.config import (
    FTP_WELCOME_TELLS,
    NMAP_HONEYPOT_TELLS,
    is_private_or_loopback,
    match_ssh_banner,
    match_uname_signature,
    merge_ports,
    parse_port_overrides,
)


def test_is_private_loopback():
    assert is_private_or_loopback("127.0.0.1")
    assert is_private_or_loopback("10.0.0.5")
    assert is_private_or_loopback("192.168.1.1")
    assert not is_private_or_loopback("8.8.8.8")


def test_merge_ports_override():
    ports = merge_ports("docker-research", parse_port_overrides("ssh=8022"))
    assert ports["ssh"] == 8022
    assert ports["http"] == 8081


def test_probe_port_map_both_includes_iana_and_lab():
    from honeypot_auditor.config import probe_port_map

    ports = probe_port_map("both")
    assert ports["ssh"] == [22, 2222]
    assert ports["http"] == [80, 8081, 443]
    assert ports["pop3"] == [110, 1110]
    assert ports["ftp"] == [21, 2121]
    assert ports["telnet"] == [23, 2323]
    assert ports["smtp"] == [25, 2525]
    assert ports["smb"] == [445, 1445]
    assert ports["sip"] == [5060]
    assert ports["vnc"] == [5900, 5000]
    assert ports["redis"] == [6379]
    assert ports["mysql"] == [3306]
    assert ports["git"] == [9418]
    assert ports["rdp"] == [3389]
    assert ports["httpproxy"] == [3128, 8080]
    assert ports["mssql"] == [1433]
    assert ports["mongodb"] == [27017]


def test_probe_port_map_dash_p_is_exclusive():
    from honeypot_auditor.config import probe_port_map

    ports = probe_port_map("both", extra_ports=[22])
    assert ports == {"ssh": [22]}
    assert "sip" not in ports
    assert "http" not in ports


def test_probe_port_map_dash_p_maps_protocols():
    from honeypot_auditor.config import probe_port_map

    ports = probe_port_map("iana", extra_ports=[2222, 8080, 110, 2200])
    assert ports["ssh"] == [2222, 2200]
    assert ports["httpproxy"] == [8080]
    assert ports["pop3"] == [110]
    assert "ftp" not in ports


def test_probe_port_map_dash_p_plus_ports_override():
    from honeypot_auditor.config import probe_port_map

    ports = probe_port_map("both", {"http": 8081}, extra_ports=[22])
    assert ports["ssh"] == [22]
    assert ports["http"] == [8081]
    assert "sip" not in ports


def test_parse_port_numbers():
    from honeypot_auditor.config import parse_port_numbers

    assert parse_port_numbers("22") == [22]
    assert parse_port_numbers("22,2222") == [22, 2222]


def test_parse_port_numbers_invalid():
    from honeypot_auditor.config import parse_port_numbers

    with pytest.raises(ValueError):
        parse_port_numbers("0")
    with pytest.raises(ValueError):
        parse_port_numbers("nope")


def test_protocol_strategies_use_the_same_terms():
    from honeypot_auditor.config import BASIC_STRATEGIES, PROTOCOL_STRATEGIES, STRATEGY_LABELS
    from honeypot_auditor.probes import PROBE_BY_PROTOCOL

    assert BASIC_STRATEGIES == ("arbitrary_auth", "state_nonpersist", "static_signature")
    assert set(PROTOCOL_STRATEGIES) == set(PROBE_BY_PROTOCOL)
    for _proto, row in PROTOCOL_STRATEGIES.items():
        assert tuple(row) == BASIC_STRATEGIES
    for key in BASIC_STRATEGIES:
        assert key in STRATEGY_LABELS
        assert STRATEGY_LABELS[key]


def test_nmap_honeypot_tells_include_cowrie():
    assert "cowrie" in NMAP_HONEYPOT_TELLS
    assert any("DiskStation" in t for t in FTP_WELCOME_TELLS)


def test_invalid_port():
    with pytest.raises(ValueError):
        parse_port_overrides("ssh=0")


def test_invalid_ports_format():
    with pytest.raises(ValueError):
        parse_port_overrides("ssh8022")


def test_unknown_preset():
    with pytest.raises(ValueError):
        merge_ports("not-a-preset")


def test_resolve_target_ip():
    from honeypot_auditor.config import resolve_target

    assert resolve_target("127.0.0.1") == "127.0.0.1"


def test_resolve_target_rejects_cidr():
    from honeypot_auditor.config import resolve_target

    with pytest.raises(ValueError, match="CIDR"):
        resolve_target("192.168.1.0/24")


def test_expand_scan_targets_host():
    from honeypot_auditor.config import expand_scan_targets

    kind, hosts = expand_scan_targets("10.0.0.5")
    assert kind == "host"
    assert hosts == ["10.0.0.5"]


def test_expand_scan_targets_slash24():
    from honeypot_auditor.config import expand_scan_targets

    kind, hosts = expand_scan_targets("192.168.1.0/24")
    assert kind == "subnet"
    assert len(hosts) == 254
    assert hosts[0] == "192.168.1.1"
    assert hosts[-1] == "192.168.1.254"


def test_expand_scan_targets_rejects_large_subnet():
    from honeypot_auditor.config import expand_scan_targets

    with pytest.raises(ValueError, match="too large"):
        expand_scan_targets("10.0.0.0/16")


def test_expand_scan_targets_slash32():
    from honeypot_auditor.config import expand_scan_targets

    kind, hosts = expand_scan_targets("192.168.1.99/32")
    assert kind == "subnet"
    assert hosts == ["192.168.1.99"]


@patch("honeypot_auditor.config.ports.socket.gethostbyname", return_value="93.184.216.34")
def test_resolve_target_hostname(mock_dns):
    from honeypot_auditor.config import resolve_target

    assert resolve_target("example.com") == "93.184.216.34"


def test_match_cpuinfo_signature():
    from honeypot_auditor.config import match_cpuinfo_signature

    assert match_cpuinfo_signature("model name : Intel(R) Core(TM)2 Duo CPU     T7300  @ 2.00GHz")


def test_ssh_banner_legacy():
    assert match_ssh_banner("SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2")
    assert match_ssh_banner("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3") is None


def test_uname_normalize():
    raw = "Linux decoy 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux"
    assert match_uname_signature(raw)


def test_uname_whitespace_only():
    from honeypot_auditor.config import normalize_uname

    assert normalize_uname("\n") == ""
    assert match_uname_signature("\n") is None


def test_match_cowrie_identity():
    from honeypot_auditor.config import match_cowrie_identity

    assert match_cowrie_identity("user_a15@svr04:~$ uname -a")
    assert match_cowrie_identity("Linux svr04 6.1.0-21-amd64 #1 SMP Debian")
    assert match_cowrie_identity(
        "The programs included with the Debian GNU/Linux system are free software;\n"
    )
    assert match_cowrie_identity("Linux realhost 6.1.0-21-amd64") is None


def test_match_ftp_stale_banner_and_auth_lure():
    from honeypot_auditor.config import match_ftp_auth_lure, match_ftp_stale_banner

    assert match_ftp_stale_banner("220 ProFTPD 1.2.10 Server") == "stock default 220 ProFTPD 1.2.10"
    assert match_ftp_stale_banner("220 ProFTPD 1.2.10")
    assert match_ftp_stale_banner("220 FTP Ready.")
    assert match_ftp_stale_banner("220 FTP server ready")
    assert match_ftp_stale_banner("220 vsftpd 3.0.3") is None
    assert match_ftp_auth_lure(
        "331 Guest login ok, send your complete e-mail address as password.",
        "530 Sorry, Authentication failed.",
    )
    assert match_ftp_auth_lure("", "530 Login incorrect.") is None


def test_match_smtp_placeholder_identity():
    from honeypot_auditor.config import match_smtp_lost_envelope, match_smtp_placeholder_identity

    assert match_smtp_placeholder_identity("220 localhost ESMTP")
    assert match_smtp_placeholder_identity("250 ip-127-0-0-1.internal")
    assert match_smtp_placeholder_identity(
        "220 ip-172-31-91-21.ec2.internal NO UCE NO RELAY PROBES ESMTP"
    )
    assert match_smtp_placeholder_identity("220 mail.example.com ESMTP Postfix") is None
    assert match_smtp_lost_envelope(250, 503, "Must have sender before recipient")
    assert match_smtp_lost_envelope(250, 550, "relay denied") is None
    assert match_smtp_lost_envelope(503, 503, "Must have sender before recipient") is None


def test_match_redis_class_tells():
    from honeypot_auditor.config import (
        match_redis_auth_any,
        match_redis_command_stub,
        match_redis_flush_stub,
        match_redis_help_client,
        match_redis_info_template,
        match_redis_unknown_core,
    )

    assert match_redis_auth_any("+OK\r\n")
    assert match_redis_auth_any("-ERR AUTH called without any password configured") is None
    assert match_redis_command_stub("+OK\r\n")
    assert match_redis_command_stub("*1\r\n*7\r\n$3\r\nget\r\n") is None
    assert match_redis_help_client("redis-cli 7.0.5\n~/.redisclirc")
    assert match_redis_help_client("ECHO message") is None
    assert match_redis_unknown_core("ECHO", "-ERR unknown command `ECHO`")
    assert match_redis_unknown_core("ECHO", "$4\r\nabcd\r\n") is None
    frozen = "server_time_usec:1644233854325059\ntotal_commands_processed:11"
    assert match_redis_info_template(frozen, frozen)
    assert match_redis_flush_stub("$9\r\nprobe_val\r\n", "probe_val")
    assert match_redis_flush_stub("$-1\r\n", "probe_val") is None


def test_match_telnet_option_spray():
    from honeypot_auditor.config import match_telnet_option_spray

    spray = bytes.fromhex("fffb03fffb00fffd00fffd1ffffd18fffd27fffd22")
    assert match_telnet_option_spray(spray, "Username: ")
    assert match_telnet_option_spray(b"\xff\xfb\x03\xff\xfb\x00", "Username: ") is None


def test_match_nmap_service_tell_unknown_and_lures():
    from honeypot_auditor.config import match_nmap_service_tell

    assert match_nmap_service_tell({"name": "tcpwrapped"}) is None
    assert (
        match_nmap_service_tell({"name": "ssh", "product": "OpenSSH", "version": "8.9p1"}) is None
    )
    assert match_nmap_service_tell({"name": "telnet", "product": "", "version": ""})
    smtp_fp = match_nmap_service_tell(
        {"name": "smtp", "product": "", "servicefp": "SF-Port2525-TCP:V=7.99"}
    )
    assert smtp_fp and "unrecognized" in smtp_fp.lower()
    assert match_nmap_service_tell(
        {"name": "ftp", "product": "vsftpd", "version": "(before 2.0.8) or WU-FTPD"}
    )
    uav = match_nmap_service_tell(
        {"name": "telnet", "servicefp": "User Access Verification\r\nUsername: Wrong password."}
    )
    assert uav and "User Access Verification" in uav
    http_unknown = match_nmap_service_tell({"name": "http", "product": "", "version": ""})
    assert http_unknown and "unrecognized" in http_unknown.lower()
    ssh_unknown = match_nmap_service_tell(
        {"name": "ssh", "product": "", "servicefp": "SF-Port22-TCP:V=7.99"}
    )
    assert ssh_unknown and "unrecognized" in ssh_unknown.lower()
    assert match_nmap_service_tell({"name": "http", "product": "nginx", "version": "1.24"}) is None
    assert match_nmap_service_tell({"name": "banner", "extrainfo": "SSH-2.0-OpenSSH_8.9"}) is None
    ftp_mismatch = match_nmap_service_tell(
        {
            "name": "ftp",
            "product": "vsftpd",
            "version": "2.0.8",
            "script_blob": "220 ProFTPD 1.2.10 Server (ProFTPD)",
        }
    )
    assert ftp_mismatch and "mismatch" in ftp_mismatch.lower()
    smtp_mismatch = match_nmap_service_tell(
        {
            "name": "smtp",
            "product": "Postfix smtpd",
            "script_blob": "220 mail ESMTP Exim 4.94",
        }
    )
    assert smtp_mismatch and "mismatch" in smtp_mismatch.lower()


def test_protocol_for_port_maps_new_faces():
    from honeypot_auditor.config import protocol_for_port

    assert protocol_for_port(3306) == "mysql"
    assert protocol_for_port(9418) == "git"
    assert protocol_for_port(3389) == "rdp"
    assert protocol_for_port(3128) == "httpproxy"
    assert protocol_for_port(1433) == "mssql"
    assert protocol_for_port(27017) == "mongodb"
    assert protocol_for_port(5000) == "vnc"
    assert protocol_for_port(8080) == "httpproxy"
    assert protocol_for_port(443) == "http"


def test_match_extra_protocol_class_tells():
    from honeypot_auditor.config import (
        MSSQL_CANNED_PRELOGIN,
        RDP_CANNED_FAIL,
        RDP_CANNED_NLA,
        match_git_always_missing,
        match_http_proxy_lure,
        match_mongo_ping_unauthorized,
        match_mongo_stock_hello,
        match_mssql_canned_prelogin,
        match_mysql_eol_banner,
        match_rdp_canned_nla,
        match_rdp_neg_fail,
        match_redis_auth_wall,
        match_ssh_banner,
        match_vnc_auth_fail,
        match_vnc_vncauth_only,
    )

    assert match_ssh_banner("SSH-2.0-OpenSSH_5.1p1 Debian-4 Ubuntu-1")
    assert match_mysql_eol_banner("5.5.43-0ubuntu0.14.04.1")
    assert match_mysql_eol_banner("8.0.36-0ubuntu0.22.04.1") is None
    assert match_git_always_missing("003dERR no such repository: /hpaudit.git")
    assert match_git_always_missing("0032refs/heads/main\n") is None
    assert match_rdp_canned_nla(RDP_CANNED_NLA)
    assert match_rdp_canned_nla(b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34") is None
    assert match_rdp_neg_fail(RDP_CANNED_FAIL)
    assert match_rdp_neg_fail(b"\x03\x00") is None
    assert match_http_proxy_lure(
        "HTTP/1.1 407 Proxy Authentication Required\r\n"
        "Via: 1.1 localhost (squid/3.3.8)\r\n"
        "X-Squid-Error: ERR_CACHE_ACCESS_DENIED 0\r\n"
    )
    assert match_http_proxy_lure("HTTP/1.1 407 Proxy Authentication Required\r\n") is None
    assert match_mssql_canned_prelogin(MSSQL_CANNED_PRELOGIN[1])
    assert match_mssql_canned_prelogin(b"\x04\x01\x00\xff") is None
    assert match_mongo_stock_hello(b"version\x00\x06\x00\x00\x004.4.6\x00")
    assert match_mongo_stock_hello(
        b"ismaster\x00\x10connectionId\x00\x01\x00\x00\x00version\x006.0.8"
    )
    assert match_mongo_stock_hello(b"version\x00\x06\x00\x00\x007.0.14\x00") is None
    assert match_mongo_ping_unauthorized("Authentication required")
    assert match_mongo_ping_unauthorized("{ok: 1.0}") is None
    assert match_vnc_vncauth_only(b"\x01\x02")
    assert match_vnc_auth_fail(b"\x00\x00\x00\x01\x00\x00\x00\x16Authentication failure")
    assert match_vnc_auth_fail(b"\x00\x00\x00\x00") is None
    assert match_redis_auth_wall(
        "-ERR invalid password\r\n", "-NOAUTH Authentication required.\r\n"
    )
    assert match_redis_auth_wall("-WRONGPASS invalid password\r\n", "*1\r\n$3\r\nget\r\n") is None
    from honeypot_auditor.config import (
        claimed_os_from_banner,
        match_ftp_port_bounce,
        match_smtp_extension_monotone,
        match_telnet_blind_option,
        match_tls_stock_cert,
        match_vnc_invalid_security_challenge,
    )

    assert claimed_os_from_banner("220 Microsoft ESMTP MAIL Service") == "windows"
    assert claimed_os_from_banner("SSH-2.0-OpenSSH_8.9") == "linux"
    assert match_telnet_blind_option(b"\xff\xfb\x63")
    assert match_ftp_port_bounce("200 PORT command successful")
    assert match_ftp_port_bounce("500 Illegal PORT command") is None
    assert match_vnc_invalid_security_challenge(b"\x00" * 16)
    assert match_vnc_invalid_security_challenge(b"\x01\x02") is None
    assert match_tls_stock_cert("CN=synologynas.local")
    assert match_smtp_extension_monotone(
        [("VRFY", 250, "ok"), ("EXPN", 250, "ok"), ("ETRN", 250, "ok"), ("STARTTLS", 250, "ok")]
    )
