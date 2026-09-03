"""Tests for Shodan and Nmap recon modules (mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from honeypot_auditor.probes.recon import _http_get, nmap_scan, shodan_lookup


def test_shodan_skipped_without_api_key():
    inds = shodan_lookup("8.8.8.8", None)
    assert len(inds) == 4
    assert all(i.skipped for i in inds)


def test_shodan_skipped_on_private_ip():
    inds = shodan_lookup("127.0.0.1", "fake-key")
    assert len(inds) == 4
    assert all(i.skipped for i in inds)
    assert "RFC1918" in inds[0].skip_reason or "loopback" in inds[0].skip_reason.lower()


def test_passive_intel_http_rejects_non_https_and_unapproved_hosts():
    with patch("honeypot_auditor.probes.recon.urlopen") as mock_open:
        for url in (
            "http://api.shodan.io/labs/honeyscore/8.8.8.8",
            "https://api.shodan.io.evil.invalid/labs/honeyscore/8.8.8.8",
            "file:///etc/passwd",
        ):
            body, err = _http_get(url, {"key": "synthetic"})
            assert body == ""
            assert "allowlist" in err
        mock_open.assert_not_called()


def test_passive_intel_http_allows_only_shodan_https_endpoint():
    response = MagicMock()
    response.status = 200
    response.read.return_value = b"0.25"
    response.__enter__.return_value = response
    with patch("honeypot_auditor.probes.recon.urlopen", return_value=response) as mock_open:
        body, err = _http_get("https://api.shodan.io/labs/honeyscore/8.8.8.8", {"key": "synthetic"})
    assert (body, err) == ("0.25", "")
    assert mock_open.call_count == 1


@patch("honeypot_auditor.probes.recon._honeyscore", return_value=(0.85, ""))
@patch(
    "honeypot_auditor.probes.recon._host_lookup",
    return_value=({"tags": ["honeypot"], "data": []}, ""),
)
def test_shodan_honeyscore_and_tag_hit(mock_lookup, mock_score):
    inds = shodan_lookup("8.8.8.8", "fake-key")
    by_id = {i.id: i for i in inds}
    assert by_id["shodan.honeyscore"].triggered
    assert by_id["shodan.tags"].triggered


def test_nmap_disabled():
    inds = nmap_scan("127.0.0.1", {"ssh": 22}, enabled=False)
    assert inds[0].skipped
    assert "with-nmap" in inds[0].skip_reason or "-n" in inds[0].skip_reason


@patch("honeypot_auditor.probes.recon.shutil.which", return_value="/usr/bin/nmap")
@patch("honeypot_auditor.probes.recon._open_tcp_ports", return_value=[8023, 8022])
def test_nmap_parses_cowrie_product(mock_open, mock_which):
    tcp_bucket = {
        8023: {
            "name": "telnet",
            "product": "Cowrie Honeypot telnetd",
            "version": "",
            "extrainfo": "",
            "cpe": "",
            "script": {},
        },
        8022: {
            "name": "ssh",
            "product": "OpenSSH",
            "version": "9.2p1",
            "extrainfo": "",
            "cpe": "",
            "script": {},
        },
    }

    host_obj = MagicMock()
    host_obj.all_tcp.return_value = [8023, 8022]
    host_obj.all_udp.return_value = []

    def getitem(key):
        return tcp_bucket if key == "tcp" else {}

    host_obj.__getitem__.side_effect = getitem

    scanner = MagicMock()
    scanner.all_hosts.return_value = ["127.0.0.1"]
    scanner.__getitem__.return_value = host_obj

    fake_nmap = MagicMock()
    fake_nmap.PortScanner.return_value = scanner

    def import_side(name):
        return fake_nmap if name == "nmap" else None

    with patch("honeypot_auditor.probes.recon.optional_import", side_effect=import_side):
        inds = nmap_scan("127.0.0.1", {"ssh": 8022, "telnet": 8023})

    assert inds[0].triggered
    assert "Cowrie" in inds[0].detail


@patch("honeypot_auditor.probes.recon.shutil.which", return_value="/usr/bin/nmap")
@patch("honeypot_auditor.probes.recon._open_tcp_ports", return_value=[23, 21, 2525])
def test_nmap_unrecognized_fingerprint_and_ambiguous_ftp(mock_open, mock_which):
    tcp_bucket = {
        23: {
            "name": "telnet",
            "product": "",
            "version": "",
            "extrainfo": "",
            "cpe": "",
            "servicefp": "SF-Port23-TCP:V=7.99 User Access Verification Username:",
            "script": {},
        },
        21: {
            "name": "ftp",
            "product": "vsftpd",
            "version": "(before 2.0.8) or WU-FTPD",
            "extrainfo": "",
            "cpe": "",
            "script": {},
        },
        2525: {
            "name": "smtp",
            "product": "",
            "version": "",
            "extrainfo": "ip-172-31-91-21.ec2.internal NO UCE NO RELAY PROBES",
            "cpe": "",
            "script": {},
        },
    }
    host_obj = MagicMock()
    host_obj.all_tcp.return_value = [23, 21, 2525]
    host_obj.all_udp.return_value = []
    host_obj.__getitem__.side_effect = lambda key: tcp_bucket if key == "tcp" else {}
    scanner = MagicMock()
    scanner.all_hosts.return_value = ["127.0.0.1"]
    scanner.__getitem__.return_value = host_obj
    fake_nmap = MagicMock()
    fake_nmap.PortScanner.return_value = scanner

    with patch("honeypot_auditor.probes.recon.optional_import", return_value=fake_nmap):
        inds = nmap_scan("127.0.0.1", {"telnet": 23, "ftp": 21, "smtp": 2525})

    assert inds[0].triggered
    detail = inds[0].detail.lower()
    assert "telnet" in detail or "user access" in detail.lower()
    assert "ftp" in detail or "ambiguous" in detail
    assert "smtp" in detail or "uce" in detail or "private" in detail


@patch("honeypot_auditor.probes.recon.shutil.which", return_value="/usr/bin/nmap")
@patch(
    "honeypot_auditor.probes.recon._open_tcp_ports",
    return_value=[21, 22, 23, 25, 80, 110, 139, 443, 445, 5900, 6379],
)
def test_nmap_version_scans_every_open_port(mock_open, mock_which):
    scanner = MagicMock()
    scanner.all_hosts.return_value = []
    fake_nmap = MagicMock()
    fake_nmap.PortScanner.return_value = scanner
    ports = {
        "ftp": 21,
        "ssh": 22,
        "telnet": 23,
        "smtp": 25,
        "http": 80,
        "pop3": 110,
        "netbios": 139,
        "https": 443,
        "smb": 445,
        "vnc": 5900,
        "redis": 6379,
    }
    with patch("honeypot_auditor.probes.recon.optional_import", return_value=fake_nmap):
        nmap_scan("127.0.0.1", ports)
    arguments = scanner.scan.call_args.kwargs["arguments"]
    for port in mock_open.return_value:
        assert str(port) in arguments
    assert "-sV" in arguments


@patch("honeypot_auditor.probes.recon.shutil.which", return_value="/usr/bin/nmap")
@patch("honeypot_auditor.probes.recon._open_tcp_ports", return_value=[])
def test_nmap_skipped_no_open_ports(mock_open, mock_which):
    fake_nmap = MagicMock()
    with patch("honeypot_auditor.probes.recon.optional_import", return_value=fake_nmap):
        inds = nmap_scan("127.0.0.1", {"ssh": 8022})
    assert inds[0].skipped
    assert "no open TCP" in inds[0].skip_reason


@patch("honeypot_auditor.probes.recon.shutil.which", return_value="/usr/bin/nmap")
@patch("honeypot_auditor.probes.recon._open_tcp_ports", return_value=[22])
def test_nmap_scan_failure(mock_open, mock_which):
    fake_nmap = MagicMock()
    fake_nmap.PortScanner.return_value.scan.side_effect = RuntimeError("boom")
    with patch("honeypot_auditor.probes.recon.optional_import", return_value=fake_nmap):
        inds = nmap_scan("127.0.0.1", {"ssh": 22})
    assert inds[0].skipped
    assert "nmap failed" in inds[0].skip_reason


@patch("honeypot_auditor.probes.recon._http_get", return_value=("", "HTTP 403"))
def test_shodan_honeyscore_api_error(mock_get):
    inds = shodan_lookup("8.8.8.8", "fake-key")
    by_id = {i.id: i for i in inds}
    assert by_id["shodan.honeyscore"].skipped


@patch("honeypot_auditor.probes.recon._host_lookup", return_value=({}, "rate limit"))
@patch("honeypot_auditor.probes.recon._honeyscore", return_value=(0.1, ""))
def test_shodan_tag_api_error(mock_score, mock_lookup):
    inds = shodan_lookup("8.8.8.8", "fake-key")
    by_id = {i.id: i for i in inds}
    assert not by_id["shodan.honeyscore"].triggered
    assert by_id["shodan.tags"].skipped


@patch("honeypot_auditor.probes.recon.shutil.which", return_value=None)
def test_nmap_skipped_without_binary(mock_which):
    inds = nmap_scan("127.0.0.1", {"ssh": 22})
    assert inds[0].skipped
    assert "PATH" in inds[0].skip_reason


@patch("honeypot_auditor.probes.recon.optional_import", return_value=None)
@patch("honeypot_auditor.probes.recon._http_get")
def test_host_tags_rest_fallback(mock_get, mock_import):
    mock_get.return_value = ('{"tags": ["scanner"]}', "")

    from honeypot_auditor.probes.recon import _host_lookup

    info, err = _host_lookup("8.8.8.8", "key")
    tags = [str(t) for t in (info.get("tags") or [])]
    assert tags == ["scanner"]
    assert err == ""


def test_osint_only_skips_tcp_probes(monkeypatch):
    from honeypot_auditor import cli
    from honeypot_auditor.settings import settings

    settings.osint_only = True
    try:
        # Without a key, Shodan is not scheduled at all (opt-in).
        args = cli.build_parser().parse_args(["--target", "127.0.0.1", "--osint-only"])
        jobs = cli._probe_jobs("127.0.0.1", {"ssh": [22]}, args, include_shodan=True)
        assert [n for n, _ in jobs] == []

        # With a key, only the Shodan job runs — no TCP probes.
        args = cli.build_parser().parse_args(
            ["--target", "127.0.0.1", "--osint-only", "--shodan-key", "fake"]
        )
        with patch("honeypot_auditor.cli.shodan_lookup", return_value=[]):
            jobs = cli._probe_jobs("127.0.0.1", {"ssh": [22]}, args, include_shodan=True)
        names = [n for n, _ in jobs]
        assert names == ["shodan"]
        assert not any(":" in n for n in names)
    finally:
        settings.osint_only = False


def test_shodan_job_skipped_without_key():
    from honeypot_auditor import cli

    args = cli.build_parser().parse_args(["--target", "127.0.0.1", "-p", "21"])
    with patch("honeypot_auditor.cli.shodan_lookup") as shodan:
        jobs = cli._probe_jobs("127.0.0.1", {"ftp": [21]}, args, include_shodan=True)
    shodan.assert_not_called()
    assert "shodan" not in [n for n, _ in jobs]
    assert any(n.startswith("ftp:") for n, _ in jobs)
