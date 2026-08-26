"""Tests for Shodan and Nmap recon modules (mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from honeypot_auditor.probes.recon import nmap_scan, shodan_lookup


def test_shodan_skipped_without_api_key():
    inds = shodan_lookup("8.8.8.8", None)
    assert len(inds) == 2
    assert all(i.skipped for i in inds)


def test_shodan_skipped_on_private_ip():
    inds = shodan_lookup("127.0.0.1", "fake-key")
    assert len(inds) == 2
    assert all(i.skipped for i in inds)
    assert "RFC1918" in inds[0].skip_reason or "loopback" in inds[0].skip_reason.lower()


@patch("honeypot_auditor.probes.recon._honeyscore", return_value=(0.85, ""))
@patch("honeypot_auditor.probes.recon._host_tags", return_value=(["honeypot"], ""))
def test_shodan_honeyscore_and_tag_hit(mock_tags, mock_score):
    inds = shodan_lookup("8.8.8.8", "fake-key")
    by_id = {i.id: i for i in inds}
    assert by_id["shodan.honeyscore"].triggered
    assert by_id["shodan.tags"].triggered


def test_nmap_disabled():
    inds = nmap_scan("127.0.0.1", {"ssh": 22}, enabled=False)
    assert inds[0].skipped
    assert "skip-nmap" in inds[0].skip_reason


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


@patch("honeypot_auditor.probes.recon.shutil.which", return_value=None)
def test_nmap_skipped_without_binary(mock_which):
    inds = nmap_scan("127.0.0.1", {"ssh": 22})
    assert inds[0].skipped
    assert "PATH" in inds[0].skip_reason
