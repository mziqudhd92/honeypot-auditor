"""Compatibility re-exports. Prefer ``honeypot_auditor.probes.ssh`` (etc.)."""

from honeypot_auditor.probes.ftp import probe_ftp
from honeypot_auditor.probes.smb import probe_smb
from honeypot_auditor.probes.ssh import probe_ssh
from honeypot_auditor.probes.telnet import probe_telnet

__all__ = ["probe_ftp", "probe_smb", "probe_ssh", "probe_telnet"]
