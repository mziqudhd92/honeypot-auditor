"""Compatibility re-exports. Prefer ``honeypot_auditor.probes.http`` (etc.)."""

from honeypot_auditor.probes.http import probe_http
from honeypot_auditor.probes.pop3 import probe_pop3
from honeypot_auditor.probes.redis import probe_redis
from honeypot_auditor.probes.sip import probe_sip
from honeypot_auditor.probes.smtp import probe_smtp
from honeypot_auditor.probes.vnc import probe_vnc

__all__ = ["probe_http", "probe_pop3", "probe_redis", "probe_sip", "probe_smtp", "probe_vnc"]
