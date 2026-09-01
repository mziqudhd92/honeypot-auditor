"""Per-protocol fingerprint engines.

Each service lives in its own module so reviewers can read one playbook at a time:

    probes/ssh.py       probes/telnet.py     probes/ftp.py
    probes/http.py      probes/smb.py        probes/redis.py
    probes/smtp.py      probes/vnc.py        probes/sip.py
    probes/mysql.py     probes/git.py        probes/rdp.py
    probes/httpproxy.py probes/mssql.py     probes/mongodb.py

Every protocol uses the same three strategies: arbitrary auth, state non-persistence,
static signature (see ``PROTOCOL_STRATEGIES`` in config).

Shared helpers: ``common.py`` (creds / skip rows), ``shell_cti.py`` (Cowrie/Kippo tells).
Recon (Shodan/Nmap) is ``recon.py``. ``--deep`` axes live under ``deep/``.
"""

from __future__ import annotations

from collections.abc import Callable

from honeypot_auditor.models import Indicator
from honeypot_auditor.probes.ftp import probe_ftp
from honeypot_auditor.probes.git import probe_git
from honeypot_auditor.probes.http import probe_http
from honeypot_auditor.probes.httpproxy import probe_httpproxy
from honeypot_auditor.probes.mongodb import probe_mongodb
from honeypot_auditor.probes.mssql import probe_mssql
from honeypot_auditor.probes.mysql import probe_mysql
from honeypot_auditor.probes.postgres import probe_postgres
from honeypot_auditor.probes.rdp import probe_rdp
from honeypot_auditor.probes.redis import probe_redis
from honeypot_auditor.probes.sip import probe_sip
from honeypot_auditor.probes.smb import probe_smb
from honeypot_auditor.probes.smtp import probe_smtp
from honeypot_auditor.probes.ssh import probe_ssh
from honeypot_auditor.probes.telnet import probe_telnet
from honeypot_auditor.probes.vnc import probe_vnc

ProbeFn = Callable[[str, int], list[Indicator]]

PROBE_BY_PROTOCOL: dict[str, ProbeFn] = {
    "ssh": probe_ssh,
    "telnet": probe_telnet,
    "smb": probe_smb,
    "ftp": probe_ftp,
    "http": probe_http,
    "redis": probe_redis,
    "smtp": probe_smtp,
    "vnc": probe_vnc,
    "sip": probe_sip,
    "mysql": probe_mysql,
    "postgres": probe_postgres,
    "git": probe_git,
    "rdp": probe_rdp,
    "httpproxy": probe_httpproxy,
    "mssql": probe_mssql,
    "mongodb": probe_mongodb,
}

try:
    from honeypot_auditor.plugins.api import get_registered_probes

    for _name, _fn in get_registered_probes().items():
        if _name not in PROBE_BY_PROTOCOL:
            PROBE_BY_PROTOCOL[_name] = _fn
except Exception as exc:
    import logging

    logging.getLogger(__name__).warning("plugin probe merge failed: %s", exc)

__all__ = [
    "PROBE_BY_PROTOCOL",
    "probe_ftp",
    "probe_git",
    "probe_http",
    "probe_httpproxy",
    "probe_mongodb",
    "probe_mssql",
    "probe_mysql",
    "probe_postgres",
    "probe_rdp",
    "probe_redis",
    "probe_sip",
    "probe_smb",
    "probe_smtp",
    "probe_ssh",
    "probe_telnet",
    "probe_vnc",
]
