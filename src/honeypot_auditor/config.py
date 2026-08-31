"""Scoring weights, timeouts, port presets, and signature corpus."""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
import time
from collections.abc import Mapping

from honeypot_auditor import __version__

USER_AGENT = f"honeypot-auditor/{__version__}"
DEFAULT_TIMEOUT_SECONDS = 3.0
NMAP_HOST_TIMEOUT = "90s"
SHODAN_HONEYSCORE_URL = "https://api.shodan.io/labs/honeyscore/{ip}"
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
SHODAN_SCORE_THRESHOLD = 0.6

WEIGHTS: dict[str, float] = {
    "shodan": 0.25,
    "arbitrary_auth": 0.30,
    "state_nonpersist": 0.25,
    "static_signature": 0.20,
    "cotenancy": 0.15,
}

# Graduated bonus when many protocols fire tells (beyond the first).
CORROBORATION_PROTOCOL_THRESHOLD = 1
CORROBORATION_PROTOCOL_STEP_PCT = 5.0
CORROBORATION_PROTOCOL_MAX_BONUS = 35.0

# Same three detection strategies on every protocol (how each service applies them differs).
BASIC_STRATEGIES: tuple[str, ...] = ("arbitrary_auth", "state_nonpersist", "static_signature")

STRATEGY_LABELS: dict[str, str] = {
    "shodan": "Shodan intel",
    "arbitrary_auth": "Arbitrary auth",
    "state_nonpersist": "State non-persistence",
    "static_signature": "Static signature",
    "behavior": "Shell execution semantics",
    "coherence": "Cross-artifact OS coherence",
    "stack_fingerprint": "HASSH / TCP stack fingerprint",
    "proto_conformance": "Protocol FSM conformance",
    "cotenancy": "Multi-service honeypot buffet",
    "corroboration": "Multi-protocol corroboration bonus",
    "temporal": "Temporal / latency behavior",
}

# Per-protocol instantiation of BASIC_STRATEGIES. Empty = not used on the basic path.
PROTOCOL_STRATEGIES: dict[str, dict[str, str]] = {
    "ssh": {
        "arbitrary_auth": "any-password (2 random users)",
        "state_nonpersist": "exec vs fake PTY · /tmp canary",
        "static_signature": "banner · lure whoami · honeyfs",
    },
    "telnet": {
        "arbitrary_auth": "any-password (2 random users)",
        "state_nonpersist": "canned reject · /tmp canary",
        "static_signature": "UAV / IAC spray · unknown-option WILL · lure whoami · fake tty/pipes",
    },
    "ftp": {
        "arbitrary_auth": "stock decoy login (test)",
        "state_nonpersist": "PASV mismatch · canned 530 · STOR/SIZE · FEAT/PWD desert",
        "static_signature": "stock 220 · SYST L8 · PORT bounce",
    },
    "smtp": {
        "arbitrary_auth": "AUTH any-password · open relay",
        "state_nonpersist": "MAIL then RCPT 503 (lost envelope)",
        "static_signature": "loopback identity · VRFY/EXPN/STARTTLS/ETRN monotone",
    },
    "http": {
        "arbitrary_auth": "",
        "state_nonpersist": "",
        "static_signature": "empty PUT 405 · GET / → index.html login skin · 407 Via localhost",
    },
    "smb": {
        "arbitrary_auth": "",
        "state_nonpersist": "bogus pipe NTSTATUS · session FSM",
        "static_signature": "SMB1/EOL native_os · static NTLM challenge",
    },
    "sip": {
        "arbitrary_auth": "",
        "state_nonpersist": "",
        "static_signature": "default User-Agent template",
    },
    "vnc": {
        "arbitrary_auth": "",
        "state_nonpersist": "RFB auth always canned failure (no desktop)",
        "static_signature": "RFB 3.8 VNC-auth only · canned Authentication failure · type-0 still challenges",
    },
    "redis": {
        "arbitrary_auth": "AUTH any-password",
        "state_nonpersist": "FLUSHALL no-op · key vanishes after reconnect",
        "static_signature": "COMMAND stub · EVAL/CONFIG stub · AUTH-invalid+COMMAND NOAUTH wall · frozen INFO · missing ECHO/SELECT",
    },
    "mysql": {
        "arbitrary_auth": "",
        "state_nonpersist": "drop after 1045 · wrong-seq ER 1156 · SSL-request silent drop",
        "static_signature": "EOL 5.5.x ubuntu greeting · stock handshake caps",
    },
    "git": {
        "arbitrary_auth": "",
        "state_nonpersist": "",
        "static_signature": "git-upload-pack always ERR no such repository",
    },
    "rdp": {
        "arbitrary_auth": "",
        "state_nonpersist": "second packet is canned negotiation failure",
        "static_signature": "canned NLA cookie 0x1234",
    },
    "httpproxy": {
        "arbitrary_auth": "",
        "state_nonpersist": "",
        "static_signature": "407 Via localhost · frozen squid 3.3.8 · ISA deny phrase",
    },
    "mssql": {
        "arbitrary_auth": "",
        "state_nonpersist": "canned LOGIN7 18456 failure · TLS close after ENCRYPT_NOT_SUP",
        "static_signature": "canned TDS prelogin · PRELOGIN encrypt NOT SUP",
    },
    "mongodb": {
        "arbitrary_auth": "",
        "state_nonpersist": "ping unauthorized after hello",
        "static_signature": "hello connectionId frozen at 1 · OP_MSG synthetic reply",
    },
    "postgres": {
        "arbitrary_auth": "",
        "state_nonpersist": "cleartext-only auth · frozen auth.c:326 fail blob",
        "static_signature": "SSLRequest → N then AuthenticationCleartextPassword only",
    },
}

# Deep-mode strategies (--deep). Sum adds to 0.75 atop basic weights when all fire.
DEEP_WEIGHTS: dict[str, float] = {
    "behavior": 0.18,
    "coherence": 0.15,
    "stack_fingerprint": 0.12,
    "proto_conformance": 0.12,
    "temporal": 0.10,
}

# Extra ports scanned for co-tenancy on deception / lab stacks.
EXTENDED_PROBE_PORTS: dict[str, int] = {
    "modbus": 1502,
    "snmp": 161,
    "dns": 15353,
    "ipp": 631,
    "pop": 1110,
}

# Strategies that corroborate co-tenancy (avoid false positives on multi-decoy platforms).
COTENANCY_CORROBORATION_CATEGORIES = frozenset(
    {
        "arbitrary_auth",
        "behavior",
        "static_signature",
        "state_nonpersist",
        "coherence",
        "stack_fingerprint",
    }
)

THREAT_CONFIRMED = 60.0
THREAT_SUSPECTED = 30.0

THREAT_LEVELS = {
    "confirmed": "Confirmed Honeypot",
    "suspected": "Suspected Honeypot",
    "likely_real": "Likely Real Host",
    "inconclusive": "Inconclusive",
}

PORT_PRESET_IANA: dict[str, int] = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "http": 80,
    "smb": 445,
    "sip": 5060,
    "vnc": 5900,
    "redis": 6379,
    "mysql": 3306,
    "postgres": 5432,
    "git": 9418,
    "rdp": 3389,
    "httpproxy": 3128,
    "mssql": 1433,
    "mongodb": 27017,
}

# Non-privileged ports common in Docker / lab compose stacks.
PORT_PRESET_DOCKER_RESEARCH: dict[str, int] = {
    "ftp": 2121,
    "ssh": 2222,
    "telnet": 2323,
    "smtp": 2525,
    "http": 8081,
    "smb": 1445,
    "sip": 5060,
    "vnc": 5000,
    "redis": 6379,
    "mysql": 3306,
    "postgres": 5432,
    "git": 9418,
    "rdp": 3389,
    "httpproxy": 8080,
    "mssql": 1433,
    "mongodb": 27017,
}

PORT_PRESETS: dict[str, dict[str, int]] = {
    "iana": PORT_PRESET_IANA,
    "docker-research": PORT_PRESET_DOCKER_RESEARCH,
}

DEFAULT_PORT_PRESET = "both"
PORT_PRESET_CHOICES = ("both", "iana", "docker-research")

# Extra well-known numbers not in the two presets (still map -p to a protocol).
_EXTRA_PORT_PROTOCOLS: dict[int, str] = {
    139: "smb",
    443: "http",
    8080: "httpproxy",
    8443: "http",
    5061: "sip",
    5000: "vnc",
    5901: "vnc",
}


def _well_known_port_protocols() -> dict[int, str]:
    mapping: dict[int, str] = dict(_EXTRA_PORT_PROTOCOLS)
    for proto, port in PORT_PRESET_IANA.items():
        mapping[port] = proto
    for proto, port in PORT_PRESET_DOCKER_RESEARCH.items():
        mapping[port] = proto
    return mapping


WELL_KNOWN_PORT_PROTOCOLS = _well_known_port_protocols()

NMAP_SCRIPTS = "banner,ssh2-enum-algos,ssh-auth-methods,ssh-publickey-acceptance"
_NMAP_NSE_SCRIPT_NAMES = frozenset(
    s.strip().lower() for s in NMAP_SCRIPTS.split(",") if s.strip()
)

# Sort -sV ports in this order, then any other open preset ports. No cap: every open preset port is version-scanned.
NMAP_PORT_PRIORITY = (
    "telnet",
    "ssh",
    "ftp",
    "http",
    "smb",
    "smtp",
    "vnc",
    "redis",
    "sip",
    "mysql",
    "postgres",
    "git",
    "rdp",
    "httpproxy",
    "mssql",
    "mongodb",
)

# Substrings in nmap service/product/version/script output that indicate emulators.
NMAP_HONEYPOT_TELLS = (
    "honeypot",
    "cowrie",
    "kippo",
    "dionaea",
    "conpot",
    "opencanary",
    "honeyd",
    "amun",
    "glastopf",
)

PROBE_USERNAME_TEMPLATE = "user_a{n}"
PROBE_PASSWORD_TEMPLATE = "pass_z{n}"
FTP_PROBE_PREFIX = "hpaudit_"
FTP_PROBE_BODY = b"hpaudit-state-probe\n"
FTP_WELCOME_TELLS = (
    "DiskStation FTP server",
    "dionaea",
    "honeypot ftp",
)
# Exact 220 strings many low-interaction FTP lures ship unchanged (not a live daemon).
FTP_STOCK_220 = (
    "ProFTPD 1.2.10",
    "FTP Ready.",
    "FTP server ready",
    "Microsoft FTP Service",
)
# Broader EOL versions on the 220 line (frozen emulator templates).
_FTP_STALE_BANNER_RE = re.compile(
    r"(ProFTPD\s+1\.2\.\S+|ProFTPD\s+1\.3\.[0-4]\S*|vsftpd\s+[12]\.[0-3]\.\S+|FileZilla[^\r\n]*0\.9\.\S+)",
    re.IGNORECASE,
)
FTP_CANNED_REJECTS = (
    "Sorry, Authentication failed",
    "User cannot log in",
)
# Stock decoy logins (not a brute-force list). Tried only after anonymous + random fail.
FTP_LURE_ACCOUNTS = (
    ("test", ""),
    ("test", "test"),
    ("user", "test"),
    ("ftp", "ftp"),
    ("admin", "admin"),
    ("user", "user"),
)
FTP_SYST_TELLS = (
    "215 UNIX Type: L8",
    "215 UNIX Type: L8 version",
)
HTTP_SERVER_TELLS = (
    "nginx",
    "apache/2.2.22",
)
HTTP_STATIC_BODY_MARKERS = (
    b"<html>",
    b"Welcome",
)
REDIS_PROBE_KEY_PREFIX = "hpaudit_"
REDIS_PROBE_VALUE = "probe_val"

SMTP_HELO = "auditor.invalid"
SMTP_MAIL_FROM = "probe@auditor.invalid"
SMTP_RCPT_TO = "fake_user@external-domain.com"

SSH_BANNER_SIGNATURES = (
    "SSH-2.0-OpenSSH_5.1p1 Debian-4",
    "SSH-2.0-OpenSSH_5.1p1 Debian-5",
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4",
)

UNAME_SIGNATURES = (
    "Linux <host> 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:08 UTC 2009 i686 GNU/Linux",
    "Linux <host> 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux",
    "Linux <host> 3.2.0-4-amd64 #1 SMP Debian 3.2.51-1 x86_64 GNU/Linux",
)

CPUINFO_TELLS = (
    "Intel(R) Core(TM)2 Duo CPU     T7300  @ 2.00GHz",
    "Intel(R) Core(TM)2 Duo CPU T7300 @ 2.00GHz",
)

# Cowrie/Kippo honeyfs defaults (cowrie.cfg.dist hostname = svr04).
COWRIE_HOSTNAMES = ("svr04", "nas3")
COWRIE_MOTD_TELLS = (
    "The programs included with the Debian GNU/Linux system are free software",
)

SMB_SMB1_DIALECTS = frozenset({"NT LM 0.12", "SMB1", "1.0"})
SMB_NATIVE_OS_TELLS = ("Windows 5.0", "Windows 5.1", "Unix")
SMB2_DIALECT_30 = 0x0300
SMB2_DIALECT_311 = 0x0311
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
HTTP_DYNAMIC_HEADERS = ("date",)
SIP_UA_TELLS = ("honeypot", "sipuas", "friendly-scanner")

_UNAME_HOST_RE = re.compile(r"^Linux\s+\S+\s+")


def match_ssh_banner(banner: str) -> str | None:
    text = (banner or "").strip()
    for sig in SSH_BANNER_SIGNATURES:
        if sig in text:
            return sig
    return None


def normalize_uname(text: str) -> str:
    if not text:
        return ""
    lines = (text or "").strip().splitlines()
    if not lines:
        return ""
    line = lines[0]
    return _UNAME_HOST_RE.sub("Linux <host> ", line).strip()


def match_uname_signature(text: str) -> str | None:
    norm = normalize_uname(text)
    for sig in UNAME_SIGNATURES:
        if norm == sig:
            return sig
    return None


def match_cpuinfo_signature(text: str) -> str | None:
    blob = text or ""
    for tell in CPUINFO_TELLS:
        if tell in blob:
            return tell
    return None


def match_cowrie_identity(text: str) -> str | None:
    """Default Cowrie/Kippo hostname or MOTD (works even when banners are modern OpenSSH)."""
    blob = text or ""
    if not blob.strip():
        return None
    low = blob.lower()
    for host in COWRIE_HOSTNAMES:
        token = host.lower()
        if f"@{token}" in low or f"linux {token} " in low or f"linux {token}\n" in low:
            return f"cowrie-default-hostname={host}"
    for motd in COWRIE_MOTD_TELLS:
        if motd.lower() in low:
            return "cowrie-default-motd"
    return None


# Pre-auth telnet lures (scored even when random login is rejected).
TELNET_BANNER_TELLS = (
    "User Access Verification",  # Cisco IOS-class greeting used by many telnet lures
    "Welcome to Microsoft Telnet Service",
    "honeypot",
)
# Real Cisco uses "% Authentication failed" / "% Login invalid"; real Unix uses "Login incorrect".
TELNET_CANNED_REJECTS = (
    "Wrong password.",
    "Wrong password",
    "Too many wrong attempts",
)


def match_telnet_banner(text: str) -> str | None:
    blob = text or ""
    if not blob.strip():
        return None
    low = blob.lower()
    for tell in TELNET_BANNER_TELLS:
        if tell.lower() in low:
            return tell
    return None


def match_telnet_canned_reject(text: str) -> str | None:
    blob = text or ""
    if not blob.strip():
        return None
    low = blob.lower()
    for tell in TELNET_CANNED_REJECTS:
        if tell.lower() in low:
            return tell
    return None


def match_telnet_option_spray(raw: bytes, text: str = "") -> str | None:
    """Many WILL/DO options then a Username: prompt — typical of a canned telnet FSM."""
    data = raw or b""
    n_will_do = 0
    i = 0
    while i + 2 < len(data):
        if data[i] == 255 and data[i + 1] in (251, 253):  # WILL / DO
            n_will_do += 1
            i += 3
            continue
        i += 1
    if n_will_do >= 5 and "username:" in (text or "").lower():
        return f"IAC option spray ({n_will_do} WILL/DO) then Username:"
    return None


def match_telnet_blind_option(raw: bytes) -> str | None:
    """Server WILL/DO unknown option 99 (RFC 854 would WONT/DONT)."""
    data = raw or b""
    if b"\xff\xfb\x63" in data or b"\xff\xfd\x63" in data:
        return "accepted unknown Telnet option 99"
    return None


def claimed_os_from_banner(text: str) -> str:
    """Best-effort OS family from a service banner (for stack vs banner)."""
    low = (text or "").lower()
    if any(tok in low for tok in ("windows", "microsoft", "exchange", "iis")):
        return "windows"
    if any(tok in low for tok in ("linux", "ubuntu", "debian", "unix type", "openssh")):
        return "linux"
    return ""


def match_smtp_extension_monotone(replies: list[tuple[str, int, str]]) -> str | None:
    """VRFY/EXPN/STARTTLS/ETRN return one generic code instead of RFC-distinct replies."""
    if len(replies) < 3:
        return None
    hits: list[str] = []
    for cmd, code, _msg in replies:
        if cmd == "VRFY" and code == 250:
            hits.append("VRFY 250 (real MTAs usually 252/550/502)")
        if cmd == "STARTTLS" and code == 250:
            hits.append("STARTTLS 250 instead of 220")
    codes = [c for _, c, _ in replies]
    if len(set(codes)) == 1 and codes[0] in {250, 500, 502, 503}:
        hits.append(f"VRFY/EXPN/ETRN/STARTTLS all returned {codes[0]}")
    return "; ".join(hits) if hits else None


def match_ftp_port_bounce(resp: str) -> str | None:
    """PORT to an unrelated host was accepted (no anti-bounce)."""
    first = (resp or "").strip().split(None, 1)[0] if resp else ""
    if first in {"200", "250"}:
        return f"PORT to an external address accepted ({first})"
    return None


def match_ftp_command_desert(responses: dict[str, str]) -> str | None:
    """Common FTP verbs all return the same shallow 500 Unknown Command."""
    unknown: list[str] = []
    for cmd, resp in (responses or {}).items():
        low = (resp or "").lower()
        if "500" in (resp or "") and "unknown" in low:
            unknown.append(cmd)
    if len(unknown) >= 2:
        return f"{len(unknown)} common verbs return 500 Unknown Command ({', '.join(unknown)})"
    return None


def match_vnc_invalid_security_challenge(raw: bytes) -> str | None:
    """Selecting security type 0 still produced a 16-byte VNC-auth challenge."""
    data = raw or b""
    if len(data) == 16 and not data.startswith(b"RFB"):
        return "security type 0 still sent a VNC-auth challenge"
    return None


def match_tls_stock_cert(text: str) -> str | None:
    """TLS certificate CN/SAN is a stock lab/dev name, not a production hostname."""
    low = (text or "").lower()
    for tell in (
        "synologynas.local",
        "localhost",
        "cowrie",
        "dionaea",
        "honeypot",
        "example.local",
    ):
        if tell in low:
            return f"stock TLS certificate name {tell}"
    return None


def match_ftp_stale_banner(welcome: str) -> str | None:
    """Stock/default 220 (e.g. ProFTPD 1.2.10) or an EOL daemon version on the greeting."""
    blob = welcome or ""
    low = blob.lower()
    for tell in FTP_STOCK_220:
        if tell.lower() in low:
            return f"stock default 220 {tell}"
    m = _FTP_STALE_BANNER_RE.search(blob)
    return f"stale FTP banner {m.group(1)}" if m else None


_MYSQL_EOL_RE = re.compile(r"5\.5\.\d+-0ubuntu0\.14\.04", re.IGNORECASE)
# Frozen capability block in common low-interaction MySQL lures (OpenCanary-class).
_MYSQL_STOCK_CAP_BLOCK = b"\xff\xf7\x08\x02\x00\x0f\x80"
_MYSQL_PKT_ORDER_CODE = 1156

# nmap ms-sql-s prelogin payload (TDS type 0x12). Canned lure replies match this blob.
MSSQL_NMAP_PRELOGIN_PAYLOAD = (
    b"\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c"
    b"\x03\x00(\x00\x04\xff\x08\x00\x01U\x00\x00\x00MSSQLServer\x00H\x0f\x00\x00"
)
MSSQL_CANNED_PRELOGIN = (
    b"\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01"
    b"\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0a\x32\x10\xb4",
    b"\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01"
    b"\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0b\x00\x0c\x38",
    b"\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01"
    b"\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0c\x00\x07\xd0",
)
RDP_CANNED_NLA = bytes.fromhex("030000130ed000001234000209080002000000")
RDP_CANNED_FAIL = bytes.fromhex("0001000400010000052e")
VNC_CANNED_AUTH_FAIL = b"\x00\x00\x00\x01\x00\x00\x00\x16Authentication failure"


def match_mysql_eol_banner(version: str) -> str | None:
    """Frozen MySQL 5.5-on-Ubuntu-14.04 greeting (EOL template, not a live distro)."""
    blob = (version or "").strip()
    if not blob:
        return None
    if _MYSQL_EOL_RE.search(blob):
        return f"EOL MySQL greeting {blob}"
    return None


def match_mysql_stock_handshake(raw: bytes) -> str | None:
    """Server greeting uses a frozen capability block and mysql_native_password only."""
    data = raw or b""
    if _MYSQL_STOCK_CAP_BLOCK not in data:
        return None
    if b"mysql_native_password" not in data:
        return None
    return "stock handshake capability block + mysql_native_password"


def match_mysql_pkt_order(raw: bytes) -> str | None:
    """Wrong auth sequence id returns ER 1156 packets out of order (emulator FSM)."""
    payload = raw[4:] if len(raw) > 4 else raw
    if not payload.startswith(b"\xff"):
        return None
    if len(payload) >= 3 and struct.unpack("<H", payload[1:3])[0] == _MYSQL_PKT_ORDER_CODE:
        return "ER 1156 packets out of order on wrong auth sequence"
    if b"packets out of order" in raw:
        return "packets out of order on wrong auth sequence"
    return None


def match_smb_static_ntlm_challenge(challenges: list[bytes]) -> str | None:
    """Two sessions received the same 8-byte NTLM server challenge."""
    if len(challenges) < 2:
        return None
    if challenges[0] == challenges[1]:
        return f"identical NTLM server challenge across {len(challenges)} sessions"
    return None


def match_smb_bogus_pipe(code: int | None, detail: str, *, accepted: bool) -> str | None:
    """Random IPC$ pipe should return OBJECT_NAME_NOT_FOUND, not accept or reset."""
    if accepted:
        return f"bogus named pipe accepted ({detail})"
    if code == STATUS_OBJECT_NAME_NOT_FOUND:
        return None
    if code is not None:
        return f"bogus pipe NTSTATUS 0x{code:08X} (expected 0x{STATUS_OBJECT_NAME_NOT_FOUND:08X})"
    low = (detail or "").lower()
    if any(tok in low for tok in ("reset", "broken pipe", "connection refused", "timed out")):
        return f"bogus pipe probe failed messily: {detail[:120]}"
    return None


def match_smb_negotiate_deficit(facts: dict) -> str | None:
    """Negotiate stuck on legacy dialect or SMB 3.1.1 without encryption capability."""
    dialect = facts.get("dialect")
    if dialect is None:
        return None
    if isinstance(dialect, str):
        blob = dialect.strip()
        if blob in SMB_SMB1_DIALECTS or blob.upper().startswith("SMB 1") or blob == "1":
            return f"negotiated legacy dialect {blob}"
    if isinstance(dialect, int) and dialect < SMB2_DIALECT_30:
        return f"negotiated legacy dialect 0x{dialect:04x}"
    if dialect == SMB2_DIALECT_311 and not facts.get("supports_encryption"):
        return "SMB 3.1.1 without encryption capability"
    return None


def match_smb_target_info_mismatch(native_os: str, meta: dict) -> str | None:
    """Windows native_os but NTLM AV pairs advertise Unix/Samba-style names."""
    av = meta.get("av_pairs")
    if not av:
        return None
    try:
        from impacket import ntlm
    except ImportError:
        return None

    def _av_name(pair_id: int) -> str:
        item = av.get(pair_id)
        if not item:
            return ""
        raw = item[1]
        if isinstance(raw, bytes):
            return raw.decode("utf-16le", "replace")
        return str(raw)

    os_low = (native_os or "").lower()
    if "windows" not in os_low:
        return None
    for label in (_av_name(ntlm.NTLMSSP_AV_HOSTNAME), _av_name(ntlm.NTLMSSP_AV_DNS_HOSTNAME)):
        if not label:
            continue
        low = label.lower()
        if any(tok in low for tok in ("samba", "linux", "unix", "ubuntu", "debian", "emerald")):
            return f"native_os {native_os!r} vs NTLM name {label!r}"
    return None


def match_git_always_missing(text: str) -> str | None:
    """git-upload-pack always ERR no such repository — no ref advertisement."""
    blob = text or ""
    low = blob.lower()
    if "err no such repository" in low and "refs/" not in low and "capability" not in low:
        return "git-upload-pack always ERR no such repository"
    return None


def match_rdp_canned_nla(raw: bytes) -> str | None:
    """First RDP reply is a canned NLA TPKT with cookie 0x1234."""
    data = raw or b""
    if data.startswith(RDP_CANNED_NLA) or RDP_CANNED_NLA in data[:32]:
        return "canned NLA cookie 0x1234"
    return None


def match_vnc_auth_fail(raw: bytes) -> str | None:
    """RFB SecurityResult is a canned Authentication failure (length 0x16), never a desktop."""
    data = raw or b""
    if VNC_CANNED_AUTH_FAIL in data or data.startswith(VNC_CANNED_AUTH_FAIL):
        return "canned RFB Authentication failure"
    return None


def match_vnc_vncauth_only(raw: bytes) -> str | None:
    """Security handshake offers only VNC authentication (type 2)."""
    data = raw or b""
    if data[:2] == b"\x01\x02" or data.startswith(b"\x01\x02"):
        return "RFB offers only VNC-auth"
    return None


def match_rdp_neg_fail(raw: bytes) -> str | None:
    """Second RDP write is a canned negotiation-failure blob, then close."""
    data = raw or b""
    if data.startswith(RDP_CANNED_FAIL) or RDP_CANNED_FAIL in data[:24]:
        return "canned RDP negotiation failure"
    return None


def match_http_proxy_lure(text: str) -> str | None:
    """407 with Via localhost, frozen squid 3.3.8, X-Squid-Error, or ISA deny phrase."""
    blob = text or ""
    if not blob.strip():
        return None
    low = blob.lower()
    hits: list[str] = []
    if "via:" in low and "localhost" in low:
        hits.append("Via: localhost")
    if "squid/3.3.8" in low:
        hits.append("frozen squid/3.3.8")
    if "x-squid-error" in low:
        hits.append("X-Squid-Error")
    if "web proxy service is denied" in low:
        hits.append("ISA proxy deny phrase")
    return "; ".join(hits) if hits else None


def match_mssql_canned_prelogin(raw: bytes) -> str | None:
    """TDS prelogin reply is one of the frozen nmap-shaped templates."""
    data = raw or b""
    if not data:
        return None
    for canned in MSSQL_CANNED_PRELOGIN:
        if data.startswith(canned) or data == canned:
            return "canned TDS prelogin (nmap-probe-shaped)"
    if (
        b"\xff\x0b\x00\x0c\x38" in data
        or b"\xff\x0c\x00\x07\xd0" in data
        or b"\xff\x0a\x32\x10\xb4" in data
    ):
        return "canned TDS prelogin (nmap-probe-shaped)"
    return None


def match_mssql_prelogin_encrypt(raw: bytes) -> str | None:
    """Client PRELOGIN gets encryption NOT SUP (0x02) and a frozen version blob."""
    data = raw or b""
    if len(data) > 8 and data[0] == 0x04:
        i = 8
        while i + 5 <= len(data):
            if data[i] == 0xFF:
                break
            token = data[i]
            offset = struct.unpack(">H", data[i + 1 : i + 3])[0]
            length = struct.unpack(">H", data[i + 3 : i + 5])[0]
            i += 5
            if token == 0x01 and length >= 1:
                pos = 8 + offset
                if pos < len(data) and data[pos] == 0x02:
                    return "PRELOGIN encryption NOT SUP (0x02)"
    payload = data[8:] if len(data) > 8 and data[0] == 0x04 else data
    if b"\x0c\x00\x10\x04\x00\x00" in payload and b"\xff" in payload:
        if b"\x02" in payload[payload.find(b"\xff") : payload.find(b"\xff") + 32]:
            return "PRELOGIN encryption NOT SUP with frozen version token"
    return None


def match_postgres_cleartext_only(ssl_reply: bytes, auth_reply: bytes) -> str | None:
    """SSLRequest rejected with N, then only AuthenticationCleartextPassword."""
    if (ssl_reply or b"")[:1] != b"N":
        return None
    data = auth_reply or b""
    # R + len(8) + auth type 3 (cleartext)
    if data.startswith(b"R") and len(data) >= 9 and data[5:9] == b"\x00\x00\x00\x03":
        return "SSLRequest → N then AuthenticationCleartextPassword only"
    return None


def match_postgres_auth_c_blob(raw: bytes) -> str | None:
    """FATAL 28P01 fail blob freezes auth.c line/routine (low-interaction template)."""
    data = raw or b""
    if b"auth.c" in data and b"326" in data and b"auth_failed" in data:
        return "FATAL 28P01 with frozen auth.c:326 / auth_failed"
    if b"Fauth.c" in data and b"L326" in data and b"Rauth_failed" in data:
        return "FATAL 28P01 with frozen auth.c:326 / auth_failed"
    return None


def match_mssql_login7_canned(raw: bytes) -> str | None:
    """LOGIN7 gets a canned 18456 failure with a fixed trailing token trailer."""
    data = raw or b""
    if len(data) >= 6 and data[0] == 0x04 and struct.unpack(">H", data[4:6])[0] == 54:
        if b"Login failed" in data or "Login failed".encode("utf-16le") in data:
            return "canned LOGIN7 failure (fixed SPID 54)"
    if b"\xfd\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" in data:
        if b"Login failed" in data or "Login failed".encode("utf-16le") in data:
            return "canned LOGIN7 failure with fixed trailer"
    return None


def match_mongo_stock_hello(raw: bytes) -> str | None:
    """hello/isMaster looks like mongod but connectionId is hardcoded to 1."""
    data = raw or b""
    looks_like_hello = b"ismaster" in data or b"maxWireVersion" in data or b"maxBsonObjectSize" in data
    if looks_like_hello and b"\x10connectionId\x00\x01\x00\x00\x00" in data:
        return "hello connectionId frozen at 1"
    if b"4.4.6" in data:
        return "frozen hello version 4.4.6"
    return None


def match_mongo_ping_unauthorized(text: str) -> str | None:
    """Ping/other commands return unauthorized while hello still works."""
    low = (text or "").lower()
    if "authentication required" in low or "not authorized" in low:
        return "non-hello command unauthorized after hello"
    return None


def match_mongo_op_msg_reply(raw: bytes) -> str | None:
    """OP_MSG hello reply uses opcode 2013 or a synthetic outbound requestId."""
    data = raw or b""
    if len(data) < 16:
        return None
    _length, request_id, _response_to, opcode = struct.unpack("<IIII", data[:16])
    hits: list[str] = []
    if opcode == 2013:
        hits.append("OP_MSG opcode 2013 reply")
    if request_id == 9999:
        hits.append("synthetic reply requestId 9999")
    return "; ".join(hits) if hits else None


def match_redis_eval_stub(reply: str) -> str | None:
    """EVAL accepted but did not execute Lua (stub +OK or unknown command)."""
    text = (reply or "").lstrip()
    if not text:
        return None
    if text.startswith("+OK"):
        return "EVAL returned +OK without Lua execution"
    if "unknown command" in text.lower():
        return "EVAL unimplemented"
    return None


def match_redis_config_stub(reply: str) -> str | None:
    """CONFIG GET should return a bulk/array catalog, not +OK or NOAUTH wall."""
    text = (reply or "").lstrip()
    if not text:
        return None
    if text.startswith("+OK"):
        return "CONFIG GET returned +OK instead of parameters"
    if text.startswith("-ERR wrong number of arguments"):
        return "CONFIG GET wrong-arity stub"
    if "noauth" in text.lower():
        return None
    if text.startswith("-ERR unknown command"):
        return "CONFIG GET unimplemented"
    return None



def match_ftp_auth_lure(user_resp: str = "", pass_resp: str = "") -> str | None:
    blob = f"{user_resp}\n{pass_resp}"
    low = blob.lower()
    if ("guest login ok" in low or "anonymous login ok" in low) and (
        "530" in low or "authentication failed" in low
    ):
        return "331 guest/anonymous login ok then 530 reject"
    for tell in FTP_CANNED_REJECTS:
        if tell.lower() in low:
            return tell
    return None


def match_smtp_placeholder_identity(text: str) -> str | None:
    """Greeting/EHLO hostname is loopback, RFC1918-in-name, or a canned 'no relay' lure."""
    blob = (text or "").lower()
    if not blob.strip():
        return None
    if "127.0.0.1" in blob or "localhost" in blob:
        return "SMTP identity is loopback/localhost"
    if re.search(r"\bip-127-\d+-\d+-\d+\b", blob):
        return "SMTP identity encodes loopback"
    if re.search(r"\bip-(?:10|172-(?:1[6-9]|2\d|3[01])|192-168)-\d+", blob):
        return "SMTP identity encodes a private IP"
    if "no uce" in blob or "no ube" in blob or "no relay probes" in blob:
        return "SMTP 220 advertises canned NO UCE/RELAY PROBES"
    return None


_NMAP_PRODUCT_FAMILIES = (
    "proftpd",
    "vsftpd",
    "wu-ftp",
    "filezilla",
    "postfix",
    "exim",
    "sendmail",
    "openssh",
    "dropbear",
    "nginx",
    "apache",
    "cowrie",
    "kippo",
)


def _nmap_product_families(text: str) -> set[str]:
    low = (text or "").lower()
    return {fam for fam in _NMAP_PRODUCT_FAMILIES if fam in low}


def match_nmap_service_tell(data: dict) -> str | None:
    """Class-level -sV tells: unknown fingerprint on any protocol, family mismatch, lure banners."""
    name = str(data.get("name") or "").strip()
    if name.lower() == "tcpwrapped":
        return None
    product = str(data.get("product") or "").strip()
    version = str(data.get("version") or "").strip()
    extra = str(data.get("extrainfo") or "").strip()
    fp = str(data.get("servicefp") or "").strip()
    blob_parts = [name, product, version, extra, fp]
    for key, val in data.items():
        if key in {"script", "name", "product", "version", "extrainfo", "servicefp"}:
            continue
        if isinstance(val, str) and val.strip():
            blob_parts.append(val)
    blob = " ".join(blob_parts)
    low = blob.lower()
    for tell in NMAP_HONEYPOT_TELLS:
        if tell in low:
            snippet = (product or version or tell)[:120]
            return f"{name or 'service'}: {tell} ({snippet})"
    telnet_hit = match_telnet_banner(blob) or match_telnet_canned_reject(blob)
    if telnet_hit:
        return f"telnet lure in -sV ({telnet_hit})"
    smtp_hit = match_smtp_placeholder_identity(blob)
    if smtp_hit:
        return smtp_hit
    banner_blob = " ".join(
        str(data.get(k) or "") for k in ("script_blob", "extrainfo", "servicefp")
    )
    prod_fams = _nmap_product_families(f"{product} {version}")
    banner_fams = _nmap_product_families(banner_blob)
    if prod_fams and banner_fams and prod_fams.isdisjoint(banner_fams):
        return (
            f"{name or 'service'} -sV/banner family mismatch "
            f"({', '.join(sorted(prod_fams))} vs {', '.join(sorted(banner_fams))})"
        )
    is_nse = name.lower() in _NMAP_NSE_SCRIPT_NAMES
    if not is_nse:
        if fp.startswith("SF-") or "SF-Port" in fp:
            if not product:
                return f"{name or 'port'} unrecognized -sV fingerprint (data, no product match)"
        if not product and not version and name.lower() not in {"", "tcpwrapped"}:
            return f"{name} open but -sV has no product/version (unrecognized service)"
    if "ftp" in low and " or " in low:
        return f"ambiguous FTP -sV ({(product or version)[:120]})"
    return None


def match_redis_auth_any(reply: str) -> str | None:
    """AUTH with random credentials returned +OK (real Redis rejects or WRONGPASS)."""
    if (reply or "").lstrip().startswith("+OK"):
        return "AUTH accepted random credentials"
    return None


def match_redis_auth_wall(auth_reply: str, command_reply: str) -> str | None:
    """AUTH is always invalid-password and COMMAND is NOAUTH (never a catalog)."""
    auth = (auth_reply or "").lower()
    cmd = (command_reply or "").lower()
    if "invalid password" in auth and "noauth" in cmd:
        return "AUTH always invalid password and COMMAND is NOAUTH"
    return None


def match_redis_command_stub(reply: str) -> str | None:
    """COMMAND is a catalog array on real Redis; stubs return +OK or unknown."""
    text = (reply or "").lstrip()
    if not text:
        return None
    if text.startswith("+OK"):
        return "COMMAND returned +OK instead of a command catalog"
    if "unknown command" in text.lower():
        return "COMMAND unimplemented"
    return None


def match_redis_help_client(reply: str) -> str | None:
    """HELP on the wire returns redis-cli client text instead of server command help."""
    low = (reply or "").lower()
    if "redis-cli" in low or "redisclirc" in low:
        return "HELP returns redis-cli client text"
    return None


def match_redis_unknown_core(cmd: str, reply: str) -> str | None:
    """A core command (ECHO, SELECT, …) is unimplemented."""
    if "unknown command" in (reply or "").lower():
        return f"{cmd} unimplemented (core command missing)"
    return None


def _redis_info_field(blob: str, key: str) -> str | None:
    prefix = f"{key}:"
    for line in (blob or "").replace("\r\n", "\n").splitlines():
        if line.startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


def match_redis_info_template(info1: str, info2: str = "") -> str | None:
    """INFO is a frozen dump: stale clock, or stats that do not move between calls."""
    usec = _redis_info_field(info1, "server_time_usec")
    if usec:
        try:
            stamp = int(usec)
            seconds = stamp / 1_000_000 if stamp > 10_000_000_000 else float(stamp)
            if abs(time.time() - seconds) > 7 * 86400:
                return "INFO server_time is a frozen snapshot"
        except ValueError:
            pass
    if info2:
        t1 = _redis_info_field(info1, "server_time_usec")
        t2 = _redis_info_field(info2, "server_time_usec")
        if t1 and t2 and t1 == t2:
            return "INFO server_time_usec identical across calls (static dump)"
        c1 = _redis_info_field(info1, "total_commands_processed")
        c2 = _redis_info_field(info2, "total_commands_processed")
        if c1 and c2 and c1 == c2:
            return "INFO stats do not change after commands (static dump)"
    return None


def match_redis_flush_stub(get_after_flush: str, expected: str) -> str | None:
    """FLUSHALL returned OK but the probe key is still there."""
    text = get_after_flush or ""
    if not expected or text.lstrip().startswith("$-1"):
        return None
    if expected in text:
        return "FLUSHALL returned OK but key still present"
    return None


def match_smtp_lost_envelope(mail_code: int, rcpt_code: int, rcpt_msg: str = "") -> str | None:
    """MAIL FROM 2xx then RCPT 503 need-sender: the envelope was not actually stored."""
    try:
        mail_n, rcpt_n = int(mail_code), int(rcpt_code)
    except (TypeError, ValueError):
        return None
    if not (200 <= mail_n < 300 and rcpt_n == 503):
        return None
    blob = (rcpt_msg or "").lower()
    if any(t in blob for t in ("sender", "mail from", "need mail", "mail first")):
        return "MAIL FROM accepted then RCPT 503 (envelope not stored)"
    return None


def _require_tcp_port(port: int, *, label: str = "port") -> int:
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid {label} {port}")
    return port


def parse_port_overrides(spec: str) -> dict[str, int]:
    out: dict[str, int] = {}
    if not spec:
        return out
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"invalid --ports item {part!r}; expected proto=port")
        name, raw = part.split("=", 1)
        name = name.strip().lower()
        port = _require_tcp_port(int(raw.strip()), label=f"port for {name}")
        out[name] = port
    return out


def parse_port_numbers(spec: str) -> list[int]:
    """Parse ``22`` or ``22,2222`` into TCP port numbers."""
    out: list[int] = []
    if not spec:
        return out
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part, 10)
        except ValueError as exc:
            raise ValueError(f"invalid --port value {part!r}") from exc
        out.append(_require_tcp_port(port))
    if not out:
        raise ValueError("empty --port value")
    return out


def protocol_for_port(port: int) -> str:
    """Map a TCP port to a probe protocol. Unknown numbers are treated as SSH."""
    return WELL_KNOWN_PORT_PROTOCOLS.get(int(port), "ssh")


def as_port_list(value: int | list[int] | tuple[int, ...] | None, default: int | list[int] | None = None) -> list[int]:
    if value is None:
        value = default
    if value is None:
        return []
    if isinstance(value, int):
        return [value]
    return [int(p) for p in value]


def all_tcp_ports(ports: Mapping[str, int | list[int]]) -> list[int]:
    seen: list[int] = []
    for value in ports.values():
        for port in as_port_list(value):
            if port not in seen:
                seen.append(port)
    return seen


def protocol_by_port(ports: Mapping[str, int | list[int]]) -> dict[int, str]:
    mapping: dict[int, str] = {}
    for name, value in ports.items():
        for port in as_port_list(value):
            mapping[int(port)] = name
    return mapping


def _unique_ports(*ports: int) -> list[int]:
    seen: list[int] = []
    for port in ports:
        if port not in seen:
            seen.append(port)
    return seen


def probe_port_map(
    preset: str = DEFAULT_PORT_PRESET,
    overrides: Mapping[str, int] | None = None,
    extra_ports: list[int] | None = None,
) -> dict[str, list[int]]:
    """
    Ports to probe per protocol.

    ``both`` (default) unions IANA well-known ports with docker/lab aliases
    (SSH 22 and 2222, HTTP 80 and 8081, …). ``--ports proto=N`` replaces that
    protocol's list. ``-p/--port`` is nmap-style: **only** those numbers are
    scanned (preset is ignored). Well-known numbers map to a protocol;
    unknown ports are probed as SSH.
    """
    if extra_ports:
        ports: dict[str, list[int]] = {}
        for port in extra_ports:
            port = _require_tcp_port(int(port))
            proto = protocol_for_port(port)
            current = ports.setdefault(proto, [])
            if port not in current:
                current.append(port)
    elif preset == "both":
        ports = {
            proto: _unique_ports(PORT_PRESET_IANA[proto], PORT_PRESET_DOCKER_RESEARCH[proto])
            for proto in PORT_PRESET_IANA
        }
    elif preset in PORT_PRESETS:
        ports = {proto: [port] for proto, port in PORT_PRESETS[preset].items()}
    else:
        raise ValueError(f"unknown preset {preset!r}; choose from {PORT_PRESET_CHOICES}")
    if not extra_ports and preset in ("both", "iana"):
        http_ports = ports.get("http")
        if http_ports is not None and 443 not in http_ports:
            http_ports.append(443)
    if overrides:
        for name, port in overrides.items():
            ports[name] = [_require_tcp_port(int(port), label=f"port for {name}")]
    return ports


def merge_ports(preset: str, overrides: Mapping[str, int] | None = None) -> dict[str, int]:
    if preset == "both":
        raise ValueError("merge_ports() is single-port only; use probe_port_map('both')")
    if preset not in PORT_PRESETS:
        raise ValueError(f"unknown preset {preset!r}; choose from {sorted(PORT_PRESETS)}")
    ports = dict(PORT_PRESETS[preset])
    if overrides:
        ports.update(overrides)
    return ports


def resolve_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise ValueError("target is empty")
    if "/" in target:
        raise ValueError(
            "target looks like a CIDR subnet; use expand_scan_targets() or pass a single IP/hostname"
        )
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)


# Largest allowed IPv4 scan: /24 (256 addresses). Smaller prefixes are rejected.
MAX_SUBNET_PREFIX_IPV4 = 24
MAX_SUBNET_HOSTS = 256
DEFAULT_SCAN_CONCURRENCY = 8


def expand_scan_targets(target: str) -> tuple[str, list[str]]:
    """
    Expand --target to one or more probe addresses.

    Returns (scan_kind, addresses) where scan_kind is ``host`` or ``subnet``.
  Single IPs and hostnames resolve to one address. IPv4 CIDR up to /24 expands
    to host addresses (network/broadcast omitted when applicable).
    """
    target = (target or "").strip()
    if not target:
        raise ValueError("target is empty")

    if "/" not in target:
        return "host", [resolve_target(target)]

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR target {target!r}: {exc}") from exc

    if network.version != 4:
        raise ValueError("subnet scans support IPv4 CIDR only")

    if network.prefixlen < MAX_SUBNET_PREFIX_IPV4:
        raise ValueError(
            f"subnet {target} is too large; maximum allowed prefix is /{MAX_SUBNET_PREFIX_IPV4}"
        )

    if network.num_addresses > MAX_SUBNET_HOSTS:
        raise ValueError(
            f"subnet {target} has {network.num_addresses} addresses; "
            f"maximum is {MAX_SUBNET_HOSTS} (/{MAX_SUBNET_PREFIX_IPV4})"
        )

    hosts = [str(addr) for addr in network.hosts()]
    if not hosts and network.num_addresses <= 2:
        hosts = [str(addr) for addr in network]
    if not hosts:
        raise ValueError(f"subnet {target} has no scannable host addresses")

    return "subnet", hosts


def is_private_or_loopback(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
