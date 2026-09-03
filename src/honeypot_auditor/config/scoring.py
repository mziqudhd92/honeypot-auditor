"""Honeyscore weights, threat levels, and per-protocol strategy metadata."""

from __future__ import annotations

WEIGHTS: dict[str, float] = {
    "shodan": 0.25,
    "arbitrary_auth": 0.30,
    "state_nonpersist": 0.25,
    "static_signature": 0.20,
    "cotenancy": 0.15,
}

CORROBORATION_PROTOCOL_THRESHOLD = 1
CORROBORATION_PROTOCOL_STEP_PCT = 5.0
CORROBORATION_PROTOCOL_MAX_BONUS = 35.0

# Extra hits in the same category add diminishing corroboration (cap +15%).
INTRA_CATEGORY_STEP_PCT = 7.5
INTRA_CATEGORY_MAX_BONUS_PCT = 15.0

# Indicator.fidelity "high" / "decisive" awards this bonus once per audit.
HIGH_SIGNAL_BONUS_PCT = 15.0
HIGH_SIGNAL_FIDELITIES = frozenset({"high", "decisive"})

# Valid Indicator.fidelity values (default medium).
FIDELITY_LEVELS = frozenset({"low", "medium", "high", "decisive"})

BASIC_STRATEGIES: tuple[str, ...] = ("arbitrary_auth", "state_nonpersist", "static_signature")

STRATEGY_LABELS: dict[str, str] = {
    "shodan": "Passive intel (Shodan / plugins)",
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

PROTOCOL_STRATEGIES: dict[str, dict[str, str]] = {
    "ssh": {
        "arbitrary_auth": "any-password (2 random users)",
        "state_nonpersist": "exec vs fake PTY · /tmp canary",
        "static_signature": "banner · KEX facade · lure whoami · honeyfs",
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
    "pop3": {
        "arbitrary_auth": "two random USER/PASS pairs",
        "state_nonpersist": "STAT/NOOP before authentication",
        "static_signature": (
            "+OK greeting framing · unknown-command rejection · "
            "auth-failed -ERR blanket (STAT/CAPA/HPAU) · stock lure banner"
        ),
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

DEEP_WEIGHTS: dict[str, float] = {
    "behavior": 0.18,
    "coherence": 0.15,
    "stack_fingerprint": 0.12,
    "proto_conformance": 0.12,
    "temporal": 0.10,
}

EXTENDED_PROBE_PORTS: dict[str, int] = {
    "modbus": 1502,
    "snmp": 161,
    "dns": 15353,
    "ipp": 631,
}

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
    # Fired tells below Suspected must never read as "Likely Real Host".
    "anomalies": "Inconclusive (Low-confidence anomalies detected)",
}
