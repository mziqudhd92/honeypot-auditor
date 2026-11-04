"""Port→family map for entropy-based sudden_buffet (Shodan/Censys history)."""

from __future__ import annotations

# Cheap port→family map for entropy scoring (not full product attribution).
PORT_FAMILY: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "mail",
    53: "dns",
    80: "web",
    110: "mail",
    143: "mail",
    161: "snmp",
    443: "web",
    445: "smb",
    502: "modbus",
    993: "mail",
    995: "mail",
    1433: "mssql",
    1883: "mqtt",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "web",
    8443: "web",
    9200: "elasticsearch",
    27017: "mongo",
}

# EIP-recycle faces commonly appear together on cloud churn — low deception alone.
EIP_FAMILIES = frozenset({"web", "mail", "ssh"})

# Legacy / DB / ICS families that raise sudden_buffet entropy.
LEGACY_DB_ICS_FAMILIES = frozenset(
    {
        "telnet",
        "smb",
        "ftp",
        "mysql",
        "mssql",
        "postgres",
        "redis",
        "mongo",
        "modbus",
        "snmp",
        "mqtt",
        "rdp",
        "vnc",
        "elasticsearch",
        "dns",
    }
)
