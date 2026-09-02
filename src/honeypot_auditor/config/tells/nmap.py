NMAP_SCRIPTS = "banner,ssh2-enum-algos,ssh-auth-methods,ssh-publickey-acceptance"
NMAP_NSE_SCRIPT_NAMES = frozenset(s.strip().lower() for s in NMAP_SCRIPTS.split(",") if s.strip())

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

NMAP_PRODUCT_FAMILIES = (
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
