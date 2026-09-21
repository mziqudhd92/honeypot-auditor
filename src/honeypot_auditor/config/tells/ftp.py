from __future__ import annotations

import re

FTP_WELCOME_TELLS = (
    "DiskStation FTP server",
    "dionaea",
    "honeypot ftp",
)

FTP_STOCK_220 = (
    "ProFTPD 1.2.10",
    "FTP Ready.",
    "FTP server ready",
    "Microsoft FTP Service",
)

FTP_STALE_BANNER_RE = re.compile(
    r"(ProFTPD\s+1\.2\.\S+|ProFTPD\s+1\.3\.[0-4]\S*|vsftpd\s+[12]\.[0-3]\.\S+|FileZilla[^\r\n]*0\.9\.\S+)",
    re.IGNORECASE,
)

FTP_CANNED_REJECTS = (
    "Sorry, Authentication failed",
    "User cannot log in",
)

FTP_LURE_ACCOUNTS = (
    ("test", ""),
    ("test", "test"),
    ("user", "test"),
    ("ftp", "ftp"),
    ("admin", "admin"),
    ("user", "user"),
)

FTP_SYST_TELLS = (
    # Exact stock strings from low-interaction faces — bare "215 UNIX Type: L8"
    # is the normal RFC 959 SYST reply on real vsftpd/proftpd and must not score.
    "215 UNIX Type: L8 version: Pure-FTPd",
    "215 UNIX emulation by Microsoft",
)
