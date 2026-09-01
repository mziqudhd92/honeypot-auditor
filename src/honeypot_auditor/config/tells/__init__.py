"""Tell corpora grouped by protocol."""

from honeypot_auditor.config.tells.ftp import (
    FTP_CANNED_REJECTS,
    FTP_LURE_ACCOUNTS,
    FTP_STOCK_220,
    FTP_SYST_TELLS,
    FTP_WELCOME_TELLS,
)
from honeypot_auditor.config.tells.http import (
    HTTP_DYNAMIC_HEADERS,
    HTTP_HEADER_LURE_ORDERS,
    HTTP_SERVER_TELLS,
    HTTP_STATIC_BODY_MARKERS,
    WILDCARD_HOST,
)
from honeypot_auditor.config.tells.mssql import MSSQL_CANNED_PRELOGIN, MSSQL_NMAP_PRELOGIN_PAYLOAD
from honeypot_auditor.config.tells.mysql import (
    MYSQL_PKT_ORDER_CODE,
    MYSQL_STOCK_CAP_BLOCK,
)
from honeypot_auditor.config.tells.nmap import (
    NMAP_HONEYPOT_TELLS,
    NMAP_PORT_PRIORITY,
    NMAP_SCRIPTS,
)
from honeypot_auditor.config.tells.rdp_vnc import (
    RDP_CANNED_FAIL,
    RDP_CANNED_NLA,
    VNC_CANNED_AUTH_FAIL,
)
from honeypot_auditor.config.tells.sip import SIP_UA_TELLS
from honeypot_auditor.config.tells.smb import (
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
    SMB_NATIVE_OS_TELLS,
    SMB_SMB1_DIALECTS,
    STATUS_OBJECT_NAME_NOT_FOUND,
)
from honeypot_auditor.config.tells.ssh import (
    COWRIE_HOSTNAMES,
    COWRIE_MOTD_TELLS,
    CPUINFO_TELLS,
    SSH_BANNER_SIGNATURES,
    UNAME_SIGNATURES,
)
from honeypot_auditor.config.tells.telnet import TELNET_BANNER_TELLS, TELNET_CANNED_REJECTS

__all__ = [
    "COWRIE_HOSTNAMES",
    "COWRIE_MOTD_TELLS",
    "CPUINFO_TELLS",
    "FTP_CANNED_REJECTS",
    "FTP_LURE_ACCOUNTS",
    "FTP_STOCK_220",
    "FTP_SYST_TELLS",
    "FTP_WELCOME_TELLS",
    "HTTP_DYNAMIC_HEADERS",
    "HTTP_HEADER_LURE_ORDERS",
    "HTTP_SERVER_TELLS",
    "HTTP_STATIC_BODY_MARKERS",
    "MSSQL_CANNED_PRELOGIN",
    "MSSQL_NMAP_PRELOGIN_PAYLOAD",
    "MYSQL_PKT_ORDER_CODE",
    "MYSQL_STOCK_CAP_BLOCK",
    "NMAP_HONEYPOT_TELLS",
    "NMAP_PORT_PRIORITY",
    "NMAP_SCRIPTS",
    "RDP_CANNED_FAIL",
    "RDP_CANNED_NLA",
    "SIP_UA_TELLS",
    "SMB2_DIALECT_30",
    "SMB2_DIALECT_311",
    "SMB_NATIVE_OS_TELLS",
    "SMB_SMB1_DIALECTS",
    "SSH_BANNER_SIGNATURES",
    "STATUS_OBJECT_NAME_NOT_FOUND",
    "TELNET_BANNER_TELLS",
    "TELNET_CANNED_REJECTS",
    "UNAME_SIGNATURES",
    "VNC_CANNED_AUTH_FAIL",
    "WILDCARD_HOST",
]
