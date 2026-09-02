"""Protocol signature matchers."""

from honeypot_auditor.config.signatures.common import claimed_os_from_banner
from honeypot_auditor.config.signatures.ftp import (
    match_ftp_auth_lure,
    match_ftp_command_desert,
    match_ftp_port_bounce,
    match_ftp_stale_banner,
)
from honeypot_auditor.config.signatures.git import match_git_always_missing
from honeypot_auditor.config.signatures.http import match_http_proxy_lure, match_tls_stock_cert
from honeypot_auditor.config.signatures.mongo import (
    match_mongo_op_msg_reply,
    match_mongo_ping_unauthorized,
    match_mongo_stock_hello,
)
from honeypot_auditor.config.signatures.mssql import (
    match_mssql_canned_prelogin,
    match_mssql_login7_canned,
    match_mssql_prelogin_encrypt,
)
from honeypot_auditor.config.signatures.mysql import (
    match_mysql_eol_banner,
    match_mysql_pkt_order,
    match_mysql_stock_handshake,
)
from honeypot_auditor.config.signatures.nmap import match_nmap_service_tell
from honeypot_auditor.config.signatures.postgres import (
    match_postgres_auth_c_blob,
    match_postgres_cleartext_only,
)
from honeypot_auditor.config.signatures.rdp_vnc import (
    match_rdp_canned_nla,
    match_rdp_neg_fail,
    match_vnc_auth_fail,
    match_vnc_invalid_security_challenge,
    match_vnc_vncauth_only,
)
from honeypot_auditor.config.signatures.redis import (
    match_redis_auth_any,
    match_redis_auth_wall,
    match_redis_command_stub,
    match_redis_config_stub,
    match_redis_eval_stub,
    match_redis_flush_stub,
    match_redis_help_client,
    match_redis_info_template,
    match_redis_unknown_core,
)
from honeypot_auditor.config.signatures.smb import (
    match_smb_bogus_pipe,
    match_smb_negotiate_deficit,
    match_smb_static_ntlm_challenge,
    match_smb_target_info_mismatch,
)
from honeypot_auditor.config.signatures.smtp import (
    match_smtp_extension_monotone,
    match_smtp_lost_envelope,
    match_smtp_placeholder_identity,
)
from honeypot_auditor.config.signatures.ssh import (
    match_cowrie_identity,
    match_cpuinfo_signature,
    match_ssh_banner,
    match_uname_signature,
    normalize_uname,
)
from honeypot_auditor.config.signatures.telnet import (
    match_telnet_banner,
    match_telnet_blind_option,
    match_telnet_canned_reject,
    match_telnet_cowrie_preamble,
    match_telnet_option_spray,
)

__all__ = [
    "claimed_os_from_banner",
    "match_cowrie_identity",
    "match_cpuinfo_signature",
    "match_ftp_auth_lure",
    "match_ftp_command_desert",
    "match_ftp_port_bounce",
    "match_ftp_stale_banner",
    "match_git_always_missing",
    "match_http_proxy_lure",
    "match_mongo_op_msg_reply",
    "match_mongo_ping_unauthorized",
    "match_mongo_stock_hello",
    "match_mssql_canned_prelogin",
    "match_mssql_login7_canned",
    "match_mssql_prelogin_encrypt",
    "match_mysql_eol_banner",
    "match_mysql_pkt_order",
    "match_mysql_stock_handshake",
    "match_nmap_service_tell",
    "match_postgres_auth_c_blob",
    "match_postgres_cleartext_only",
    "match_rdp_canned_nla",
    "match_rdp_neg_fail",
    "match_redis_auth_any",
    "match_redis_auth_wall",
    "match_redis_command_stub",
    "match_redis_config_stub",
    "match_redis_eval_stub",
    "match_redis_flush_stub",
    "match_redis_help_client",
    "match_redis_info_template",
    "match_redis_unknown_core",
    "match_smb_bogus_pipe",
    "match_smb_negotiate_deficit",
    "match_smb_static_ntlm_challenge",
    "match_smb_target_info_mismatch",
    "match_smtp_extension_monotone",
    "match_smtp_lost_envelope",
    "match_smtp_placeholder_identity",
    "match_ssh_banner",
    "match_telnet_banner",
    "match_telnet_blind_option",
    "match_telnet_canned_reject",
    "match_telnet_cowrie_preamble",
    "match_telnet_option_spray",
    "match_tls_stock_cert",
    "match_uname_signature",
    "match_vnc_auth_fail",
    "match_vnc_invalid_security_challenge",
    "match_vnc_vncauth_only",
    "normalize_uname",
]
