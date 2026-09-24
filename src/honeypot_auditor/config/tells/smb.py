SMB_SMB1_DIALECTS = frozenset({"NT LM 0.12", "SMB1", "1.0"})
SMB_NATIVE_OS_TELLS = ("Windows 5.0", "Windows 5.1", "Unix")
# Decisive lure share names — rare outside honeypot skins (case-insensitive).
# Common real-world names (tmp, public, share, files) are intentionally excluded.
SMB_STOCK_SHARE_TELLS = frozenset(
    {
        "honey",
        "honeypot",
        "honeyfs",
        "canary",
        "opencanary",
    }
)
# Generic names only score when ≥2 distinct hits appear on the same face.
SMB_STOCK_SHARE_GENERIC = frozenset(
    {
        "tmp",
        "public",
        "share",
        "files",
    }
)
SMB2_DIALECT_30 = 0x0300
SMB2_DIALECT_311 = 0x0311
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_BAD_NETWORK_NAME = 0xC00000CC
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_NETWORK_NAME_DELETED = 0xC00000C9
STATUS_BAD_NETWORK_PATH = 0xC00000BE
# Benign TREE_CONNECT failures for a random/nonexistent share.
SMB_GHOST_SHARE_OK_STATUS = frozenset(
    {
        STATUS_BAD_NETWORK_NAME,
        STATUS_OBJECT_NAME_NOT_FOUND,
        STATUS_ACCESS_DENIED,
        STATUS_NETWORK_NAME_DELETED,
        STATUS_BAD_NETWORK_PATH,
    }
)
