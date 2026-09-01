"""Cross-protocol signature helpers."""


def claimed_os_from_banner(text: str) -> str:
    """Best-effort OS family from a service banner (for stack vs banner)."""
    low = (text or "").lower()
    if any(tok in low for tok in ("windows", "microsoft", "exchange", "iis")):
        return "windows"
    if any(tok in low for tok in ("linux", "ubuntu", "debian", "unix type", "openssh")):
        return "linux"
    return ""
