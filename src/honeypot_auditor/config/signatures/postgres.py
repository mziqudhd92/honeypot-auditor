def match_postgres_cleartext_only(ssl_reply: bytes, auth_reply: bytes) -> str | None:
    """SSLRequest rejected with N, then only AuthenticationCleartextPassword."""
    if (ssl_reply or b"")[:1] != b"N":
        return None
    data = auth_reply or b""
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
