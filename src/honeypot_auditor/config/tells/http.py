HTTP_SERVER_TELLS = (
    "nginx",
    "apache/2.2.22",
)

HTTP_STATIC_BODY_MARKERS = (
    b"<html>",
    b"Welcome",
)

HTTP_DYNAMIC_HEADERS = ("date",)
HTTP_HEADER_LURE_ORDERS: tuple[tuple[str, ...], ...] = (
    ("Server", "Content-Type", "Content-Length", "Connection"),
    ("Server", "Content-Type", "Content-Length"),
)
WILDCARD_HOST = "invalid.test.local"
