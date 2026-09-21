HTTP_SERVER_TELLS = (
    # Frozen / bait Server tokens only — bare "nginx"/"apache" are production.
    "apache/2.2.22",
    "nginx/0.8.54",
    "nginx/1.4.0",
    "microsoft-iis/6.0",
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
