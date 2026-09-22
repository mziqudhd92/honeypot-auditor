#!/usr/bin/env python3
"""Silent-accept tarpit listeners for the lab-tour demo."""
from __future__ import annotations

import socket
import threading
import time

PORTS = (9080, 9445, 3128)


def serve(port: int) -> None:
    # Demo listeners must accept published Docker ports from the host.
    sock = socket.socket()  # nosemgrep: python.lang.security.audit.network.bind.avoid-bind-to-all-interfaces
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    while True:
        client, _ = sock.accept()
        threading.Thread(
            target=_hold,
            args=(client,),
            daemon=True,
        ).start()


def _hold(client: socket.socket) -> None:
    try:
        time.sleep(3600)
    finally:
        try:
            client.close()
        except OSError:
            pass


def main() -> None:
    for port in PORTS:
        threading.Thread(target=serve, args=(port,), daemon=True).start()
    print("tarpit ready on", PORTS, flush=True)
    time.sleep(10**9)


if __name__ == "__main__":
    main()
