from __future__ import annotations

import re

SSH_BANNER_SIGNATURES = (
    "SSH-2.0-OpenSSH_5.1p1 Debian-4",
    "SSH-2.0-OpenSSH_5.1p1 Debian-5",
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4",
)

UNAME_SIGNATURES = (
    "Linux <host> 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:08 UTC 2009 i686 GNU/Linux",
    "Linux <host> 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux",
    "Linux <host> 3.2.0-4-amd64 #1 SMP Debian 3.2.51-1 x86_64 GNU/Linux",
)

CPUINFO_TELLS = (
    "Intel(R) Core(TM)2 Duo CPU     T7300  @ 2.00GHz",
    "Intel(R) Core(TM)2 Duo CPU T7300 @ 2.00GHz",
)

COWRIE_HOSTNAMES = ("svr04", "nas3")
COWRIE_MOTD_TELLS = (
    "The programs included with the Debian GNU/Linux system are free software",
)

UNAME_HOST_RE = re.compile(r"^Linux\s+\S+\s+")
