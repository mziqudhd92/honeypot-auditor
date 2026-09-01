"""Shared runtime constants: user agent, timeouts, Shodan URLs, probe templates."""

from __future__ import annotations

from honeypot_auditor import __version__

USER_AGENT = f"honeypot-auditor/{__version__}"

BLEND_USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
)

DEFAULT_TIMEOUT_SECONDS = 3.0
NMAP_HOST_TIMEOUT = "90s"
SHODAN_HONEYSCORE_URL = "https://api.shodan.io/labs/honeyscore/{ip}"
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
SHODAN_SCORE_THRESHOLD = 0.6

PROBE_USERNAME_TEMPLATE = "user_a{n}"
PROBE_PASSWORD_TEMPLATE = "pass_z{n}"
FTP_PROBE_PREFIX = "hpaudit_"
FTP_PROBE_BODY = b"hpaudit-state-probe\n"
REDIS_PROBE_KEY_PREFIX = "hpaudit_"
REDIS_PROBE_VALUE = "probe_val"

SMTP_HELO = "auditor.invalid"
SMTP_MAIL_FROM = "probe@auditor.invalid"
SMTP_RCPT_TO = "fake_user@external-domain.com"


def effective_user_agent() -> str:
    from honeypot_auditor.settings import ProbeProfile, settings

    if settings.profile == ProbeProfile.BLEND:
        seed = settings.seed or 0
        return BLEND_USER_AGENTS[seed % len(BLEND_USER_AGENTS)]
    return USER_AGENT
