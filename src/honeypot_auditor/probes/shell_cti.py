"""CTI-style SSH/Telnet transcript tells (Cowrie/Kippo playbook)."""

from __future__ import annotations

import re

from honeypot_auditor.config import (
    match_cowrie_identity,
    match_cpuinfo_signature,
    match_uname_signature,
)

HONEYFS_NAMES = ("cowrie.txt",)
ARITH_EXPECT = "63"
CTI_SHELL_COMMANDS = (
    "whoami",
    "id",
    "hostname",
    "uname -a",
    "echo $((7*9))",
    "ls",
    "cat /etc/hostname",
    "cat /proc/cpuinfo",
    "tty",
    "cat /etc/passwd | grep root | awk '{print $1}'",
    "ls -l /dev/null /dev/ptmx /dev/urandom 2>/dev/null",
    "cat /sys/class/dmi/id/product_name 2>/dev/null",
)


def lure_prompt_user(transcript: str, user: str) -> bool:
    """Random lure account appears as the shell identity (user@host)."""
    if not user or not transcript:
        return False
    return f"{user}@" in transcript or f"{user}@" in transcript.replace("\r", "")


def whoami_matches_lure(transcript: str, user: str) -> bool:
    if not user or not transcript:
        return False
    if lure_prompt_user(transcript, user):
        return True
    return bool(re.search(rf"(?im)^\s*{re.escape(user)}\s*$", transcript))


def honeyfs_tells(transcript: str) -> list[str]:
    low = (transcript or "").lower()
    return [name for name in HONEYFS_NAMES if name in low]


def arith_missing(transcript: str) -> bool:
    blob = (transcript or "").replace("\n", " ").replace("\r", " ")
    return ARITH_EXPECT not in blob


def identity_tells(transcript: str) -> list[str]:
    bits: list[str] = []
    cowrie = match_cowrie_identity(transcript)
    if cowrie:
        bits.append(cowrie)
    uname = match_uname_signature(transcript)
    if uname:
        bits.append(f"uname={uname}")
    cpu = match_cpuinfo_signature(transcript)
    if cpu:
        bits.append(f"cpuinfo={cpu}")
    for name in honeyfs_tells(transcript):
        bits.append(f"honeyfs={name}")
    if "7*9" in (transcript or "") and arith_missing(transcript):
        bits.append("no bash arithmetic (expected 63)")
    low = (transcript or "").lower()
    if "not a tty" in low:
        bits.append("tty is not a pty")
    if "command not found" in low and ("awk" in low or "grep" in low):
        bits.append("pipe utilities missing")
    if "qemu" in low or "virtualbox" in low or "bochs" in low:
        bits.append("hypervisor product string in dmi/cpu")
    return bits
