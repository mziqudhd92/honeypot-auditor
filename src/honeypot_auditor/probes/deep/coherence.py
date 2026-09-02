"""Deep probe #2: cross-artifact OS coherence checks."""

from __future__ import annotations

import re
from contextlib import suppress

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.sshutil import random_creds, ssh_exec, try_ssh_auth

_KERNEL_RE = re.compile(r"Linux version (\S+)")
_UNAME_KERNEL_RE = re.compile(r"Linux \S+ (\S+)")


def probe_os_coherence(host: str, port: int) -> list[Indicator]:
    user, password = random_creds()
    client, err = try_ssh_auth(host, port, user, password)
    if client is None:
        return [
            skipped_indicator(
                "deep.os_coherence",
                "Cross-artifact OS identity inconsistent",
                "coherence",
                "no SSH session (auth failed)",
                protocol="ssh",
                error=err,
            )
        ]

    artifacts: dict[str, str] = {}
    try:
        for key, cmd in (
            ("uname", "uname -a"),
            ("proc_version", "cat /proc/version 2>/dev/null"),
            ("os_release", "cat /etc/os-release 2>/dev/null | head -5"),
            (
                "cpuinfo",
                "grep -E 'model name|hypervisor|vendor_id' /proc/cpuinfo 2>/dev/null | head -6",
            ),
            ("self_exe", "readlink /proc/self/exe 2>/dev/null"),
            ("dmi", "cat /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor 2>/dev/null"),
            ("netdev", "cat /proc/net/dev 2>/dev/null | head -8"),
            ("devnodes", "ls -l /dev/null /dev/ptmx 2>/dev/null"),
        ):
            out, exec_err, _ = ssh_exec(client, cmd)
            if not exec_err and out:
                artifacts[key] = out
    finally:
        with suppress(Exception):
            client.close()

    mismatches: list[str] = []
    uname = artifacts.get("uname", "")
    proc_version = artifacts.get("proc_version", "")
    os_release = artifacts.get("os_release", "")
    cpuinfo = artifacts.get("cpuinfo", "")

    uname_k = _UNAME_KERNEL_RE.search(uname)
    proc_k = _KERNEL_RE.search(proc_version)
    if uname_k and proc_k and uname_k.group(1) != proc_k.group(1):
        mismatches.append(f"uname kernel {uname_k.group(1)} != /proc/version {proc_k.group(1)}")

    if uname and proc_version:
        if "debian" in uname.lower() and "debian" not in os_release.lower() and os_release:
            mismatches.append("uname mentions Debian but /etc/os-release does not")
        if "ubuntu" in uname.lower() and "ubuntu" not in os_release.lower() and os_release:
            mismatches.append("uname mentions Ubuntu but /etc/os-release does not")

    if (
        "hypervisor" in cpuinfo.lower()
        and "qemu" not in uname.lower()
        and "vmware" not in uname.lower()
    ):
        # Real VMs often disclose; scrubbed cpuinfo on bare-metal claim is suspicious.
        if "model name" in cpuinfo.lower():
            mismatches.append("hypervisor flag in /proc/cpuinfo with non-VM uname")

    dmi = artifacts.get("dmi", "")
    if any(tok in dmi.lower() for tok in ("qemu", "virtualbox", "bochs", "vmware", "kvm")):
        if uname and "qemu" not in uname.lower() and "kvm" not in uname.lower():
            mismatches.append("DMI product is a hypervisor but uname is not")
    netdev = artifacts.get("netdev", "")
    if "veth" in netdev.lower():
        mismatches.append("veth interface in /proc/net/dev (container netns)")
    devnodes = artifacts.get("devnodes", "")
    if uname and devnodes and " /dev/null" not in f" {devnodes}" and "null" not in devnodes.lower():
        mismatches.append("/dev/null missing from device listing")

    if uname and not proc_version and not os_release:
        mismatches.append("uname present but /proc/version and os-release empty")

    triggered = len(mismatches) >= 2
    return [
        Indicator(
            id="deep.os_coherence",
            title="Cross-artifact OS identity inconsistent",
            category="coherence",
            triggered=triggered,
            protocol="ssh",
            detail="; ".join(mismatches[:4]) if mismatches else "OS artifacts align",
            evidence="\n---\n".join(f"{k}:\n{v}" for k, v in artifacts.items())[:2500],
        )
    ]
