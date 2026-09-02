"""CTI transcript parsers for SSH/Telnet playbooks."""

from honeypot_auditor.probes.shell_cti import (
    arith_missing,
    honeyfs_tells,
    identity_tells,
    whoami_matches_lure,
)


def test_whoami_from_prompt_and_line():
    assert whoami_matches_lure("user_a15@svr04:~$ ", "user_a15")
    assert whoami_matches_lure("whoami\nuser_a15\n", "user_a15")
    assert not whoami_matches_lure("root@realhost:~$ ", "user_a15")


def test_honeyfs_and_arith():
    blob = "ls\ncowrie.txt\necho $((7*9))\necho $((7*9))\n"
    assert honeyfs_tells(blob) == ["cowrie.txt"]
    assert arith_missing(blob)
    tells = identity_tells(blob)
    assert "honeyfs=cowrie.txt" in tells
    assert "no bash arithmetic (expected 63)" in tells
    assert "tty is not a pty" in identity_tells("not a tty")


def test_identity_canned_ssh_refusals():
    bits = identity_tells("Command not handled.\nInternal error. Please try again later.")
    assert "canned 'Command not handled' refusal" in bits
    assert "canned internal-error stub" in bits


def test_identity_pipe_utils_and_hypervisor():
    bits = identity_tells("bash: awk: command not found\nProduct Name: QEMU Standard PC")
    assert "pipe utilities missing" in bits
    assert "hypervisor product string in dmi/cpu" in bits


def test_whoami_empty_inputs():
    assert not whoami_matches_lure("", "user_a1")
    assert not whoami_matches_lure("user_a1@", "")


def test_identity_cowrie_hostname():
    text = "Linux svr04 6.1.0-21-amd64 #1 SMP Debian GNU/Linux"
    bits = identity_tells(text)
    assert any("svr04" in b for b in bits)
