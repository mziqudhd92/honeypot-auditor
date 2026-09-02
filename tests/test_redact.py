"""Redaction tests."""

from __future__ import annotations

from honeypot_auditor.redact import redact


def test_redact_aws_key():
    text = "key=AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret  # gitleaks:allow
    out, found = redact(text)
    assert found
    assert "AKIA" not in out
    assert "[REDACTED_HONEYTOKEN]" in out


def test_redact_jwt():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig"  # pragma: allowlist secret  # gitleaks:allow
    out, found = redact(f"token={token}")
    assert found
    assert token not in out
