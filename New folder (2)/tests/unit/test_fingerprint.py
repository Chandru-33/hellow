"""Unit tests for fingerprint generation."""

from devsecops.core.fingerprint import generate_fingerprint


def test_fingerprint_deterministic():
    fp1 = generate_fingerprint("auth.py", "SQL Injection", 10, "query = x + y")
    fp2 = generate_fingerprint("auth.py", "SQL Injection", 10, "query = x + y")
    assert fp1 == fp2
    assert len(fp1) == 64


def test_fingerprint_changes_with_content():
    fp1 = generate_fingerprint("auth.py", "SQL Injection", 10, "query = x + y")
    fp2 = generate_fingerprint("auth.py", "SQL Injection", 10, "query = a + b")
    assert fp1 != fp2


def test_fingerprint_changes_with_line():
    fp1 = generate_fingerprint("auth.py", "SQL Injection", 10, "code")
    fp2 = generate_fingerprint("auth.py", "SQL Injection", 11, "code")
    assert fp1 != fp2
