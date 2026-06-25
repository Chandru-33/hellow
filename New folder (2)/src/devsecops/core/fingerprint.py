"""Issue fingerprint generation for resolution tracking."""

from __future__ import annotations

import hashlib


def generate_fingerprint(
    file_path: str,
    issue_type: str,
    line_number: int,
    code_snippet: str,
) -> str:
    """Generate SHA256 fingerprint for an issue."""
    payload = f"{file_path}|{issue_type}|{line_number}|{code_snippet.strip()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
