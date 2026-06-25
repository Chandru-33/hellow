"""Windows-safe Rich console setup."""

from __future__ import annotations

import sys

from rich.console import Console


def configure_stdio_encoding() -> None:
    """Use UTF-8 for stdout/stderr when the platform default is too narrow."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            if stream.encoding and stream.encoding.lower().replace("-", "") != "utf8":
                reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError, AttributeError):
            pass


def create_console() -> Console:
    configure_stdio_encoding()
    return Console(force_terminal=False, legacy_windows=False)


# Shared console instance for all CLI/report output
console = create_console()
