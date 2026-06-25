"""Entry point: python -m devsecops."""

from devsecops.core.console import configure_stdio_encoding

configure_stdio_encoding()

from devsecops.cli.main import app

if __name__ == "__main__":
    app()
