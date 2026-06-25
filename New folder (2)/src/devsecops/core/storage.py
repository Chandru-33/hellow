"""JSON-based issue tracking (no database)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class JsonStorage:
    """Manages .devsecops/ JSON files."""

    BASELINE_FILE = "baseline.json"
    RESOLVED_FILE = "resolved_issues.json"
    HISTORY_FILE = "scan_history.json"
    LAST_REPORT_FILE = "last_report.json"

    def __init__(self, devsecops_dir: Path) -> None:
        self.devsecops_dir = devsecops_dir
        self.devsecops_dir.mkdir(parents=True, exist_ok=True)

    def _read(self, filename: str) -> Any:
        path = self.devsecops_dir / filename
        if not path.exists():
            return None
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)

    def _write(self, filename: str, data: Any) -> None:
        path = self.devsecops_dir / filename
        with path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

    def has_baseline(self) -> bool:
        return (self.devsecops_dir / self.BASELINE_FILE).exists()

    def save_baseline(self, tracked_files: list[str]) -> None:
        self._write(
            self.BASELINE_FILE,
            {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "tracked_files": sorted(tracked_files),
                "file_count": len(tracked_files),
            },
        )

    def load_baseline(self) -> dict[str, Any] | None:
        return self._read(self.BASELINE_FILE)

    def is_resolved(self, fingerprint: str) -> bool:
        data = self._read(self.RESOLVED_FILE) or {"resolved": {}}
        return fingerprint in data.get("resolved", {})

    def mark_resolved(self, fingerprint: str, finding: dict[str, Any]) -> None:
        data = self._read(self.RESOLVED_FILE) or {"resolved": {}}
        data["resolved"][fingerprint] = {
            "resolved_at": datetime.now(timezone.utc).isoformat(),
            "finding": finding,
        }
        self._write(self.RESOLVED_FILE, data)

    def unmark_resolved(self, fingerprint: str) -> None:
        data = self._read(self.RESOLVED_FILE) or {"resolved": {}}
        data.get("resolved", {}).pop(fingerprint, None)
        self._write(self.RESOLVED_FILE, data)

    def list_resolved(self) -> dict[str, Any]:
        data = self._read(self.RESOLVED_FILE) or {"resolved": {}}
        return data.get("resolved", {})

    def append_history(self, scan_result: dict[str, Any]) -> None:
        data = self._read(self.HISTORY_FILE) or {"scans": []}
        data["scans"].append(scan_result)
        if len(data["scans"]) > 100:
            data["scans"] = data["scans"][-100:]
        self._write(self.HISTORY_FILE, data)

    def get_history(self, limit: int = 20) -> list[dict[str, Any]]:
        data = self._read(self.HISTORY_FILE) or {"scans": []}
        return data["scans"][-limit:]

    def save_last_report(self, report: dict[str, Any]) -> None:
        self._write(self.LAST_REPORT_FILE, report)

    def load_last_report(self) -> dict[str, Any] | None:
        return self._read(self.LAST_REPORT_FILE)
