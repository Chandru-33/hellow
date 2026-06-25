"""Unit tests for JSON storage."""

import json
from pathlib import Path

from devsecops.core.storage import JsonStorage


def test_baseline_lifecycle(tmp_path):
    storage = JsonStorage(tmp_path / ".devsecops")
    assert not storage.has_baseline()
    storage.save_baseline(["a.py", "b.py"])
    assert storage.has_baseline()
    baseline = storage.load_baseline()
    assert baseline["file_count"] == 2


def test_resolution_tracking(tmp_path):
    storage = JsonStorage(tmp_path / ".devsecops")
    fp = "abc123"
    assert not storage.is_resolved(fp)
    storage.mark_resolved(fp, {"issue_type": "test"})
    assert storage.is_resolved(fp)
    storage.unmark_resolved(fp)
    assert not storage.is_resolved(fp)


def test_scan_history(tmp_path):
    storage = JsonStorage(tmp_path / ".devsecops")
    storage.append_history({"scan_id": "001", "findings_count": 3})
    storage.append_history({"scan_id": "002", "findings_count": 0})
    history = storage.get_history()
    assert len(history) == 2
    assert history[-1]["scan_id"] == "002"


def test_last_report(tmp_path):
    storage = JsonStorage(tmp_path / ".devsecops")
    report = {"scan_id": "test", "findings": []}
    storage.save_last_report(report)
    loaded = storage.load_last_report()
    assert loaded["scan_id"] == "test"
