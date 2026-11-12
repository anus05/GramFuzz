import json

import pytest

from gramfuzz.storage.scan_repository import ScanRepository


@pytest.fixture
def repository(tmp_path):
    return ScanRepository(tmp_path / "nested" / "scans.sqlite3")


def test_round_trip_and_scan_listing(repository):
    repository.save_scan(
        scan_id="scan-1",
        target="http://127.0.0.1:3000/path?token=secret",
        started_at="2026-01-01T00:00:00+00:00",
        completed_at="2026-01-01T00:01:00+00:00",
        config={
            "target": {
                "url": "http://127.0.0.1:3000/path?token=secret",
                "headers": {"Authorization": "secret"},
            },
            "_config_path": "private-path",
        },
        analysis_results=[{"payload": "safe", "status": "normal"}],
        risk_report={"risk_score": 0},
        request_stats={"requests_sent": 1},
        report_paths={"json": "report.json"},
    )

    stored = repository.get_scan("scan-1")

    assert stored["target"] == "http://127.0.0.1:3000/path"
    assert stored["config"]["target"]["url"] == "http://127.0.0.1:3000/path"
    assert stored["config"]["target"]["headers"]["Authorization"] == "[REDACTED]"
    assert "_config_path" not in stored["config"]
    assert repository.list_scans()[0]["scan_id"] == "scan-1"
    assert repository.latest_scan()["scan_id"] == "scan-1"


def test_sql_injection_like_scan_id_is_treated_as_data(repository):
    with pytest.raises(KeyError):
        repository.get_scan("' OR 1=1 --")


def test_missing_scan_raises(repository):
    with pytest.raises(KeyError, match="not found"):
        repository.get_scan("missing")


def test_list_limit_must_be_positive(repository):
    with pytest.raises(ValueError):
        repository.list_scans(0)
