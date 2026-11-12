
import json
import pytest

from reporting.report_generator import ReportGenerator


@pytest.fixture
def generator(tmp_path):
    return ReportGenerator(output_dir=tmp_path)


@pytest.fixture
def sample_data():
    analysis_results = [
        {
            "payload": "normal-input",
            "status": "normal",
            "findings": []
        },
        {
            "payload": "test-input",
            "status": "suspicious",
            "findings": [
                {"type": "database_error", "severity": "review"}
            ]
        },
        {
            "payload": "failed-input",
            "status": "inconclusive",
            "findings": [
                "A request failed."
            ]
        }
    ]

    risk_report = {
        "status": "candidate",
        "risk_score": 35,
        "risk_level": "low",
        "confidence": "low",
        "unique_suspicious_payloads": 1,
        "findings": [
            {
                "type": "database_error",
                "base_weight": 35,
                "occurrences": 1,
                "unique_payloads": 1,
                "score": 35
            }
        ]
    }

    return analysis_results, risk_report


def test_json_report_created(generator, sample_data):
    analysis, risk = sample_data

    path = generator.generate_json(
        "http://127.0.0.1:3000",
        analysis,
        risk
    )

    assert path.exists()

    with path.open(encoding="utf-8") as file:
        report = json.load(file)

    assert report["project"] == "GramFuzz"
    assert report["summary"]["total_test_cases"] == 3
    assert report["summary"]["suspicious_cases"] == 1
    assert report["summary"]["normal_cases"] == 1
    assert report["summary"]["inconclusive_cases"] == 1


def test_html_report_created(generator, sample_data):
    analysis, risk = sample_data

    path = generator.generate_html(
        "http://127.0.0.1:3000",
        analysis,
        risk
    )

    assert path.exists()

    content = path.read_text(encoding="utf-8")

    assert "GramFuzz Security Assessment Report" in content
    assert "Assessment Summary" in content
    assert "database_error" in content


def test_empty_scan_results_generate_empty_json_and_html(generator):
    risk = {
        "status": "no_signal",
        "risk_score": 0,
        "risk_level": "informational",
        "candidate_findings": [],
    }

    json_path = generator.generate_json(
        "http://127.0.0.1:3000", [], risk
    )
    html_path = generator.generate_html(
        "http://127.0.0.1:3000", [], risk
    )
    report = json.loads(json_path.read_text(encoding="utf-8"))

    assert report["summary"]["total_test_cases"] == 0
    assert report["summary"]["suspicious_cases"] == 0
    assert report["risk_assessment"]["candidate_findings"] == []
    assert "Total Tests" in html_path.read_text(encoding="utf-8")


def test_custom_filename(generator, sample_data):
    analysis, risk = sample_data

    path = generator.generate_json(
        "http://127.0.0.1:3000",
        analysis,
        risk,
        filename="custom_report.json"
    )

    assert path.name == "custom_report.json"
    assert path.exists()


def test_invalid_analysis_input(generator):
    with pytest.raises(TypeError):
        generator.generate_json(
            "http://127.0.0.1:3000",
            "invalid",
            {}
        )


def test_html_escapes_payload(generator):
    analysis = [
        {
            "payload": "<script>alert('test')</script>",
            "status": "suspicious",
            "findings": []
        }
    ]

    risk = {
        "risk_score": 0,
        "risk_level": "informational"
    }

    path = generator.generate_html(
        "http://127.0.0.1:3000",
        analysis,
        risk
    )

    content = path.read_text(encoding="utf-8")

    assert "<script>alert('test')</script>" not in content
    assert "&lt;script&gt;" in content


def test_default_report_filenames_are_unique(generator, sample_data):
    analysis, risk = sample_data

    first = generator.generate_json("http://127.0.0.1:3000", analysis, risk)
    second = generator.generate_json("http://127.0.0.1:3000", analysis, risk)

    assert first != second


@pytest.mark.parametrize(
    "filename",
    ["../outside.json", "subfolder/report.json", "..\\outside.json"],
)
def test_report_rejects_path_filenames(generator, sample_data, filename):
    analysis, risk = sample_data

    with pytest.raises(ValueError, match="plain filename"):
        generator.generate_json(
            "http://127.0.0.1:3000", analysis, risk, filename=filename
        )


@pytest.mark.parametrize(
    "filename",
    ["C:outside.json", "C:\\outside.json", "report:stream.json"],
)
def test_report_rejects_windows_drive_and_stream_paths(
    generator, sample_data, filename
):
    analysis, risk = sample_data

    with pytest.raises(ValueError, match="plain filename"):
        generator.generate_json(
            "http://127.0.0.1:3000", analysis, risk, filename=filename
        )


def test_report_does_not_overwrite_existing_file(generator, sample_data):
    analysis, risk = sample_data
    report_path = generator.output_dir / "existing.json"
    report_path.write_text("preserve", encoding="utf-8")

    with pytest.raises(FileExistsError):
        generator.generate_json(
            "http://127.0.0.1:3000",
            analysis,
            risk,
            filename=report_path.name,
        )

    assert report_path.read_text(encoding="utf-8") == "preserve"


def test_report_redacts_sensitive_fields_in_all_sections(generator):
    path = generator.generate_json(
        "http://127.0.0.1:3000/",
        [
            {
                "payload": "safe",
                "status": "suspicious",
                "findings": [
                    {"type": "x", "evidence": {"Authorization": "secret"}}
                ],
            }
        ],
        {
            "risk_score": 1,
            "candidate_findings": [
                {"category": "x", "Cookie": "session-cookie"}
            ],
        },
        scan_metadata={"headers": {"X-Api-Key": "private"}},
    )
    report_text = path.read_text(encoding="utf-8")

    assert "secret" not in report_text
    assert "session-cookie" not in report_text
    assert "private" not in report_text
    assert report_text.count("[REDACTED]") == 3


def test_report_redacts_target_query_string(generator, sample_data):
    analysis, risk = sample_data
    path = generator.generate_json(
        "http://127.0.0.1:3000/search?token=private",
        analysis,
        risk,
    )
    report = json.loads(path.read_text(encoding="utf-8"))

    assert report["target"] == "http://127.0.0.1:3000/search"
    assert "private" not in path.read_text(encoding="utf-8")


def test_html_report_displays_escaped_candidate_evidence(generator):
    analysis = [{"payload": "<script>", "status": "suspicious", "findings": []}]
    risk = {
        "risk_score": 5,
        "risk_level": "informational",
        "candidate_findings": [
            {
                "category": "input_reflection",
                "severity": "informational",
                "confidence": "low",
                "supporting_evidence": {"matched": "<img src=x>"},
                "remediation_recommendation": "Encode output.",
            }
        ],
    }

    path = generator.generate_html(
        "http://127.0.0.1:3000/?secret=value",
        analysis,
        risk,
    )
    content = path.read_text(encoding="utf-8")

    assert "Candidate Findings and Evidence" in content
    assert "&lt;img src=x&gt;" in content
    assert "<img src=x>" not in content
    assert "secret=value" not in content


def test_report_includes_scan_metadata(generator):
    path = generator.generate_json(
        "http://127.0.0.1:3000/",
        [],
        {"risk_score": 0},
        scan_metadata={"scan_id": "scan-123", "requests_sent": 1},
    )

    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["scan_metadata"]["scan_id"] == "scan-123"
