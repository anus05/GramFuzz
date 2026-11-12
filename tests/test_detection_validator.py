
import pytest

from analyzer.detection_validator import DetectionValidator


@pytest.fixture
def validator():
    return DetectionValidator()


def test_no_signal(validator):
    results = [
        {
            "payload": "hello",
            "status": "normal",
            "findings": []
        }
    ]

    report = validator.validate(results)

    assert report["status"] == "no_signal"
    assert report["risk_score"] == 0
    assert report["risk_level"] == "informational"


def test_single_database_error(validator):
    results = [
        {
            "payload": "test-input",
            "status": "suspicious",
            "findings": [
                {"type": "database_error"}
            ]
        }
    ]

    report = validator.validate(results)

    assert report["status"] == "candidate"
    assert report["risk_score"] == 35
    assert report["risk_level"] == "low"
    assert report["confidence"] == "low"


def test_repeatable_database_error(validator):
    results = [
        {
            "payload": "input-one",
            "status": "suspicious",
            "findings": [
                {"type": "database_error"}
            ]
        },
        {
            "payload": "input-one",
            "status": "suspicious",
            "findings": [
                {"type": "database_error"}
            ]
        }
    ]

    report = validator.validate(results)

    assert report["status"] == "repeatable_signal"
    assert report["risk_score"] == 40
    assert report["risk_level"] == "medium"
    assert report["confidence"] == "moderate"
    assert report["findings"][0]["same_payload_repeat_count"] == 2
    assert report["candidate_findings"][0]["state"] == "repeatable_signal"
    assert len(report["candidate_findings"]) == 1
    assert report["candidate_findings"][0]["observation_count"] == 2


def test_distinct_inputs_do_not_establish_repeatability(validator):
    results = [
        {
            "payload": "input-one",
            "status": "suspicious",
            "findings": [{"type": "database_error"}],
        },
        {
            "payload": "input-two",
            "status": "suspicious",
            "findings": [{"type": "database_error"}],
        },
    ]

    report = validator.validate(results)

    assert report["status"] == "candidate"
    assert report["risk_score"] == 35
    assert report["findings"][0]["same_payload_repeat_count"] == 1


def test_multiple_finding_types(validator):
    results = [
        {
            "payload": "input-one",
            "status": "suspicious",
            "findings": [
                {"type": "database_error"},
                {"type": "stack_trace"}
            ]
        }
    ]

    report = validator.validate(results)

    assert report["risk_score"] == 60
    assert report["risk_level"] == "medium"


def test_inconclusive_results_are_counted(validator):
    results = [
        {
            "payload": "input-one",
            "status": "inconclusive",
            "findings": []
        }
    ]

    report = validator.validate(results)

    assert report["status"] == "no_signal"
    assert report["inconclusive_requests"] == 1


def test_unknown_finding_is_ignored(validator):
    results = [
        {
            "payload": "input-one",
            "status": "suspicious",
            "findings": [
                {"type": "unknown_finding"}
            ]
        }
    ]

    report = validator.validate(results)

    assert report["status"] == "no_signal"
    assert report["risk_score"] == 0


def test_score_is_capped_at_100(validator):
    results = [
        {
            "payload": "input-one",
            "status": "suspicious",
            "findings": [
                {"type": "database_error"},
                {"type": "server_error"},
                {"type": "stack_trace"},
                {"type": "application_error"}
            ]
        }
    ]

    report = validator.validate(results)

    assert report["risk_score"] == 100
    assert report["risk_level"] == "high"


def test_invalid_input_rejected(validator):
    with pytest.raises(TypeError):
        validator.validate("not a list")


def test_candidate_finding_contains_evidence_and_limitations(validator):
    report = validator.validate(
        [
            {
                "payload": "x",
                "payload_id": "input-x",
                "target": "http://127.0.0.1:8000",
                "parameter": "q",
                "status": "suspicious",
                "findings": [
                    {
                        "type": "database_error",
                        "evidence": {"matched_text": "SQL syntax error"},
                        "reasoning": "Database error marker found.",
                        "limitations": "Manual verification is required.",
                    }
                ],
            }
        ]
    )

    finding = report["candidate_findings"][0]
    assert finding["finding_id"]
    assert finding["target_endpoint"] == "http://127.0.0.1:8000"
    assert finding["payload_id"] == "input-x"
    assert finding["supporting_evidence"]["matched_text"] == "SQL syntax error"
    assert finding["heuristic_risk_score"] == 35
    assert finding["limitations"] == "Manual verification is required."
    assert "CVSS" in report["scoring_note"]
