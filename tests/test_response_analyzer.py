
from analyzer.response_analyzer import ResponseAnalyzer


def make_response(
    payload="normal",
    status_code=200,
    response_time=0.2,
    response_length=500,
    response_text="Normal application response",
    error=None
):

    return {
        "payload": payload,
        "method": "GET",
        "status_code": status_code,
        "response_time": response_time,
        "response_length": response_length,
        "response_text": response_text,
        "error": error
    }


def test_normal_response():

    analyzer = ResponseAnalyzer()

    baseline = make_response()
    result = make_response(payload="mutated")

    analysis = analyzer.analyze(baseline, result)

    assert analysis["status"] == "normal"
    assert analysis["findings"] == []


def test_status_code_change():

    analyzer = ResponseAnalyzer()

    baseline = make_response(status_code=200)
    result = make_response(status_code=404)

    analysis = analyzer.analyze(baseline, result)

    assert analysis["status"] == "suspicious"

    assert any(
        finding["type"] == "status_code_change"
        for finding in analysis["findings"]
    )


def test_server_error_detection():

    analyzer = ResponseAnalyzer()

    baseline = make_response()
    result = make_response(status_code=500)

    analysis = analyzer.analyze(baseline, result)

    assert any(
        finding["type"] == "server_error"
        for finding in analysis["findings"]
    )
    server_error = next(
        finding for finding in analysis["findings"]
        if finding["type"] == "server_error"
    )
    assert server_error["severity"] == "review"
    assert server_error["evidence"]["observed_status"] == 500
    assert "not" in server_error["reasoning"]


def test_response_length_change():

    analyzer = ResponseAnalyzer()

    baseline = make_response(response_length=500)
    result = make_response(response_length=900)

    analysis = analyzer.analyze(baseline, result)

    assert any(
        finding["type"] == "response_length_change"
        for finding in analysis["findings"]
    )


def test_response_time_increase():

    analyzer = ResponseAnalyzer()

    baseline = make_response(response_time=0.2)
    result = make_response(response_time=2.0)

    analysis = analyzer.analyze(baseline, result)

    assert any(
        finding["type"] == "response_time_increase"
        for finding in analysis["findings"]
    )


def test_database_error_detection():

    analyzer = ResponseAnalyzer()

    baseline = make_response()

    result = make_response(
        response_text="SQL syntax error in database query"
    )

    analysis = analyzer.analyze(baseline, result)

    assert any(
        finding["type"] == "database_error"
        for finding in analysis["findings"]
    )


def test_error_signature_present_in_baseline_is_not_a_new_signal():
    analyzer = ResponseAnalyzer()
    baseline = make_response(
        response_text="SQL syntax error already present in the baseline"
    )
    result = make_response(
        payload="ordinary-input",
        response_text="SQL syntax error already present in the baseline"
    )

    analysis = analyzer.analyze(baseline, result)

    assert not any(
        finding["type"] == "database_error"
        for finding in analysis["findings"]
    )


def test_stack_trace_detection():

    analyzer = ResponseAnalyzer()

    baseline = make_response()

    result = make_response(
        response_text=(
            "Traceback (most recent call last): "
            "Exception in application"
        )
    )

    analysis = analyzer.analyze(baseline, result)

    assert any(
        finding["type"] == "stack_trace"
        for finding in analysis["findings"]
    )


def test_failed_request_is_inconclusive():

    analyzer = ResponseAnalyzer()

    baseline = make_response()

    result = make_response(
        error="ConnectionError",
        status_code=None,
        response_time=None,
        response_length=None
    )

    analysis = analyzer.analyze(baseline, result)

    assert analysis["status"] == "inconclusive"


def test_analyze_many():

    analyzer = ResponseAnalyzer()

    baseline = make_response()

    results = [
        make_response(payload="first"),
        make_response(payload="second", status_code=500)
    ]

    analyses = analyzer.analyze_many(baseline, results)

    assert len(analyses) == 2
    assert analyses[0]["status"] == "normal"
    assert analyses[1]["status"] == "suspicious"


def test_analysis_preserves_payload_provenance():
    baseline = make_response()
    result = make_response(payload="mutated")
    result.update(
        {
            "payload_id": "payload-1-uppercase",
            "strategy": "uppercase",
            "original_payload": "normal",
            "target": "http://127.0.0.1:8080",
            "parameter": "q",
        }
    )

    analysis = ResponseAnalyzer().analyze(baseline, result)

    assert analysis["payload_id"] == "payload-1-uppercase"
    assert analysis["strategy"] == "uppercase"
    assert analysis["original_payload"] == "normal"
    assert analysis["target"] == "http://127.0.0.1:8080"


def test_input_reflection_is_a_candidate_with_limitations():
    baseline = make_response(response_text="baseline response")
    result = make_response(
        payload="<test>",
        response_text="returned <test>",
    )

    analysis = ResponseAnalyzer().analyze(baseline, result)

    reflected = next(
        finding for finding in analysis["findings"]
        if finding["type"] == "input_reflection"
    )
    assert reflected["evidence"]["reflected_input"] == "<test>"
    assert "does not demonstrate" in reflected["reasoning"]
    assert reflected["confidence"] == "low"


def test_response_thresholds_are_configurable():
    analyzer = ResponseAnalyzer(
        response_length_change_bytes=20,
        response_time_increase_seconds=0.25,
    )
    baseline = make_response(response_length=500, response_time=0.2)
    result = make_response(
        payload="different",
        response_length=525,
        response_time=0.5,
    )

    analysis = analyzer.analyze(baseline, result)

    assert {item["type"] for item in analysis["findings"]} >= {
        "response_length_change",
        "response_time_increase",
    }


def test_invalid_response_thresholds_are_rejected():
    import pytest

    with pytest.raises(ValueError, match="response_time_increase_seconds"):
        ResponseAnalyzer(response_time_increase_seconds=-1)
