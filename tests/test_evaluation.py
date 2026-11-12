from examples.evaluate_local import run_evaluation


def test_local_evaluation_exercises_real_pipeline_and_reliability():
    report = run_evaluation()

    assert report["configuration"]["seed"] == 42
    assert report["configuration"]["target_scope"] == "127.0.0.1 only"
    assert report["test_case_counts"]["scan_count"] == 7
    assert report["test_case_counts"]["sqlite_records"] == 7
    counts = report["test_case_counts"]
    assert counts["grammar_payloads_generated_total"] == 14
    assert counts["mutation_outputs_generated_total"] == 14
    assert counts["unique_payloads_scheduled_total"] == 14
    assert counts["test_payload_requests_sent_total"] == 13
    assert counts["baseline_requests_total"] == 7
    assert counts["baseline_responses_not_analyzed"] == 7
    assert counts["scheduled_payloads_not_sent_total"] == 1
    assert counts["generated_payload_outputs_total"] == 28
    assert counts["requests_sent_total"] == 21
    assert counts["requests_completed_total"] == 20
    assert counts["requests_failed_total"] == 1
    assert counts["analysis_results_total"] == 13
    assert counts["candidate_findings_total"] == 8
    assert counts["analysis_status_counts"] == {
        "normal": 7,
        "suspicious": 6,
    }
    assert report["test_case_counts"]["requests_sent_total"] == (
        report["test_case_counts"]["requests_completed_total"]
        + report["test_case_counts"]["requests_failed_total"]
    )
    assert report["false_positive_observations"][
        "normal_endpoint_candidate_findings"
    ] == 0
    scenarios = {scan["scenario"]: scan for scan in report["scans"]}
    assert scenarios["normal"]["payload_values"] == scenarios[
        "normal-repeat"
    ]["payload_values"]
    assert scenarios["controlled-error"]["candidate_categories"] == [
        "server_error",
        "status_code_change",
    ]
    assert scenarios["reflection"]["candidate_categories"] == [
        "input_reflection"
    ]
    assert scenarios["database-signature"]["candidate_categories"] == [
        "database_error"
    ]
    assert all(
        scan["html_report_contains_scan_payload"]
        and scan["json_report_matches_sqlite"]
        and scan["sqlite_persisted"]
        for scan in report["scans"]
    )
    assert report["report_generation"]["json_and_html_for_every_scan"] is True
    assert report["report_generation"]["sqlite_persistence_for_every_scan"] is True
    assert report["reliability_checks"]["network_timeout_observed"]
    assert report["reliability_checks"][
        "cancelled_scan_partial_results_persisted"
    ] is True
    assert report["reliability_checks"]["large_bounded_generation_count"] == 1000
    assert any("Cross-platform compatibility is not claimed" in item
               for item in report["limitations"])
