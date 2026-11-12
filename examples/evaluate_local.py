"""Reproducible end-to-end evaluation against the loopback test fixture."""

import argparse
import contextlib
import html
import io
import json
import platform
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyzer.detection_validator import DetectionValidator
from core.grammar_parser import GrammarError, load_grammar
from core.payload_generator import PayloadGenerator
from engine.fuzzing_engine import FuzzingEngine
from examples.local_test_app import LocalTestApplication
from gramfuzz.cli import main as gramfuzz_main
from gramfuzz.config.loader import ConfigurationError, load_config
from gramfuzz.storage.scan_repository import ScanRepository
from reporting.report_generator import ReportGenerator


GRAMMAR_FILES = {
    "sql": PROJECT_ROOT / "gramfuzz" / "grammars" / "sql_syntax.json",
    "xss": PROJECT_ROOT / "gramfuzz" / "grammars" / "xss_reflection.json",
    "path": PROJECT_ROOT / "gramfuzz" / "grammars" / "path_validation.json",
}
SEED = 42


def _write_scan_config(path, database, report_dir, target_url, grammar_path):
    config = {
        "target": {
            "url": target_url,
            "allowed_hosts": ["127.0.0.1"],
            "authorized": True,
            "allow_private_addresses": False,
            "dns_timeout": 2.0,
        },
        "scan": {
            "method": "GET",
            "parameter": "q",
            "timeout": 2,
            "delay": 0.2,
            "max_requests": 5,
            "max_payloads": 3,
            "repeats_per_payload": 1,
            "max_response_bytes": 2048,
            "concurrency": 1,
            "mutation_strategies": ["uppercase"],
        },
        "analysis": {
            "response_length_change_bytes": 100,
            "response_time_increase_seconds": 1.0,
        },
        "grammar": {
            "file": str(grammar_path),
            "max_depth": 10,
            "seed": SEED,
            "max_length": 256,
        },
        "reporting": {"output_dir": str(report_dir), "formats": ["json", "html"]},
        "storage": {"database": str(database)},
    }
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")


def _run_cli_scan(config_path, cancel_after_first_payload=False):
    output = io.StringIO()
    if not cancel_after_first_payload:
        with contextlib.redirect_stdout(output):
            exit_code = gramfuzz_main(
                [
                    "scan",
                    "--config",
                    str(config_path),
                    "--confirm-authorized",
                ]
            )
    else:
        original_send_payload = FuzzingEngine.send_payload
        cancelled = False

        def send_then_cancel(engine, payload, metadata=None):
            nonlocal cancelled
            result = original_send_payload(engine, payload, metadata)
            if metadata is not None and not cancelled:
                cancelled = True
                engine.cancel()
            return result

        with patch.object(FuzzingEngine, "send_payload", send_then_cancel):
            with contextlib.redirect_stdout(output):
                exit_code = gramfuzz_main(
                    [
                        "scan",
                        "--config",
                        str(config_path),
                        "--confirm-authorized",
                    ]
                )
    return exit_code, json.loads(output.getvalue())


def _verify_and_summarize_scan(repository, result, endpoint):
    stored = repository.get_scan(result["scan_id"])
    json_report = json.loads(
        Path(result["reports"]["json"]).read_text(encoding="utf-8")
    )
    html_report = Path(result["reports"]["html"]).read_text(encoding="utf-8")
    if json_report["analysis_results"] != stored["analysis_results"]:
        raise AssertionError("JSON report analysis differs from SQLite results.")
    if json_report["risk_assessment"] != stored["risk_report"]:
        raise AssertionError("JSON report risk differs from SQLite results.")
    if json_report["scan_metadata"]["scan_id"] != result["scan_id"]:
        raise AssertionError("Report metadata does not identify its scan.")
    if json_report["scan_metadata"]["request_statistics"] != stored[
        "request_stats"
    ]:
        raise AssertionError("Report request statistics differ from SQLite.")
    if stored["report_paths"] != result["reports"]:
        raise AssertionError("SQLite report paths differ from the CLI output.")
    if html.escape(result["scan_id"]) not in html_report:
        raise AssertionError("HTML report does not identify its scan.")
    for analysis in stored["analysis_results"]:
        if (
            html.escape(analysis["payload"]) not in html_report
            or html.escape(analysis["status"]) not in html_report
            or html.escape(json.dumps(analysis["findings"])) not in html_report
        ):
            raise AssertionError("HTML report omits a real scan payload.")
    has_html_results = bool(stored["analysis_results"])

    return {
        "endpoint": endpoint,
        "scan_id": result["scan_id"],
        "scan_status": result["scan_status"],
        "payloads": stored["request_stats"]["payloads_generated"],
        "grammar_payloads_generated": stored["request_stats"][
            "grammar_payloads_generated"
        ],
        "mutation_outputs_generated": stored["request_stats"][
            "mutation_outputs_generated"
        ],
        "mutation_payloads_scheduled": stored["request_stats"][
            "mutation_payloads_scheduled"
        ],
        "requests_sent": stored["request_stats"]["requests_sent"],
        "requests_completed": stored["request_stats"]["requests_completed"],
        "requests_failed": stored["request_stats"]["requests_failed"],
        "analysis_results": len(stored["analysis_results"]),
        "payload_values": [
            item["payload"] for item in stored["analysis_results"]
        ],
        "payload_strategies": [
            item.get("strategy", "grammar")
            for item in stored["analysis_results"]
        ],
        "analysis_statuses": [
            item["status"] for item in stored["analysis_results"]
        ],
        "candidate_categories": sorted(
            {
                finding["category"]
                for finding in stored["risk_report"]["candidate_findings"]
            }
        ),
        "candidate_findings": len(
            stored["risk_report"]["candidate_findings"]
        ),
        "risk_score": stored["risk_report"]["risk_score"],
        "json_report_matches_sqlite": True,
        "html_report_contains_scan_payload": (
            not stored["analysis_results"] or has_html_results
        ),
        "sqlite_persisted": True,
    }


def run_evaluation():
    """Run deterministic, bounded scans against a real loopback HTTP server."""
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="gramfuzz-evaluation-") as directory:
        root = Path(directory)
        database = root / "scans.sqlite3"
        repository = ScanRepository(database)
        scans = []
        with LocalTestApplication() as application:
            scenarios = [
                ("normal", "normal", "path", False),
                ("normal-repeat", "normal", "path", False),
                ("controlled-error", "controlled-error", "sql", False),
                ("reflection", "reflect", "xss", False),
                ("database-signature", "database-error", "sql", False),
                ("slow", "slow", "path", False),
                ("cancelled-partial", "normal", "path", True),
            ]

            for name, endpoint, grammar_name, should_cancel in scenarios:
                scan_root = root / name
                scan_root.mkdir()
                config_path = scan_root / "scan.json"
                report_dir = scan_root / "reports"
                request_start = len(application.received_requests)
                _write_scan_config(
                    config_path,
                    database,
                    report_dir,
                    f"{application.base_url}/{endpoint}",
                    GRAMMAR_FILES[grammar_name],
                )
                scan_started = time.perf_counter()
                exit_code, cli_result = _run_cli_scan(
                    config_path,
                    cancel_after_first_payload=should_cancel,
                )
                elapsed = time.perf_counter() - scan_started
                expected_exit_code = 130 if should_cancel else 0
                if exit_code != expected_exit_code:
                    raise AssertionError(
                        f"Unexpected CLI exit code for {name}: {exit_code}"
                    )

                summary = _verify_and_summarize_scan(
                    repository, cli_result, endpoint
                )
                summary["scenario"] = name
                summary["elapsed_seconds"] = round(elapsed, 6)
                summary["fixture_requests_received"] = (
                    len(application.received_requests) - request_start
                )
                if (
                    summary["fixture_requests_received"]
                    != summary["requests_sent"]
                ):
                    raise AssertionError(
                        f"Fixture request count mismatch for {name}."
                    )
                received_payloads = [
                    request["payload"]
                    for request in application.received_requests[request_start:]
                ]
                expected_payloads = [
                    "gramfuzz-baseline",
                    *summary["payload_values"],
                ]
                if received_payloads != expected_payloads:
                    raise AssertionError(
                        f"Fixture did not receive analyzed inputs for {name}."
                    )
                summary["mutation_results"] = sum(
                    strategy != "grammar"
                    for strategy in summary["payload_strategies"]
                )
                if not should_cancel and not summary["mutation_results"]:
                    raise AssertionError(
                        f"No mutation result was analyzed for {name}."
                    )
                scans.append(summary)

            timeout_started = time.perf_counter()
            timeout_engine = FuzzingEngine(
                target_url=f"{application.base_url}/timeout",
                parameter="q",
                timeout=1,
                delay=0.2,
                max_requests=1,
            )
            timeout_result = timeout_engine.send_payload("timeout-marker")
            timeout_seconds = time.perf_counter() - timeout_started
            if timeout_result["error"] is None:
                raise AssertionError("Expected the delayed request to time out.")

            normal_scans = [scan for scan in scans if scan["endpoint"] == "normal"]
            if any(scan["candidate_findings"] for scan in normal_scans):
                raise AssertionError("Normal fixture responses produced candidates.")
            if normal_scans[0]["risk_score"] != 0:
                raise AssertionError("Normal fixture risk score should be zero.")
            if (
                scans[0]["payload_values"] != scans[1]["payload_values"]
                or scans[0]["analysis_statuses"] != scans[1]["analysis_statuses"]
                or scans[0]["risk_score"] != scans[1]["risk_score"]
            ):
                raise AssertionError("Repeated normal scans were not reproducible.")
            if "server_error" not in scans[2]["candidate_categories"]:
                raise AssertionError("The controlled 500 response was not analyzed.")
            if "input_reflection" not in scans[3]["candidate_categories"]:
                raise AssertionError("The safe reflected input was not analyzed.")
            if "database_error" not in scans[4]["candidate_categories"]:
                raise AssertionError("The fixed database signature was not analyzed.")
            if scans[5]["requests_failed"] or scans[5]["candidate_findings"]:
                raise AssertionError("The bounded slow endpoint did not complete cleanly.")
            if (
                scans[6]["scan_status"] != "cancelled"
                or scans[6]["analysis_results"] != 1
                or not scans[6]["json_report_matches_sqlite"]
            ):
                raise AssertionError("Partial cancelled scan was not preserved.")

            malformed_grammar = root / "malformed.json"
            malformed_grammar.write_text("{", encoding="utf-8")
            try:
                load_grammar(malformed_grammar)
            except GrammarError:
                malformed_grammar_rejected = True
            else:
                raise AssertionError("Malformed grammar was accepted.")

            invalid_config = root / "invalid.json"
            invalid_config.write_text(
                json.dumps(
                    {
                        "target": {
                            "url": f"{application.base_url}/normal",
                            "authorized": True,
                        },
                        "scan": {"timeout": 0},
                    }
                ),
                encoding="utf-8",
            )
            try:
                load_config(invalid_config)
            except ConfigurationError:
                invalid_config_rejected = True
            else:
                raise AssertionError("Invalid scan configuration was accepted.")

            empty_report_dir = root / "empty-reports"
            empty_generator = ReportGenerator(empty_report_dir)
            empty_risk = DetectionValidator().validate([])
            empty_json = json.loads(
                empty_generator.generate_json(
                    f"{application.base_url}/normal", [], empty_risk
                ).read_text(encoding="utf-8")
            )
            empty_html_path = empty_generator.generate_html(
                f"{application.base_url}/normal", [], empty_risk
            )
            if (
                empty_json["summary"]["total_test_cases"] != 0
                or not empty_html_path.is_file()
            ):
                raise AssertionError("Empty scan reports were not generated.")

            bounded_grammar = {
                "start": "<marker>",
                "rules": {"<marker>": ["bounded-marker"]},
            }
            large_generation_started = time.perf_counter()
            large_payloads = PayloadGenerator(
                bounded_grammar, seed=SEED, max_length=64
            ).generate_many(1000)
            large_generation_seconds = time.perf_counter() - large_generation_started
            if len(large_payloads) != 1000 or max(map(len, large_payloads)) > 64:
                raise AssertionError("Large bounded generation was incomplete.")

            stored_scans = repository.list_scans(limit=20)
            if len(stored_scans) != len(scans):
                raise AssertionError("Not every completed scan was persisted.")

        request_counts = {
            "unique_payloads_scheduled_total": sum(
                scan["payloads"] for scan in scans
            ),
            "test_payload_requests_sent_total": sum(
                scan["requests_sent"] - 1 for scan in scans
            ),
            "baseline_requests_total": len(scans),
            "baseline_responses_not_analyzed": len(scans),
            "scheduled_payloads_not_sent_total": sum(
                scan["payloads"] - scan["analysis_results"]
                for scan in scans
            ),
            "grammar_payloads_generated_total": sum(
                scan["grammar_payloads_generated"] for scan in scans
            ),
            "mutation_outputs_generated_total": sum(
                scan["mutation_outputs_generated"] for scan in scans
            ),
            "mutation_payloads_scheduled_total": sum(
                scan["mutation_payloads_scheduled"] for scan in scans
            ),
            "generated_payload_outputs_total": sum(
                scan["grammar_payloads_generated"]
                + scan["mutation_outputs_generated"]
                for scan in scans
            ),
            "requests_sent_total": sum(scan["requests_sent"] for scan in scans)
            + 1,
            "requests_completed_total": sum(
                scan["requests_completed"] for scan in scans
            ),
            "requests_failed_total": sum(
                scan["requests_failed"] for scan in scans
            )
            + 1,
            "analysis_results_total": sum(
                scan["analysis_results"] for scan in scans
            ),
            "candidate_findings_total": sum(
                scan["candidate_findings"] for scan in scans
            ),
        }
        statuses = {}
        for scan in scans:
            for status in scan["analysis_statuses"]:
                statuses[status] = statuses.get(status, 0) + 1

        return {
            "environment": {
                "python": platform.python_version(),
                "python_implementation": platform.python_implementation(),
                "operating_system": platform.platform(),
                "machine": platform.machine(),
            },
            "configuration": {
                "seed": SEED,
                "target_scope": "127.0.0.1 only",
                "request_timeout_seconds": 2,
                "minimum_request_delay_seconds": 0.2,
                "maximum_payloads_per_scan": 3,
                "response_limit_bytes": 2048,
                "mutation_strategies": ["uppercase"],
                "grammar_files": {
                    name: str(path.relative_to(PROJECT_ROOT))
                    for name, path in GRAMMAR_FILES.items()
                },
            },
            "scans": scans,
            "test_case_counts": {
                **request_counts,
                "analysis_status_counts": statuses,
                "scan_count": len(scans),
                "sqlite_records": len(stored_scans),
            },
            "detection_results": {
                scan["scenario"]: {
                    "candidate_categories": scan["candidate_categories"],
                    "risk_score": scan["risk_score"],
                }
                for scan in scans
            },
            "false_positive_observations": {
                "normal_endpoint_scans": len(normal_scans),
                "normal_endpoint_candidate_findings": sum(
                    scan["candidate_findings"] for scan in normal_scans
                ),
                "normal_endpoint_risk_scores": [
                    scan["risk_score"] for scan in normal_scans
                ],
            },
            "reliability_checks": {
                "repeated_scans_reproducible": True,
                "empty_scan_reports_generated": True,
                "network_timeout_observed": timeout_result["error"],
                "network_timeout_elapsed_seconds": round(timeout_seconds, 6),
                "invalid_configuration_rejected": invalid_config_rejected,
                "malformed_grammar_rejected": malformed_grammar_rejected,
                "cancelled_scan_partial_results_persisted": True,
                "partial_scan_reports_generated": True,
                "large_bounded_generation_count": len(large_payloads),
                "large_bounded_generation_elapsed_seconds": round(
                    large_generation_seconds, 6
                ),
            },
            "performance": {
                "total_elapsed_seconds": round(time.perf_counter() - started, 6),
                "scan_elapsed_seconds": {
                    scan["scenario"]: scan["elapsed_seconds"] for scan in scans
                },
            },
            "report_generation": {
                "json_and_html_for_every_scan": all(
                    scan["json_report_matches_sqlite"]
                    and scan["html_report_contains_scan_payload"]
                    for scan in scans
                ),
                "sqlite_persistence_for_every_scan": all(
                    scan["sqlite_persisted"] for scan in scans
                ),
            },
            "limitations": [
                "Only the controlled IPv4 loopback fixture was evaluated.",
                "The database-error response is a fixed harmless signature, not a database interaction.",
                "The reflection endpoint returns text and benign markup; no browser execution was tested.",
                "Heuristic candidates are not confirmed vulnerabilities.",
                "Performance measurements are local single-run observations, not benchmarks.",
                "Cross-platform compatibility is not claimed; CI matrix completion was not verified.",
            ],
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report = run_evaluation()
    encoded = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
