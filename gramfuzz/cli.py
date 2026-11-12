"""Command-line interface for GramFuzz."""

import argparse
import json
import logging
import signal
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from analyzer.detection_validator import DetectionValidator
from analyzer.response_analyzer import ResponseAnalyzer
from core.grammar_parser import GrammarError, load_grammar, validate_grammar
from core.mutator import PayloadMutator
from core.payload_generator import PayloadGenerator
from engine.fuzzing_engine import FuzzingEngine, ScanCancelled
from gramfuzz import __version__
from gramfuzz.config.loader import ConfigurationError, load_config
from gramfuzz.storage.scan_repository import ScanRepository
from reporting.report_generator import ReportGenerator


logger = logging.getLogger("gramfuzz")


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="gramfuzz",
        description="Grammar-guided security testing for explicitly authorized targets.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("init", help="Create a starter YAML configuration.")
    initialize.add_argument("--directory", default=".", help="Output directory.")

    grammar = commands.add_parser("grammar", help="Validate or generate CFG inputs.")
    grammar_commands = grammar.add_subparsers(dest="grammar_command", required=True)
    validate = grammar_commands.add_parser("validate", help="Validate a JSON grammar.")
    validate.add_argument("file")

    generate = commands.add_parser("generate", help="Generate grammar inputs.")
    generate.add_argument("--grammar", required=True)
    generate.add_argument("--count", type=int, default=20)
    generate.add_argument("--seed", type=int)
    generate.add_argument("--max-depth", type=int, default=10)
    generate.add_argument("--max-length", type=int, default=4096)

    scan = commands.add_parser("scan", help="Run an authorized scan.")
    scan.add_argument("--config", required=True)
    scan.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Confirm that you are authorized to test this target.",
    )

    report = commands.add_parser("report", help="Regenerate reports from stored scan data.")
    report.add_argument("--latest", action="store_true", required=True)
    report.add_argument("--database", default=".gramfuzz/scans.sqlite3")

    scans = commands.add_parser("scans", help="List or inspect stored scans.")
    scan_commands = scans.add_subparsers(dest="scans_command", required=True)
    list_command = scan_commands.add_parser("list", help="List recent scans.")
    list_command.add_argument("--database", default=".gramfuzz/scans.sqlite3")
    list_command.add_argument("--limit", type=int, default=50)
    show = scan_commands.add_parser("show", help="Show a stored scan.")
    show.add_argument("scan_id")
    show.add_argument("--database", default=".gramfuzz/scans.sqlite3")
    return parser


def _write_starter_files(directory):
    output_dir = Path(directory).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    config_path = output_dir / "gramfuzz.yaml"
    grammar_dir = output_dir / "grammars"
    grammar_path = grammar_dir / "demo.json"

    if config_path.exists() or grammar_path.exists():
        raise FileExistsError(
            "Refusing to overwrite gramfuzz.yaml or grammars/demo.json."
        )

    grammar_dir.mkdir(parents=True, exist_ok=True)
    grammar_path.write_text(
        json.dumps(
            {
                "start": "<expression>",
                "rules": {
                    "<expression>": ["<operator> <value>"],
                    "<operator>": ["AND", "OR"],
                    "<value>": ["1=1", "2=2", "3=3"],
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    config_path.write_text(
        "\n".join(
            [
                "target:",
                '  url: "http://127.0.0.1:3000/"',
                '  allowed_hosts: [localhost, 127.0.0.1, "::1"]',
                "  authorized: false",
                "  allow_private_addresses: false",
                "  dns_timeout: 3.0",
                "scan:",
                "  method: GET",
                "  parameter: q",
                "  timeout: 5",
                "  delay: 0.5",
                "  max_requests: 50",
                "  max_payloads: 20",
                "  repeats_per_payload: 1",
                "  max_response_bytes: 1048576",
                "  concurrency: 1",
                "  mutation_strategies: [lowercase, uppercase, swapcase]",
                "analysis:",
                "  response_length_change_bytes: 100",
                "  response_time_increase_seconds: 1.0",
                "grammar:",
                "  file: grammars/demo.json",
                "  max_depth: 10",
                "  seed: 42",
                "  max_length: 4096",
                "reporting:",
                "  output_dir: reports",
                "  formats: [json, html]",
                "storage:",
                "  database: .gramfuzz/scans.sqlite3",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"Created {config_path}")
    print(f"Created {grammar_path}")


def _scan(config_path, confirm_authorized):
    if not confirm_authorized:
        raise ConfigurationError(
            "Scanning requires --confirm-authorized and an explicitly authorized "
            "target. Confirm only if you have permission to test it."
        )

    config = load_config(config_path)
    target = config["target"]
    if not target["authorized"]:
        raise ConfigurationError(
            "Set target.authorized: true only after obtaining permission to test "
            "this application."
        )

    scan_settings = config["scan"]
    grammar_config = config["grammar"]
    grammar = load_grammar(grammar_config["file"])
    generator = PayloadGenerator(
        grammar,
        max_depth=grammar_config["max_depth"],
        seed=grammar_config["seed"],
        max_length=grammar_config["max_length"],
    )
    max_payloads = scan_settings["max_payloads"]
    strategies = scan_settings["mutation_strategies"]
    original_count = (
        max_payloads
        if not strategies
        else max(1, (max_payloads + 1) // 2)
    )
    originals = generator.generate_many(original_count)
    mutator = PayloadMutator(
        strategies=strategies,
        seed=grammar_config["seed"],
        max_length=grammar_config["max_length"],
    )
    payloads = []
    seen_payloads = set()
    mutation_outputs_generated = 0
    mutation_payloads_scheduled = 0
    for index, original in enumerate(originals, start=1):
        if original not in seen_payloads and len(payloads) < max_payloads:
            payloads.append(
                {
                    "payload": original,
                    "payload_id": f"payload-{index}",
                    "strategy": "grammar",
                    "original_payload": original,
                }
            )
            seen_payloads.add(original)
        mutations = mutator.mutate(original)
        mutation_outputs_generated += len(mutations)
        for mutation_index, mutation in enumerate(mutations, start=1):
            mutated = mutation["payload"]
            if mutated in seen_payloads or len(payloads) >= max_payloads:
                continue
            payloads.append(
                {
                    "payload": mutated,
                    "payload_id": (
                        f"payload-{index}-{mutation['strategy']}-{mutation_index}"
                    ),
                    "strategy": mutation["strategy"],
                    "original_payload": original,
                }
            )
            mutation_payloads_scheduled += 1
            seen_payloads.add(mutated)

    engine = FuzzingEngine(
        target_url=target["url"],
        parameter=scan_settings["parameter"],
        method=scan_settings["method"],
        timeout=scan_settings["timeout"],
        delay=scan_settings["delay"],
        max_requests=scan_settings["max_requests"],
        allowed_hosts=target["allowed_hosts"],
        allow_private_addresses=target["allow_private_addresses"],
        max_response_bytes=scan_settings["max_response_bytes"],
        dns_timeout=target["dns_timeout"],
    )
    logger.info(
        "Starting authorized scan target=%s allowed_hosts=%s "
        "scan_configuration=%s",
        engine.target_label,
        target["allowed_hosts"],
        scan_settings,
    )
    started_at = datetime.now(timezone.utc).isoformat()
    previous_sigint_handler = signal.getsignal(signal.SIGINT)
    scan_cancelled = False

    def request_cancellation(signum, frame):
        logger.warning("Cancellation requested; waiting for current request.")
        engine.cancel()

    signal.signal(signal.SIGINT, request_cancellation)
    try:
        baseline = engine.send_payload("gramfuzz-baseline")
        if baseline["error"]:
            logger.error("Baseline request failed: %s", baseline["error"])
            raise RuntimeError(
                "Baseline request failed; scan stopped. "
                f"Request error: {baseline['error']}"
            )

        repeated_payloads = [
            {
                **payload,
                "attempt": attempt,
            }
            for payload in payloads
            for attempt in range(1, scan_settings["repeats_per_payload"] + 1)
        ]
        try:
            responses = engine.run(repeated_payloads)
        except ScanCancelled as error:
            responses = error.results
            scan_cancelled = True
            logger.warning(
                "Scan cancelled; preserving %d completed test responses.",
                len(responses),
            )
    finally:
        signal.signal(signal.SIGINT, previous_sigint_handler)
    analyses = ResponseAnalyzer(
        response_length_change_bytes=config["analysis"][
            "response_length_change_bytes"
        ],
        response_time_increase_seconds=config["analysis"][
            "response_time_increase_seconds"
        ],
    ).analyze_many(baseline, responses)
    risk = DetectionValidator().validate(analyses)
    completed_at = datetime.now(timezone.utc).isoformat()
    scan_id = uuid4().hex

    request_stats = {
        "requests_sent": engine.request_count,
        "requests_completed": sum(
            result["error"] is None for result in responses
        ) + 1,
        "requests_failed": sum(
            result["error"] is not None for result in responses
        ),
        "max_requests": scan_settings["max_requests"],
        "payloads_generated": len(payloads),
        "grammar_payloads_generated": len(originals),
        "mutation_outputs_generated": mutation_outputs_generated,
        "mutation_payloads_scheduled": mutation_payloads_scheduled,
        "unique_payloads_scheduled": len(payloads),
        "responses_received": sum(
            result["error"] is None for result in responses
        ) + 1,
        "baseline_received": True,
        "scan_status": "cancelled" if scan_cancelled else "completed",
        "request_errors": [
            result["error"] for result in responses if result["error"]
        ],
    }
    report_metadata = {
        "scan_id": scan_id,
        "started_at": started_at,
        "completed_at": completed_at,
        "target_scope": target["allowed_hosts"],
        "dns_timeout": target["dns_timeout"],
        "scan_configuration": {
            "method": scan_settings["method"],
            "parameter": scan_settings["parameter"],
            "timeout": scan_settings["timeout"],
            "delay": scan_settings["delay"],
            "max_requests": scan_settings["max_requests"],
            "max_response_bytes": scan_settings["max_response_bytes"],
            "repeats_per_payload": scan_settings["repeats_per_payload"],
            "grammar_seed": grammar_config["seed"],
            "grammar_file": Path(grammar_config["file"]).name,
        },
        "scan_status": "cancelled" if scan_cancelled else "completed",
        "analysis_thresholds": config["analysis"],
        "request_statistics": request_stats,
    }
    report_generator = ReportGenerator(config["reporting"]["output_dir"])
    report_paths = {}
    for report_format in config["reporting"]["formats"]:
        if report_format == "json":
            report_path = report_generator.generate_json(
                target["url"], analyses, risk, scan_metadata=report_metadata
            )
        else:
            report_path = report_generator.generate_html(
                target["url"], analyses, risk, scan_metadata=report_metadata
            )
        report_paths[report_format] = str(report_path)

    repository = ScanRepository(config["storage"]["database"])
    repository.save_scan(
        scan_id=scan_id,
        target=target["url"],
        started_at=started_at,
        completed_at=completed_at,
        config=config,
        analysis_results=analyses,
        risk_report=risk,
        request_stats=request_stats,
        report_paths=report_paths,
    )
    print(
        json.dumps(
            {
                "scan_id": scan_id,
                "risk_score": risk["risk_score"],
                "risk_level": risk["risk_level"],
                "request_stats": request_stats,
                "scan_status": "cancelled" if scan_cancelled else "completed",
                "reports": report_paths,
            },
            indent=2,
        )
    )
    return 130 if scan_cancelled else 0


def _dispatch(args):
    if args.command == "init":
        _write_starter_files(args.directory)
    elif args.command == "grammar":
        grammar = load_grammar(args.file)
        result = validate_grammar(grammar)
        print(
            f"Valid grammar: {result['reachable_rules']} reachable, "
            f"{result['productive_rules']} productive rules."
        )
    elif args.command == "generate":
        grammar = load_grammar(args.grammar)
        generated = PayloadGenerator(
            grammar,
            max_depth=args.max_depth,
            seed=args.seed,
            max_length=args.max_length,
        ).generate_many(args.count)
        for payload in generated:
            print(payload)
    elif args.command == "scan":
        return _scan(args.config, args.confirm_authorized)
    elif args.command == "report":
        repository = ScanRepository(args.database)
        scan = repository.latest_scan()
        if scan is None:
            raise FileNotFoundError("No stored scans are available.")
        output_dir = scan["config"]["reporting"]["output_dir"]
        generator = ReportGenerator(output_dir)
        paths = {}
        for report_format in scan["config"]["reporting"]["formats"]:
            report_metadata = {
                "scan_id": scan["scan_id"],
                "started_at": scan["started_at"],
                "completed_at": scan["completed_at"],
                "target_scope": scan["config"]["target"]["allowed_hosts"],
                "scan_configuration": scan["config"].get("scan", {}),
                "scan_status": scan["request_stats"].get(
                    "scan_status", "completed"
                ),
                "analysis_thresholds": scan["config"].get("analysis", {}),
                "request_statistics": scan["request_stats"],
            }
            if report_format == "json":
                path = generator.generate_json(
                    scan["target"],
                    scan["analysis_results"],
                    scan["risk_report"],
                    scan_metadata=report_metadata,
                )
            else:
                path = generator.generate_html(
                    scan["target"],
                    scan["analysis_results"],
                    scan["risk_report"],
                    scan_metadata=report_metadata,
                )
            paths[report_format] = str(path)
        print(json.dumps({"scan_id": scan["scan_id"], "reports": paths}, indent=2))
    elif args.command == "scans" and args.scans_command == "list":
        repository = ScanRepository(args.database)
        print(json.dumps(repository.list_scans(args.limit), indent=2))
    elif args.command == "scans" and args.scans_command == "show":
        repository = ScanRepository(args.database)
        print(json.dumps(repository.get_scan(args.scan_id), indent=2))
    return 0


def main(argv=None):
    """Run the CLI and return a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        return _dispatch(args)
    except (
        ConfigurationError,
        FileNotFoundError,
        FileExistsError,
        GrammarError,
        KeyError,
        OSError,
        RuntimeError,
        sqlite3.Error,
        TypeError,
        ValueError,
    ) as error:
        print(f"gramfuzz: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
