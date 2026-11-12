import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from gramfuzz.cli import main
from gramfuzz.storage.scan_repository import ScanRepository


class LocalScanHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlsplit(self.path).query)
        body = f"received:{query.get('q', [''])[0]}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        return


def test_real_local_scan_persists_results_and_generates_reports(tmp_path, capsys):
    server = HTTPServer(("127.0.0.1", 0), LocalScanHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        grammar_path = tmp_path / "grammar.json"
        grammar_path.write_text(
            json.dumps({"start": "<input>", "rules": {"<input>": ["hello"]}}),
            encoding="utf-8",
        )
        reports_dir = tmp_path / "reports"
        database_path = tmp_path / "scans.sqlite3"
        config_path = tmp_path / "gramfuzz.yaml"
        config_path.write_text(
            "\n".join(
                [
                    "target:",
                    f'  url: "http://127.0.0.1:{server.server_port}/search"',
                    "  authorized: true",
                    "scan:",
                    "  max_requests: 5",
                    "  max_payloads: 2",
                    "  repeats_per_payload: 2",
                    "  delay: 0.2",
                    "  mutation_strategies: [uppercase]",
                    "grammar:",
                    f"  file: {grammar_path}",
                    "reporting:",
                    f"  output_dir: {reports_dir}",
                    "storage:",
                    f"  database: {database_path}",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        assert main(
            [
                "scan",
                "--config",
                str(config_path),
                "--confirm-authorized",
            ]
        ) == 0

        output = json.loads(capsys.readouterr().out)
        stored_scan = ScanRepository(database_path).get_scan(output["scan_id"])
        report_json = json.loads(
            Path(output["reports"]["json"]).read_text(encoding="utf-8")
        )
        assert report_json["scan_metadata"]["scan_id"] == output["scan_id"]
        assert report_json["analysis_results"] == stored_scan["analysis_results"]
        assert report_json["risk_assessment"] == stored_scan["risk_report"]
        assert (
            stored_scan["request_stats"]["mutation_outputs_generated"] > 0
        )
        assert (
            stored_scan["request_stats"]["mutation_payloads_scheduled"] > 0
        )
        assert (
            report_json["scan_metadata"]["request_statistics"]
            == stored_scan["request_stats"]
        )
        assert stored_scan["request_stats"]["requests_sent"] == 5
        assert stored_scan["request_stats"]["responses_received"] == 5
        assert len(stored_scan["analysis_results"]) == 4
        assert stored_scan["analysis_results"][2]["strategy"] == "uppercase"
        assert stored_scan["analysis_results"][2]["original_payload"] == "hello"
        assert stored_scan["analysis_results"][0]["attempt"] == 1
        assert stored_scan["analysis_results"][1]["attempt"] == 2
        assert stored_scan["analysis_results"][0]["status"] == "suspicious"
        assert (
            stored_scan["risk_report"]["status"] == "repeatable_signal"
        )
        reflection = next(
            finding
            for finding in stored_scan["risk_report"]["candidate_findings"]
            if finding["category"] == "input_reflection"
        )
        assert reflection["repeatability"]["same_payload_observations"] == 2
        assert all(path.exists() for path in reports_dir.iterdir())

        assert main(["scans", "list", "--database", str(database_path)]) == 0
        assert json.loads(capsys.readouterr().out)[0]["scan_id"] == output["scan_id"]
        assert main(
            [
                "scans",
                "show",
                output["scan_id"],
                "--database",
                str(database_path),
            ]
        ) == 0
        assert json.loads(capsys.readouterr().out)["scan_id"] == output["scan_id"]
        assert main(
            [
                "report",
                "--latest",
                "--database",
                str(database_path),
            ]
        ) == 0
        regenerated = json.loads(capsys.readouterr().out)
        assert regenerated["scan_id"] == output["scan_id"]
        assert all(Path(path).exists() for path in regenerated["reports"].values())
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
