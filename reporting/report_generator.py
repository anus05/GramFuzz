
import json
import html
import os
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4


class ReportGenerator:
    """
    Generates JSON and HTML security assessment reports.
    """

    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _redact_sensitive_fields(value, key=""):
        markers = (
            "authorization",
            "cookie",
            "password",
            "secret",
            "token",
            "credential",
            "api-key",
            "api_key",
        )
        if any(marker in key.lower() for marker in markers):
            return "[REDACTED]"
        if isinstance(value, dict):
            return {
                item_key: ReportGenerator._redact_sensitive_fields(
                    item_value, str(item_key)
                )
                for item_key, item_value in value.items()
            }
        if isinstance(value, list):
            return [
                ReportGenerator._redact_sensitive_fields(item) for item in value
            ]
        if isinstance(value, tuple):
            return [
                ReportGenerator._redact_sensitive_fields(item) for item in value
            ]
        return value

    def _validate_data(self, analysis_results, risk_report):
        if not isinstance(analysis_results, list):
            raise TypeError("Analysis results must be a list.")
        if any(not isinstance(item, dict) for item in analysis_results):
            raise TypeError("Each analysis result must be a dictionary.")

        if not isinstance(risk_report, dict):
            raise TypeError("Risk report must be a dictionary.")
        candidate_findings = risk_report.get("candidate_findings", [])
        if not isinstance(candidate_findings, list) or any(
            not isinstance(item, dict) for item in candidate_findings
        ):
            raise TypeError("Candidate findings must be a list of dictionaries.")

    def _build_report(
        self, target_url, analysis_results, risk_report, scan_metadata=None
    ):
        parsed_target = urlsplit(str(target_url))
        hostname = parsed_target.hostname or ""
        if ":" in hostname:
            hostname = f"[{hostname}]"
        if parsed_target.port is not None:
            hostname = f"{hostname}:{parsed_target.port}"
        safe_target = urlunsplit(
            (
                parsed_target.scheme,
                hostname,
                parsed_target.path,
                "",
                "",
            )
        )
        candidate_findings = risk_report.get("candidate_findings", [])
        severity_distribution = {
            severity: sum(
                finding.get("severity") == severity
                for finding in candidate_findings
            )
            for severity in ("high", "medium", "low", "informational")
        }
        return {
            "project": "GramFuzz",
            "report_generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "target": safe_target,
            "summary": {
                "total_test_cases": len(analysis_results),
                "suspicious_cases": sum(
                    1 for item in analysis_results
                    if item.get("status") == "suspicious"
                ),
                "normal_cases": sum(
                    1 for item in analysis_results
                    if item.get("status") == "normal"
                ),
                "inconclusive_cases": sum(
                    1 for item in analysis_results
                    if item.get("status") == "inconclusive"
                ),
                "severity_distribution": severity_distribution,
            },
            "risk_assessment": self._redact_sensitive_fields(risk_report),
            "scan_metadata": self._redact_sensitive_fields(scan_metadata or {}),
            "analysis_results": self._redact_sensitive_fields(analysis_results),
            "disclaimer": (
                "Automated findings are indicators for investigation, "
                "not proof of exploitable vulnerabilities. "
                "Manual verification is required."
            )
        }

    def _output_path(self, filename, suffix):
        if filename is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filename = f"gramfuzz_report_{timestamp}_{uuid4().hex[:8]}{suffix}"

        if (
            not isinstance(filename, str)
            or not filename
            or Path(filename).name != filename
            or PureWindowsPath(filename).drive
            or PureWindowsPath(filename).root
            or "/" in filename
            or "\\" in filename
            or ":" in filename
            or filename in {".", ".."}
        ):
            raise ValueError("Report filename must be a plain filename.")
        if Path(filename).suffix.lower() != suffix:
            raise ValueError(f"Report filename must end with {suffix}.")

        output_path = self.output_dir / filename
        if output_path.is_symlink():
            raise ValueError("Refusing to write a report through a symbolic link.")
        return output_path

    @staticmethod
    def _open_new_report(output_path):
        """Create a report without following or replacing an existing path."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(output_path, flags, 0o600)
        return os.fdopen(descriptor, "w", encoding="utf-8")

    def generate_json(
        self,
        target_url,
        analysis_results,
        risk_report,
        filename=None,
        scan_metadata=None,
    ):
        self._validate_data(analysis_results, risk_report)

        report = self._build_report(
            target_url,
            analysis_results,
            risk_report,
            scan_metadata,
        )

        output_path = self._output_path(filename, ".json")

        with self._open_new_report(output_path) as file:
            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

        return output_path

    def generate_html(
        self,
        target_url,
        analysis_results,
        risk_report,
        filename=None,
        scan_metadata=None,
    ):
        self._validate_data(analysis_results, risk_report)

        report = self._build_report(
            target_url,
            analysis_results,
            risk_report,
            scan_metadata,
        )

        summary = report["summary"]
        risk_score = risk_report.get("risk_score", 0)
        risk_level = risk_report.get("risk_level", "unknown")

        rows = []
        finding_rows = []
        for finding in risk_report.get("candidate_findings", []):
            finding_rows.append(
                "<tr>"
                f"<td>{html.escape(str(finding.get('severity', 'unknown')))}</td>"
                f"<td>{html.escape(str(finding.get('category', 'unknown')))}</td>"
                f"<td>{html.escape(str(finding.get('confidence', 'unknown')))}</td>"
                f"<td><code>{html.escape(json.dumps(finding, ensure_ascii=False))}</code></td>"
                "</tr>"
            )

        for item in analysis_results:
            payload = html.escape(
                str(item.get("payload", ""))
            )

            status = html.escape(
                str(item.get("status", "unknown"))
            )

            findings = html.escape(
                json.dumps(item.get("findings", []))
            )

            rows.append(
                f"""
                <tr>
                    <td><code>{payload}</code></td>
                    <td>{status}</td>
                    <td>{findings}</td>
                </tr>
                """
            )

        generated_at = html.escape(
            report["report_generated_at"]
        )

        safe_target = html.escape(report["target"])
        safe_risk_level = html.escape(str(risk_level))
        safe_risk_score = html.escape(str(risk_score))
        severity_summary = html.escape(
            json.dumps(summary["severity_distribution"], ensure_ascii=False)
        )
        scan_metadata = html.escape(
            json.dumps(report["scan_metadata"], ensure_ascii=False, indent=2)
        )

        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>GramFuzz Security Report</title>

            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 40px;
                    background: #f4f6f9;
                    color: #222;
                }}

                .container {{
                    max-width: 1100px;
                    margin: auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                }}

                h1, h2 {{
                    color: #183153;
                }}

                .cards {{
                    display: flex;
                    flex-wrap: wrap;
                    gap: 15px;
                }}

                .card {{
                    background: #eef3f8;
                    padding: 18px;
                    border-radius: 8px;
                    min-width: 150px;
                    flex: 1;
                }}

                .score {{
                    font-size: 28px;
                    font-weight: bold;
                }}

                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}

                th, td {{
                    padding: 12px;
                    border: 1px solid #ddd;
                    text-align: left;
                    vertical-align: top;
                }}

                th {{
                    background: #183153;
                    color: white;
                }}

                code {{
                    overflow-wrap: anywhere;
                    white-space: pre-wrap;
                }}

                .disclaimer {{
                    margin-top: 25px;
                    padding: 15px;
                    background: #fff4d6;
                    border-radius: 6px;
                }}
            </style>
        </head>

        <body>
            <div class="container">
                <h1>GramFuzz Security Assessment Report</h1>

                <p><strong>Target:</strong> {safe_target}</p>
                <p><strong>Generated:</strong> {generated_at}</p>

                <h2>Assessment Summary</h2>

                <div class="cards">
                    <div class="card">
                        <h3>Total Tests</h3>
                        <div class="score">{summary["total_test_cases"]}</div>
                    </div>

                    <div class="card">
                        <h3>Suspicious</h3>
                        <div class="score">{summary["suspicious_cases"]}</div>
                    </div>

                    <div class="card">
                        <h3>Normal</h3>
                        <div class="score">{summary["normal_cases"]}</div>
                    </div>

                    <div class="card">
                        <h3>Inconclusive</h3>
                        <div class="score">{summary["inconclusive_cases"]}</div>
                    </div>
                </div>

                <h2>Risk Assessment</h2>

                <p><strong>Heuristic Risk Score:</strong> {safe_risk_score}/100</p>
                <p><strong>Risk Level:</strong> {safe_risk_level}</p>
                <p><strong>Confidence:</strong>
                    {html.escape(str(risk_report.get("confidence", "unknown")))}
                </p>

                <h2>Severity Distribution</h2>
                <p><code>{severity_summary}</code></p>

                <h2>Scan Details</h2>
                <pre><code>{scan_metadata}</code></pre>

                <h2>Candidate Findings and Evidence</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Heuristic severity</th>
                            <th>Category</th>
                            <th>Confidence</th>
                            <th>Evidence, reasoning, and recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(finding_rows)}
                    </tbody>
                </table>

                <h2>Detailed Analysis</h2>

                <table>
                    <thead>
                        <tr>
                            <th>Payload</th>
                            <th>Status</th>
                            <th>Findings</th>
                        </tr>
                    </thead>

                    <tbody>
                        {"".join(rows)}
                    </tbody>
                </table>

                <div class="disclaimer">
                    <strong>Disclaimer:</strong>
                    {html.escape(report["disclaimer"])}
                </div>
            </div>
        </body>
        </html>
        """

        output_path = self._output_path(filename, ".html")
        with self._open_new_report(output_path) as file:
            file.write(html_content)

        return output_path
