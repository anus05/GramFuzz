"""Baseline comparisons that produce evidence-backed candidate signals."""

import re


class ResponseAnalyzer:
    """Compare HTTP responses without treating anomalies as confirmed flaws."""

    ERROR_PATTERNS = {
        "database_error": [
            r"SQL syntax.*error",
            r"database query failed",
            r"sqlite.*exception",
            r"postgresql.*error",
        ],
        "stack_trace": [
            r"Traceback \(most recent call last\)",
            r"at [\w.$]+\([\w.]+:\d+\)",
            r"Exception in thread",
        ],
        "application_error": [
            r"Internal Server Error",
            r"Unhandled Exception",
            r"Application Error",
        ],
    }

    LIMITATION = (
        "This heuristic is a candidate signal only. It does not establish "
        "exploitability; review the target behavior manually."
    )

    def __init__(
        self,
        response_length_change_bytes=100,
        response_time_increase_seconds=1.0,
    ):
        for value, name in (
            (response_length_change_bytes, "response_length_change_bytes"),
            (response_time_increase_seconds, "response_time_increase_seconds"),
        ):
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or value <= 0
            ):
                raise ValueError(f"{name} must be a positive number.")
        self.response_length_change_bytes = response_length_change_bytes
        self.response_time_increase_seconds = response_time_increase_seconds

    def _finding(self, finding_type, reasoning, evidence, baseline_comparison):
        return {
            "type": finding_type,
            "severity": "review",
            "detection_method": finding_type,
            "reasoning": reasoning,
            "evidence": evidence,
            "baseline_comparison": baseline_comparison,
            "confidence": "low",
            "limitations": self.LIMITATION,
        }

    def analyze(self, baseline, test_result):
        """Compare a test response with its baseline and retain evidence."""
        findings = []

        if baseline.get("error") or test_result.get("error"):
            analysis = {
                "status": "inconclusive",
                "findings": [
                    {
                        "type": "request_error",
                        "evidence": {
                            "baseline_error": baseline.get("error"),
                            "test_error": test_result.get("error"),
                        },
                        "reasoning": (
                            "At least one request failed, so response comparison "
                            "is unavailable."
                        ),
                        "confidence": "none",
                        "limitations": "No response-based conclusion can be drawn.",
                    }
                ],
            }
            return self._attach_payload_metadata(analysis, test_result)

        baseline_status = baseline.get("status_code")
        observed_status = test_result.get("status_code")
        if baseline_status != observed_status:
            findings.append(
                self._finding(
                    "status_code_change",
                    "The test response status differs from the baseline.",
                    {"baseline_status": baseline_status, "observed_status": observed_status},
                    {"baseline_status": baseline_status, "observed_status": observed_status},
                )
            )

        status_code = observed_status
        if isinstance(status_code, int) and status_code >= 500:
            findings.append(
                self._finding(
                    "server_error",
                    "The test response returned a 5xx status; this alone is not "
                    "evidence of a vulnerability.",
                    {"observed_status": status_code},
                    {"baseline_status": baseline_status, "observed_status": status_code},
                )
            )

        baseline_length = baseline.get("response_length")
        test_length = test_result.get("response_length")
        if (
            isinstance(baseline_length, int)
            and isinstance(test_length, int)
            and baseline_length >= 0
            and test_length >= 0
        ):
            difference = abs(test_length - baseline_length)
            if difference >= self.response_length_change_bytes:
                findings.append(
                    self._finding(
                        "response_length_change",
                        "The captured test response differs in length from baseline "
                        "by at least 100 bytes.",
                        {
                            "baseline_length": baseline_length,
                            "observed_length": test_length,
                            "absolute_difference": difference,
                            "test_response_truncated": test_result.get(
                                "response_truncated", False
                            ),
                        },
                        {
                            "baseline_length": baseline_length,
                            "observed_length": test_length,
                        },
                    )
                )

        baseline_time = baseline.get("response_time")
        test_time = test_result.get("response_time")
        if (
            isinstance(baseline_time, (int, float))
            and isinstance(test_time, (int, float))
            and test_time - baseline_time
            >= self.response_time_increase_seconds
        ):
            findings.append(
                self._finding(
                    "response_time_increase",
                    "The test response took at least one second longer than baseline.",
                    {
                        "baseline_seconds": baseline_time,
                        "observed_seconds": test_time,
                    },
                    {
                        "baseline_seconds": baseline_time,
                        "observed_seconds": test_time,
                    },
                )
            )

        response_text = test_result.get("response_text") or ""
        baseline_text = baseline.get("response_text") or ""
        payload = test_result.get("payload")
        if (
            isinstance(payload, str)
            and payload
            and payload in response_text
            and payload not in baseline_text
        ):
            findings.append(
                self._finding(
                    "input_reflection",
                    "The test input was present in the test response but not in "
                    "the baseline response; reflection alone does not demonstrate "
                    "client-side code execution.",
                    {"reflected_input": payload[:200]},
                    {"input_present_in_baseline": False},
                )
            )

        for category, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                baseline_match = re.search(
                    pattern, baseline_text, re.IGNORECASE
                )
                payload_match = (
                    re.search(pattern, payload, re.IGNORECASE)
                    if isinstance(payload, str)
                    else None
                )
                if match and not baseline_match and not payload_match:
                    findings.append(
                        self._finding(
                            category,
                            "The response contains a text pattern commonly "
                            "associated with an application error.",
                            {
                                "matched_pattern": pattern,
                                "matched_text": match.group(0)[:120],
                            },
                            {"baseline_status": baseline_status},
                        )
                    )
                    break

        analysis = {
            "status": "suspicious" if findings else "normal",
            "findings": findings,
        }
        return self._attach_payload_metadata(analysis, test_result)

    @staticmethod
    def _attach_payload_metadata(analysis, test_result):
        for key in (
            "payload",
            "payload_id",
            "strategy",
            "original_payload",
            "target",
            "parameter",
            "attempt",
        ):
            if key in test_result:
                analysis[key] = test_result[key]
        return analysis

    def analyze_many(self, baseline, test_results):
        """Analyze a sequence of responses against a shared baseline."""
        return [self.analyze(baseline, result) for result in test_results]
