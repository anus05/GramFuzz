"""Repeatability analysis and transparent heuristic risk scoring."""

import hashlib
import json
from datetime import datetime, timezone


class DetectionValidator:
    """Aggregate candidate signals without claiming manual verification."""

    FINDING_WEIGHTS = {
        "database_error": 35,
        "server_error": 30,
        "stack_trace": 25,
        "application_error": 20,
        "status_code_change": 10,
        "response_time_increase": 10,
        "response_length_change": 5,
        "input_reflection": 5,
    }

    REMEDIATIONS = {
        "database_error": "Review database error handling and use parameterized queries.",
        "server_error": "Investigate the server-side failure and validate input handling.",
        "stack_trace": "Disable detailed error disclosure in responses.",
        "application_error": "Review exception handling and server-side input validation.",
        "status_code_change": "Review whether the response change is expected for this input.",
        "response_time_increase": "Repeat under controlled conditions and inspect application logs.",
        "response_length_change": "Review the response difference; size changes alone are inconclusive.",
        "input_reflection": "Apply context-aware output encoding; reflection alone is not proof of XSS.",
    }

    def validate(self, analysis_results):
        """Score response signals using repeat observations of identical inputs."""
        if not isinstance(analysis_results, list):
            raise TypeError("Analysis results must be a list.")

        grouped = {}
        inconclusive_count = 0
        for result in analysis_results:
            if not isinstance(result, dict):
                raise TypeError("Each analysis result must be a dictionary.")
            if result.get("status") == "inconclusive":
                inconclusive_count += 1
                continue
            findings = result.get("findings", [])
            if not isinstance(findings, list):
                raise TypeError("Analysis findings must be a list.")
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                finding_type = finding.get("type")
                if (
                    not isinstance(finding_type, str)
                    or finding_type not in self.FINDING_WEIGHTS
                ):
                    continue
                group = grouped.setdefault(
                    finding_type,
                    {
                        "occurrences": 0,
                        "payload_counts": {},
                        "observations": [],
                    },
                )
                group["occurrences"] += 1
                payload = result.get("payload")
                if isinstance(payload, str):
                    group["payload_counts"][payload] = (
                        group["payload_counts"].get(payload, 0) + 1
                    )
                group["observations"].append((result, finding))

        if not grouped:
            return {
                "status": "no_signal",
                "risk_score": 0,
                "risk_level": "informational",
                "confidence": "none",
                "unique_suspicious_payloads": 0,
                "inconclusive_requests": inconclusive_count,
                "findings": [],
                "candidate_findings": [],
                "scoring_note": "Heuristic score only; not an official CVSS score.",
            }

        total_score = 0
        validated_findings = []
        candidate_findings_by_id = {}
        any_repeatable = False

        for finding_type, details in grouped.items():
            payload_counts = details["payload_counts"]
            unique_payload_count = len(payload_counts)
            repeat_count = max(payload_counts.values(), default=1)
            repeatable = repeat_count >= 2
            any_repeatable = any_repeatable or repeatable
            repeat_bonus = min(max(repeat_count - 1, 0) * 5, 15)
            score = min(self.FINDING_WEIGHTS[finding_type] + repeat_bonus, 100)
            total_score += score
            validated_findings.append(
                {
                    "type": finding_type,
                    "base_weight": self.FINDING_WEIGHTS[finding_type],
                    "occurrences": details["occurrences"],
                    "unique_payloads": unique_payload_count,
                    "same_payload_repeat_count": repeat_count,
                    "score": score,
                }
            )

            for result, finding in details["observations"]:
                identity = json.dumps(
                    [
                        finding_type,
                        result.get("target"),
                        result.get("parameter"),
                        result.get("payload"),
                    ],
                    ensure_ascii=False,
                )
                finding_id = hashlib.sha256(
                    identity.encode("utf-8")
                ).hexdigest()[:16]
                evidence = finding.get("evidence", {})
                baseline_comparison = finding.get("baseline_comparison", {})
                candidate = candidate_findings_by_id.get(finding_id)
                if candidate is not None:
                    candidate["supporting_evidence_samples"].append(evidence)
                    candidate["baseline_comparison_samples"].append(
                        baseline_comparison
                    )
                    candidate["observation_count"] += 1
                    continue
                candidate_findings_by_id[finding_id] = {
                    "finding_id": finding_id,
                    "category": finding_type,
                    "target_endpoint": result.get("target"),
                    "parameter": result.get("parameter"),
                    "payload_id": result.get("payload_id"),
                    "detection_method": finding.get(
                        "detection_method", finding_type
                    ),
                    "supporting_evidence": evidence,
                    "supporting_evidence_samples": [evidence],
                    "baseline_comparison": baseline_comparison,
                    "baseline_comparison_samples": [baseline_comparison],
                    "observation_count": 1,
                    "repeatability": {
                        "same_payload_observations": repeat_count,
                        "distinct_payloads": unique_payload_count,
                        "state": (
                            "repeatable_signal" if repeatable else "candidate"
                        ),
                    },
                    "confidence": "moderate" if repeatable else "low",
                    "heuristic_risk_score": score,
                    "severity": self._severity(score),
                    "remediation_recommendation": self.REMEDIATIONS[finding_type],
                    "reasoning": finding.get("reasoning", ""),
                    "limitations": finding.get(
                        "limitations",
                        "Candidate signal only; manual verification is required.",
                    ),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "state": "repeatable_signal" if repeatable else "candidate",
                }

        risk_score = min(total_score, 100)
        status = "repeatable_signal" if any_repeatable else "candidate"
        confidence = "moderate" if any_repeatable else "low"
        candidate_findings = list(candidate_findings_by_id.values())
        return {
            "status": status,
            "risk_score": risk_score,
            "risk_level": self._severity(risk_score),
            "confidence": confidence,
            "unique_suspicious_payloads": len(
                {
                    payload
                    for details in grouped.values()
                    for payload in details["payload_counts"]
                }
            ),
            "inconclusive_requests": inconclusive_count,
            "findings": validated_findings,
            "candidate_findings": candidate_findings,
            "scoring_note": "Heuristic score only; not an official CVSS score.",
        }

    @staticmethod
    def _severity(score):
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "informational"
