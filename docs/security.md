# Security and authorization

GramFuzz is intended for systems for which the operator has explicit
authorization. A YAML field is not legal proof of authorization: the scanner
also requires the command-line `--confirm-authorized` flag on every scan.

## Scope controls

- The default allowlist is `localhost`, `127.0.0.1`, and `::1`.
- Additional hosts require an exact `target.allowed_hosts` entry.
- URL schemes, user information, hostnames, and ports are validated.
- Non-global DNS results are rejected unless private-address access is
  explicitly enabled for an allowlisted target.
- Resolved addresses are revalidated and pinned for each HTTP connection.
- DNS resolution has a configurable deadline (`target.dns_timeout`, 0.1–15
  seconds). The operating-system resolver cannot be forcibly interrupted; a
  timed-out worker is daemonized and subsequent hostname lookups fail closed
  while that resolver call remains stuck.
- Environment proxies are bypassed; redirects are not followed.
- Timeouts, minimum inter-request delays, maximum requests, response capture,
  payload size/depth, and sequential concurrency are bounded.
- The HTTP response body reader enforces a total deadline between streamed
  chunks. A blocked read can overrun that deadline by up to the configured
  per-read timeout.
- Cancellation is available through the engine's `cancel()` method.

## Limitations

The scanner currently supports HTTP only and does not provide optional
redirect following, custom request headers, concurrent requests, or JSON-body
POST requests. DNS uses the operating-system resolver; a call that exceeds its
deadline cannot be terminated, so one daemon resolver thread may remain until
the OS call returns. While it remains stuck, subsequent DNS requests fail
closed. `allow_private_addresses` broadens the address policy for allowlisted
targets and should only be used when the specific private target is in scope.

Analyzer output is heuristic. Server errors, response differences, error
signatures, and reflected inputs are candidate signals, not proof of
exploitation. Risk scores are not CVSS. Confirm findings manually and review
the evidence and limitations in the generated report.

## Heuristic scoring

The score is an internal prioritization aid, not CVSS:

| Signal | Base weight |
|---|---:|
| Database error signature | 35 |
| HTTP 5xx response | 30 |
| Stack trace | 25 |
| Application exception signature | 20 |
| Status code change | 10 |
| Response-time increase | 10 |
| Response-length change | 5 |
| Input reflection | 5 |

For each signal category, each repeat observation of the same payload adds 5
points, capped at a 15-point bonus. Category scores are capped at 100 and
summed to a report score capped at 100. Severity bands are informational
(0–19), low (20–39), medium (40–69), and high (70–100). A signal repeated
with the same input is marked `repeatable_signal`; distinct inputs alone do
not establish repeatability. Non-repeated signals remain `candidate`, and
manual verification is never inferred automatically.

Generated inputs are transmitted to the configured target; do not use
untrusted grammars or targets. GramFuzz does not execute generated input on the
local machine.
