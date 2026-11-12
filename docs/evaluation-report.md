# Controlled end-to-end evaluation

## Environment and configuration

Measured on Windows 11 (`10.0.26300`), CPython 3.14.6, AMD64. The evaluation
used seed `42`, the three starter grammars, an uppercase mutation strategy,
`max_payloads: 3`, `max_requests: 5`, a 0.2-second minimum delay, a
2-second per-request timeout, and a 2,048-byte response cap. The timeout
failure case used a 1-second request timeout. The test application binds only
to `127.0.0.1`; it does not accept a configurable listen host.

The database-signature endpoint returns a fixed harmless text string; it does
not connect to or query a database. The reflection endpoint returns ordinary
text and benign marker markup; it does not execute content in a browser.

The fixture's `/normal`, `/controlled-error`, `/reflect`, `/database-error`,
and `/slow` endpoints provide the normal, fixed HTTP 500, safe reflection,
fixed database-signature, and 0.25-second response cases. `/timeout` sleeps
for 1.5 seconds to exercise the one-second request timeout.

## Measured results

One complete run of `python examples/evaluate_local.py --output
evaluation-results.json` took **6.156 seconds** on this machine. Timings are
single-run observations, not performance benchmarks.

| Scenario | Requests sent | Responses analyzed | Candidate signals | Heuristic score | Elapsed |
|---|---:|---:|---|---:|---:|
| Normal | 3 | 2 | None | 0 | 0.472 s |
| Normal repeat | 3 | 2 | None | 0 | 0.491 s |
| Controlled HTTP 500 | 3 | 2 | `server_error`, `status_code_change` | 40 | 0.458 s |
| Safe input reflection | 3 | 2 | `input_reflection` | 5 | 0.478 s |
| Fixed database-error signature | 3 | 2 | `database_error` | 35 | 0.491 s |
| Slow response within timeout | 3 | 2 | None | 0 | 0.907 s |
| Cancelled partial scan | 2 | 1 | None | 0 | 0.304 s |

Across the seven scans, GramFuzz generated **14 CFG outputs** and **14 mutation
outputs** (28 outputs total). Seven mutation results were scheduled after
duplicate/budget filtering, alongside seven grammar inputs, for **14 unique
payloads**. Thirteen of those test payloads were sent: the cancelled scan had
one planned payload that was not dispatched. The scanner sent one baseline
request per scan (seven total); baseline responses are intentionally not
passed to the test-response analyzer. It sent 20 scan requests (seven
baselines plus 13 test payloads) and one separate timeout request, for **21
requests total**. The 20 scan requests completed; the separate request failed
with `ReadTimeout`. Thus, 13 test responses were analyzed, not 20 successful
responses: the seven baselines are comparison inputs and the failed timeout
was outside the seven CLI scans. The cancelled scan's next payload was never
sent and was not a failed request.

Request trace by scenario: each of `normal`, `normal-repeat`,
`controlled-error`, `reflection`, `database-signature`, and `slow` sent one
baseline plus two test-payload requests. `cancelled-partial` sent its baseline
and first test payload; its second planned payload was not dispatched. The
separate `/timeout` request was sent once, timed out, and was not part of CLI
analysis or SQLite scan records.

The 13 analyses comprised seven normal and six suspicious responses. Eight
candidate finding entries were produced: four associated with the controlled
HTTP 500 responses, two with the safe reflection responses, and two with the
fixed database-signature responses. All seven CLI scans were persisted to
SQLite. Both report files for every scan were checked against that scan's
SQLite record: JSON metadata included the same scan ID and request statistics,
the stored report paths matched the CLI output, and the HTML contained that
scan ID and every analyzed payload/status/evidence row.

The normal endpoint was scanned three times, including the partial scan. It
produced **zero candidate findings** and a score of **0** on every run. The two
complete repeated normal scans generated the same payload sequence for seed
42. Generation of 1,000 bounded marker payloads took 0.002 seconds. The
delayed request timed out after approximately 1.018 seconds with the
configured 1-second timeout.

## Interpretation and limitations

The HTTP 500, reflection, and fixed database-error text were all deliberately
produced by the local fixture. GramFuzz reported them as candidate signals;
this evaluation discovered **no vulnerability**. The scores are heuristic
prioritization values, not CVSS or proof of exploitability. Reflection alone
does not demonstrate XSS, and the fixed database signature is not evidence of
database execution.

The evaluation covers only the tested local Windows/Python environment and
these controlled responses. It does not establish behavior on other operating
systems, Python versions, network stacks, real databases, browsers, or
authorized production systems. Although CI configuration contains a
Windows/macOS/Linux and Python 3.10–3.14 matrix, those external jobs were not
verified for this evaluation; cross-platform compatibility is therefore not
claimed.

## Reliability checks

The same runner also verified:

- Invalid scan configuration and malformed grammar are rejected.
- Empty analysis results produce valid zero-case JSON and HTML reports.
- A request exceeding the local endpoint timeout is recorded as a failure.
- A cancelled CLI scan preserves its one completed response, generates
  partial JSON/HTML reports, stores its results in SQLite, and exits with
  status 130.
- A 1,000-item payload generation batch respects the configured size bound.

## Reproduction

From the project root, install the project and test dependencies, then run:

```shell
python -m pip install -e ".[dev]"
python examples/evaluate_local.py --output evaluation-results.json
python -m pytest
```

The runner starts and stops its own ephemeral-port loopback-only application,
uses temporary configuration/report/SQLite files, fixes the seed at `42`, and
checks each report against the scan record. Its JSON output includes the
actual platform details, measured timings, per-scan results, and limitations.
