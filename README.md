# GramFuzz

GramFuzz is an early, grammar-guided web application testing tool for targets
you are explicitly authorized to assess. It generates bounded inputs from JSON
context-free grammars, sends rate-limited HTTP requests, compares responses
with a baseline, and records heuristic signals for manual investigation.

## Status and limitations

GramFuzz is an initial implementation, not a penetration-testing certification
or a vulnerability verification system. Signals are candidates only; a 5xx
response, response-size change, or reflected input is not proof of a
vulnerability. The scanner currently supports sequential GET and POST
parameter testing over HTTP. HTTPS, custom request headers,
parallel scans, redirect following, manual verification, and a complete
evidence model are not implemented.

Default scope is limited to `localhost`, `127.0.0.1`, and `::1`. Other hosts
must be named in `target.allowed_hosts`; non-public DNS results are rejected
unless `target.allow_private_addresses` is explicitly enabled. The scanner
does not follow redirects, uses bounded DNS and response deadlines, caps
response capture, and pins each HTTP connection to an address validated for
that request.

## Installation

Python 3.10 or newer is required. From a checkout:

```powershell
python -m pip install .
gramfuzz --help
```

For development and tests:

```powershell
python -m pip install ".[dev]"
python -m pytest
```

## Quick start

Create the starter configuration and grammar in a new directory. This avoids
conflicting with an existing `gramfuzz.yaml` or `grammars/demo.json` in the
current directory:

```powershell
gramfuzz init --directory gramfuzz-demo
gramfuzz grammar validate gramfuzz-demo/grammars/demo.json
gramfuzz generate --grammar gramfuzz-demo/grammars/demo.json --count 10 --seed 42
```

`init` prints the paths of the created `gramfuzz.yaml` and `grammars/demo.json`.
It creates the output directory if needed, but refuses to overwrite either
file. Without `--directory`, it uses the current directory.

To scan, edit `gramfuzz-demo/gramfuzz.yaml` for an application you are
authorized to test. Set `target.authorized: true` only after obtaining
permission. Every scan also requires explicit confirmation:

```powershell
gramfuzz scan --config gramfuzz-demo/gramfuzz.yaml --confirm-authorized
gramfuzz scans list --database gramfuzz-demo/.gramfuzz/scans.sqlite3
gramfuzz scans show SCAN_ID --database gramfuzz-demo/.gramfuzz/scans.sqlite3
gramfuzz report --latest --database gramfuzz-demo/.gramfuzz/scans.sqlite3
```

Replace `SCAN_ID` with the ID printed by a successful scan. The list, show,
and report commands apply after a scan has been saved. The generated
configuration marks its sample target unauthorized, so scanning it before
editing and authorizing the target is rejected.

## Configuration

```yaml
target:
  url: "http://127.0.0.1:3000/"
  allowed_hosts: [localhost, 127.0.0.1, "::1"]
  authorized: false
  allow_private_addresses: false
  dns_timeout: 3.0
scan:
  method: GET
  parameter: q
  timeout: 5
  delay: 0.5
  max_requests: 50
  max_payloads: 20
  repeats_per_payload: 1
  max_response_bytes: 1048576
  concurrency: 1
  mutation_strategies: [lowercase, uppercase, swapcase]
analysis:
  response_length_change_bytes: 100
  response_time_increase_seconds: 1.0
grammar:
  file: grammars/demo.json
  max_depth: 10
  seed: 42
  max_length: 4096
reporting:
  output_dir: reports
  formats: [json, html]
storage:
  database: .gramfuzz/scans.sqlite3
```

Paths are resolved relative to the YAML file. Concurrency must remain `1`
until concurrent execution is implemented. Request, payload, response-size,
and timing limits are validated before a scan starts. The HTTP response size
and DNS timeouts are bounded separately.
The response length and time thresholds shown above are configurable baseline
comparison heuristics.

## Grammar format

Grammars are JSON or YAML objects with a start non-terminal and a mapping of
non-terminals to non-empty production lists:

```json
{
  "start": "<expression>",
  "rules": {
    "<expression>": ["<operator> <value>"],
    "<operator>": ["AND", "OR"],
    "<value>": ["1=1", "2=2"]
  }
}
```

Validation rejects undefined, unreachable, and unproductive rules. Generation
supports a deterministic random seed and enforces depth, count, expansion, and
output-length bounds. Scans apply the mutation strategies selected in
`scan.mutation_strategies`, while retaining each mutated input's source payload.

The bounded starter grammars are [documented here](docs/grammars.md):
`gramfuzz/grammars/sql_syntax.json`, `gramfuzz/grammars/xss_reflection.json`,
and `gramfuzz/grammars/path_validation.json`. They ship as package data, use
harmless markers, and do not establish SQL injection, XSS, or file disclosure.

## Reports and storage

JSON and HTML reports are generated only from the responses of the current
scan or persisted scan data. Names are unique by default; custom report names
cannot contain paths. Reports omit URL query strings. SQLite stores scan
configuration snapshots, analysis summaries, request statistics, risk
heuristics, and report paths; full response bodies and request headers are not
stored.

## Development

Run the test suite with `python -m pytest`. The CI workflow runs this suite on
Windows, Ubuntu, and macOS with Python 3.10 through 3.14. This matrix is
configured but compatibility is not confirmed until the corresponding CI jobs
pass. Unit tests use controlled response doubles; integration and evaluation
tests start a real loopback-only HTTP server. This does not replace independent
security review or manual testing.

See [docs/architecture.md](docs/architecture.md),
[docs/usage.md](docs/usage.md), and [docs/security.md](docs/security.md) for
details. An unauthorized local configuration example is in
[examples/authorized_local_scan.yaml](examples/authorized_local_scan.yaml).
See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[CHANGELOG.md](CHANGELOG.md) for project policies and version history.

Run the controlled, loopback-only end-to-end evaluation and emit JSON results:

```powershell
python examples/evaluate_local.py --output evaluation-results.json
```

The fixture exposes only harmless test endpoints and binds to `127.0.0.1`.
The measured run and its limitations are recorded in
[docs/evaluation-report.md](docs/evaluation-report.md).

Only test systems for which you have explicit permission. The operator is
responsible for authorization, scope, and safe use. Automated findings are
indicators for investigation and are not official CVSS scores or proof of
exploitability.

## License

GramFuzz currently has no declared open-source license. Do not assume that
the project may be used, modified, or redistributed.
