# Usage

Install the package in an activated virtual environment:

```shell
python -m pip install -e .
gramfuzz --help
```

Use `gramfuzz init --directory gramfuzz-demo` to create a starter
`gramfuzz.yaml` and JSON grammar in a new directory. This avoids conflicting
with an existing configuration or grammar in the current directory. `init`
creates the output directory if needed, prints both created paths, and refuses
to overwrite either file. Without `--directory`, it targets the current
directory.

The starter config is explicitly unauthorized. Validate the generated grammar
and generate inputs without making network requests:

```shell
gramfuzz grammar validate gramfuzz-demo/grammars/demo.json
gramfuzz generate --grammar gramfuzz-demo/grammars/demo.json --count 20 --seed 42
```

After you have permission to test the application, edit
`gramfuzz-demo/gramfuzz.yaml` with the target, host allowlist, and
`authorized: true`. Then provide an explicit confirmation for each run:

```shell
gramfuzz scan --config gramfuzz-demo/gramfuzz.yaml --confirm-authorized
gramfuzz scans list --database gramfuzz-demo/.gramfuzz/scans.sqlite3
gramfuzz scans show SCAN_ID --database gramfuzz-demo/.gramfuzz/scans.sqlite3
gramfuzz report --latest --database gramfuzz-demo/.gramfuzz/scans.sqlite3
```

Replace `SCAN_ID` with the ID printed by the scan. The list, show, and report
commands are for use after a scan has been saved.

`scan.max_payloads` limits distinct generated/mutated inputs.
`scan.repeats_per_payload` controls how many times the same input is sent to
check whether a signal repeats. The total request budget includes one baseline
request and must cover every configured repeat.

Relative grammar, report, and database paths are resolved relative to the YAML
file. Reports contain response-derived evidence but not full response bodies,
request headers, cookies, or URL query strings.

## Controlled local evaluation

The loopback-only test application and reproducible evaluation runner are in
`examples/`. From the project root, run:

```shell
python examples/evaluate_local.py --output evaluation-results.json
```

It starts the fixture on an ephemeral `127.0.0.1` port, uses seed `42`, runs
bounded real HTTP scans, checks reports against SQLite records, and emits
measured JSON results. See [evaluation-report.md](evaluation-report.md) for
the recorded environment, observations, and limitations.
