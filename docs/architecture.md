# Architecture

GramFuzz keeps the initial implementation's `core`, `engine`, `analyzer`, and
`reporting` modules and adds an installable `gramfuzz` command package.

## Scan flow

1. `gramfuzz.config.loader` parses YAML, applies defaults, checks scan and
   analysis thresholds, and
   resolves configured file paths relative to the configuration file.
2. `core.grammar_parser` validates JSON or YAML CFG definitions; `core.payload_generator`
   creates bounded, reproducible inputs; `core.mutator` applies selected
   deterministic mutations.
3. `engine.scope_validator` checks target authorization and DNS answers, then
   returns an IP-pinned URL. `engine.fuzzing_engine` performs sequential
   requests with rate, timeout, response-size, request-count, and cancellation
   controls.
4. `analyzer.response_analyzer` compares each response with the collected
   baseline and records evidence-backed candidate signals.
   `analyzer.detection_validator` checks whether identical inputs produced
   repeated signals and applies documented heuristic weights.
5. `reporting.report_generator` creates JSON and HTML output; the
   `gramfuzz.storage.scan_repository` module persists sanitized scan metadata
   and results in SQLite.

Scan metadata distinguishes CFG-generated inputs, mutation outputs, scheduled
unique payloads, and completed/failed requests. If cancellation arrives during
the test-request loop, completed responses are still analyzed, reported, and
persisted with a `cancelled` status.

The scanner does not follow redirects, execute generated content locally, or
claim automatic manual verification. The HTTP client bypasses environment
proxies and uses the validated address for its connection.

## Compatibility

The existing top-level modules remain the implementation modules to avoid
breaking direct imports from the original project. `gramfuzz.cli` is the
supported command entry point. Moving all legacy modules under a single
namespace can be considered in a future breaking release.
