# Changelog

Notable changes to GramFuzz are recorded here.

## 0.1.0 - unreleased

This is the initial public-release preparation version; it has not been
published.

- Added the installable CLI, bounded grammar generation, mutation strategies,
  scoped HTTP scanning, response analysis, and heuristic candidate scoring.
- Added SQLite scan persistence and JSON/HTML report generation.
- Added the localhost-only controlled evaluation application and reproducible
  end-to-end runner.
- Added packaged, harmless starter grammars for SQL syntax variation, safe
  reflection checks, and path input validation.
- Added DNS resolution deadlines, Windows report-path validation, scan
  cancellation handling, and cross-platform CI coverage configuration.
- Documented that scanner output is heuristic and is not confirmation of
  vulnerability or proof of exploitability.
